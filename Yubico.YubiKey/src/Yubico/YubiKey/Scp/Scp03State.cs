// Copyright 2021 Yubico AB
//
// Licensed under the Apache License, Version 2.0 (the "License").
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Linq;
using System.Security.Cryptography;
using Yubico.Core.Iso7816;
using Yubico.YubiKey.Scp.Commands;

namespace Yubico.YubiKey.Scp
{
    internal abstract class ScpState : IDisposable
    {
        protected readonly SessionKeys SessionKeys;
        protected Memory<byte> MacChainingValue;

        private int _encryptionCounter = 1;
        private bool _disposed;

        /// <summary>
        /// Initializes the host-side state for an SCP session.
        /// </summary>
        public ScpState(SessionKeys sessionKeys, Memory<byte> macChain)
        {
            MacChainingValue = macChain;
            SessionKeys = sessionKeys;
        }

        /// <summary>
        /// Encodes (encrypt then MAC) a command using SCP03. Modifies state,
        /// and must be sent in-order. Must be called after LoadInitializeUpdate.
        /// </summary>
        /// <returns></returns>
        public CommandApdu EncodeCommand(CommandApdu command)
        {
            if (SessionKeys == null)
            {
                throw new InvalidOperationException(ExceptionMessages.UnknownScp03Error);
            }

            if (command is null)
            {
                throw new ArgumentNullException(nameof(command));
            }

            var encodedCommand = new CommandApdu
            {
                Cla = (byte)(command.Cla | 0x04),
                Ins = command.Ins,
                P1 = command.P1,
                P2 = command.P2
            };

            byte[] commandData = command.Data.ToArray();
            byte[] encryptedData = ChannelEncryption.EncryptData(
                commandData, SessionKeys.GetEncKey.ToArray(), _encryptionCounter);

            _encryptionCounter++;
            encodedCommand.Data = encryptedData;

            CommandApdu encodedApdu;
            (encodedApdu, MacChainingValue) = ChannelMac.MacApdu(
                encodedCommand, SessionKeys.GetMacKey.ToArray(), MacChainingValue.ToArray()); // TODO toarray remove

            return encodedApdu;
        }

        /// <summary>
        /// Decodes (verify RMAC then decrypt) a raw response from the device.
        /// </summary>
        /// <param name="response"></param>
        /// <returns></returns>
        public ResponseApdu DecodeResponse(ResponseApdu response)
        {
            if (SessionKeys is null)
            {
                throw new InvalidOperationException(ExceptionMessages.UnknownScp03Error);
            }

            if (response is null)
            {
                throw new ArgumentNullException(nameof(response));
            }

            // If the response is not Success, just return the response. The
            // standard says, "No R-MAC shall be generated and no protection
            // shall be applied to a response that includes an error status word:
            // in this case only the status word shall be returned in the
            // response."
            if (response.SW != SWConstants.Success)
            {
                return response;
            }

            // ALWAYS check RMAC before decryption
            byte[] responseData = response.Data.ToArray();
            ChannelMac.VerifyRmac(responseData, SessionKeys.GetRmacKey.ToArray(), MacChainingValue.ToArray());

            byte[] decryptedData = Array.Empty<byte>();
            if (responseData.Length > 8)
            {
                decryptedData = ChannelEncryption.DecryptData(
                    responseData.Take(responseData.Length - 8).ToArray(),
                    SessionKeys.GetEncKey.ToArray(), //toarray
                    _encryptionCounter - 1
                    );
            }

            byte[] fullDecryptedResponse = new byte[decryptedData.Length + 2];
            decryptedData.CopyTo(fullDecryptedResponse, 0);
            fullDecryptedResponse[decryptedData.Length] = response.SW1;
            fullDecryptedResponse[decryptedData.Length + 1] = response.SW2;
            return new ResponseApdu(fullDecryptedResponse);
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    SessionKeys?.Dispose();

                    _disposed = true;
                }
            }
        }
    }

    internal class Scp03State : ScpState
    {
        private readonly ReadOnlyMemory<byte> _hostCryptogram;

        public Scp03State(
            SessionKeys sessionKeys,
            Memory<byte> hostCryptogram)
            : base(sessionKeys, new Memory<byte>(new byte[16]))
        {
            _hostCryptogram = hostCryptogram;
        }

        internal static Scp03State CreateScpState(
            IApduTransform pipeline,
            Scp03KeyParameters keyParameters,
            ReadOnlyMemory<byte> hostChallenge)
        {
            var (cardChallenge, cardCryptogram) = PerformInitializeUpdate(pipeline, keyParameters, hostChallenge);
            var state = CreateScpState(keyParameters, hostChallenge, cardChallenge, cardCryptogram);
            state.PerformExternalAuthenticate(pipeline);

            return state;
        }

        private static Scp03State CreateScpState(
            Scp03KeyParameters keyParameters,
            ReadOnlyMemory<byte> hostChallenge,
            ReadOnlyMemory<byte> cardChallenge,
            ReadOnlyMemory<byte> cardCryptogram)
        {
            // derive session keys
            var sessionKeys = Derivation.DeriveSessionKeysFromStaticKeys(
                keyParameters.StaticKeys,
                hostChallenge.Span,
                cardChallenge.Span);

            // check supplied card cryptogram
            var calculatedCardCryptogram = Derivation.DeriveCryptogram(
                Derivation.DDC_CARD_CRYPTOGRAM,
                sessionKeys.GetMacKey.Span,
                hostChallenge.Span,
                cardChallenge.Span);

            if (!CryptographicOperations.FixedTimeEquals(cardCryptogram.Span, calculatedCardCryptogram.Span))
            {
                throw new SecureChannelException(ExceptionMessages.IncorrectCardCryptogram);
            }

            // calculate host cryptogram
            var hostCryptogram = Derivation.DeriveCryptogram(
                Derivation.DDC_HOST_CRYPTOGRAM,
                sessionKeys.GetMacKey.Span,
                hostChallenge.Span,
                cardChallenge.Span);

            return new Scp03State(sessionKeys, hostCryptogram);
        }

        private static (ReadOnlyMemory<byte> cardChallenge, ReadOnlyMemory<byte> cardCryptogram)
            PerformInitializeUpdate(
            IApduTransform pipeline,
            Scp03KeyParameters keyParameters,
            ReadOnlyMemory<byte> hostChallenge)
        {
            var initializeUpdateCommand = new InitializeUpdateCommand(
                keyParameters.KeyReference.VersionNumber, hostChallenge);

            var initializeUpdateResponseApdu = pipeline.Invoke(
                initializeUpdateCommand.CreateCommandApdu(),
                typeof(InitializeUpdateCommand),
                typeof(InitializeUpdateResponse));

            var initializeUpdateResponse = initializeUpdateCommand.CreateResponseForApdu(initializeUpdateResponseApdu);
            initializeUpdateResponse.ThrowIfFailed();

            var cardChallenge = initializeUpdateResponse.CardChallenge.ToArray().AsMemory();
            var cardCryptogram = initializeUpdateResponse.CardCryptogram.ToArray().AsMemory();

            return (cardChallenge, cardCryptogram);
        }

        private void
            PerformExternalAuthenticate(
            IApduTransform pipeline) // cannot be static, cause it needs to update _macChainingValue
        {
            var eaCommandInitial = new ExternalAuthenticateCommand(_hostCryptogram); //todo pass as params?

            (var macdApdu, byte[] newMacChainingValue) = ChannelMac.MacApdu(
                eaCommandInitial.CreateCommandApdu(),
                SessionKeys.GetMacKey.ToArray(),
                MacChainingValue.ToArray()
                );

            MacChainingValue = newMacChainingValue;

            var eaCommand = new ExternalAuthenticateCommand(macdApdu.Data.ToArray());
            var externalAuthenticateResponseApdu = pipeline.Invoke(
                eaCommand.CreateCommandApdu(),
                typeof(ExternalAuthenticateCommand),
                typeof(ExternalAuthenticateResponse));

            var externalAuthenticateResponse = eaCommandInitial.CreateResponseForApdu(externalAuthenticateResponseApdu);
            externalAuthenticateResponse.ThrowIfFailed();
        }
    }
}
