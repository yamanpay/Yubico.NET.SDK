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
using System.Security.Cryptography;
using Yubico.Core.Iso7816;
using Yubico.YubiKey.Cryptography;
using Yubico.YubiKey.Scp;
using Yubico.YubiKey.Scp.Commands;
using Yubico.YubiKey.Scp03;
using Session = Yubico.YubiKey.Scp.Session;

namespace Yubico.YubiKey.Pipelines
{
    /// <summary>
    /// Performs SCP encrypt-then-MAC on commands and verify-then-decrypt on responses.
    /// </summary>
    /// <remarks>
    /// Does an SCP Initialize Update / External Authenticate handshake at setup.
    ///
    /// Commands and responses sent through this pipeline are confidential and authenticated.
    ///
    /// Requires pre-shared <see cref="Scp03.StaticKeys"/>.
    /// </remarks>
    // TODO This appears to only handle Scp03 as if it were the sole protocol. Needs to be either refactored or 
    // broken into two transforms
    internal class ScpApduTransform : IApduTransform, IDisposable
    {
        private readonly IApduTransform _pipeline;
        private readonly Session _session;

        private bool _disposed;

        public ScpKeyParameters KeyParameters { get; private set; }
        public StaticKeys StaticKeys => ((Scp03KeyParameters)KeyParameters).StaticKeys;

        /// <summary>
        /// Constructs a new pipeline from the given one.
        /// </summary>
        /// <param name="pipeline">Underlying pipeline to send and receive encoded APDUs with</param>
        /// <param name="keyParameters">Static keys pre-shared with the device</param>
        public ScpApduTransform(IApduTransform pipeline, ScpKeyParameters keyParameters)
        {
            _pipeline = pipeline ?? throw new ArgumentNullException(nameof(pipeline));
            KeyParameters = keyParameters ?? throw new ArgumentNullException(nameof(keyParameters));

            _session = new Session();
            _disposed = false;
        }

        /// <summary>
        /// Performs SCP handshake. Must be called after SELECT.
        /// </summary>
        public void Setup()
        {
            using var rng = CryptographyProviders.RngCreator();
            Setup(rng);
        }

        internal void Setup(RandomNumberGenerator rng)
        {
            _pipeline.Setup();
            
            // Generate host challenge
            byte[] hostChallenge = new byte[8];
            rng.GetBytes(hostChallenge);
            
            // Perform IU/EA handshake
            PerformInitializeUpdate(hostChallenge);
            PerformExternalAuthenticate(); // What are you even doing? Not seeing any state being set 
        }

        public ResponseApdu Invoke(CommandApdu command, Type commandType, Type responseType)
        {
            // Encode command
            var encodedCommand = _session.EncodeCommand(command);
            
            // Pass along the encoded command
            var response = _pipeline.Invoke(encodedCommand, commandType, responseType);

            // Special carve out for SelectApplication here, since there will be nothing to decode
            if (commandType == typeof(InterIndustry.Commands.SelectApplicationCommand))
            {
                return response;
            }
            
            // Decode response and return it
            return _session.DecodeResponse(response);
        }

        private void PerformInitializeUpdate(byte[] hostChallenge)
        {
            var initializeUpdateCommand = _session.BuildInitializeUpdate(
                KeyParameters.KeyVersionNumber, hostChallenge);

            var initializeUpdateResponseApdu = _pipeline.Invoke(
                initializeUpdateCommand.CreateCommandApdu(),
                typeof(InitializeUpdateCommand),
                typeof(InitializeUpdateResponse));

            var initializeUpdateResponse = initializeUpdateCommand.CreateResponseForApdu(initializeUpdateResponseApdu);
            initializeUpdateResponse.ThrowIfFailed();
            _session.LoadInitializeUpdateResponse(initializeUpdateResponse, StaticKeys);
        }

        private void PerformExternalAuthenticate()
        {
            var externalAuthenticateCommand = _session.BuildExternalAuthenticate();

            var externalAuthenticateResponseApdu = _pipeline.Invoke(
                externalAuthenticateCommand.CreateCommandApdu(),
                typeof(ExternalAuthenticateCommand),
                typeof(ExternalAuthenticateResponse));

            var externalAuthenticateResponse = externalAuthenticateCommand.CreateResponseForApdu(externalAuthenticateResponseApdu);
            externalAuthenticateResponse.ThrowIfFailed();
            _session.LoadExternalAuthenticateResponse(externalAuthenticateResponse);
        }

        // There is a call to cleanup and a call to Dispose. The cleanup only
        // needs to call the cleanup on the local APDU Pipeline object.
        public void Cleanup() => _pipeline.Cleanup();

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        // The Dispose needs to make sure the local disposable fields are
        // disposed.
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // ScpKeys.Dispose(); // TODO
                    _session.Dispose();

                    _disposed = true;
                }
            }
        }
    }
}
