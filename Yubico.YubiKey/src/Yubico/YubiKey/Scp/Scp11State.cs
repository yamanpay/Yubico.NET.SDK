// Copyright 2024 Yubico AB
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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Yubico.Core.Cryptography;
using Yubico.Core.Iso7816;
using Yubico.Core.Tlv;
using Yubico.YubiKey.Cryptography;
using Yubico.YubiKey.Scp.Commands;
using Yubico.YubiKit.Core.Util;

namespace Yubico.YubiKey.Scp
{
    internal class Scp11State : ScpState
    {
        private const int ReceiptTag = 0x86;
        private const int EckaTag = 0x5F49;
        private const int KeyAgreementTag = 0xA6;

        public Scp11State(SessionKeys sessionKeys, Memory<byte> receipt)
            : base(sessionKeys, receipt)
        {
        }

        internal static Scp11State CreateScpState(
            IApduTransform pipeline,
            Scp11KeyParameters keyParams)
        {
            // Handle Scp11a and Scp11c
            if (keyParams.KeyReference.Id == ScpKid.Scp11a || keyParams.KeyReference.Id == ScpKid.Scp11c)
            {
                PerformSecurityOperation(pipeline, keyParams);
            }

            var securityDomainPublicKey = keyParams.SecurityDomainEllipticCurveKeyAgreementKeyPublicKey;
            var securityDomainPublicKeyCurve = securityDomainPublicKey.Curve;

            var ecdhObject = CryptographyProviders.EcdhPrimitivesCreator();
            var ephemeralKeyPairOceEcka = ecdhObject.GenerateKeyPair(securityDomainPublicKeyCurve);

            // Create an encoded point of the ephemeral public key to send to the Yubikey
            byte[] ephemeralPublicKeyEncodedPointOceEcka = new byte[65];
            ephemeralPublicKeyEncodedPointOceEcka[0] = 0x04;
            ephemeralKeyPairOceEcka.Q.X.CopyTo(ephemeralPublicKeyEncodedPointOceEcka, 1);
            ephemeralKeyPairOceEcka.Q.Y.CopyTo(ephemeralPublicKeyEncodedPointOceEcka, 33);

            // GPC v2.3 Amendment F (SCP11) v1.4 §7.6.2.3
            byte[] keyUsage = { 0x3C }; // AUTHENTICATED | C_MAC | C_DECRYPTION | R_MAC | R_ENCRYPTION
            byte[] keyType = { 0x88 }; // AES
            byte[] keyLen = { 16 }; // 128-bit
            byte[] keyIdentifier = { 0x11, GetScpIdentifierByte(keyParams.KeyReference) };
            byte[] authenticateScpTlvData = TlvObjects.EncodeMany(
                new TlvObject(
                    KeyAgreementTag, TlvObjects.EncodeMany(
                        new TlvObject(0x90, keyIdentifier),
                        new TlvObject(0x95, keyUsage),
                        new TlvObject(0x80, keyType),
                        new TlvObject(0x81, keyLen)
                        )),
                new TlvObject(EckaTag, ephemeralPublicKeyEncodedPointOceEcka)
                );

            var authenticateCommand = keyParams.KeyReference.Id == ScpKid.Scp11b
                ? new InternalAuthenticateCommand(
                    keyParams.KeyReference.VersionNumber, keyParams.KeyReference.Id,
                    authenticateScpTlvData) as IYubiKeyCommand<ScpResponse>
                : new ExternalAuthenticateCommand(
                    keyParams.KeyReference.VersionNumber, keyParams.KeyReference.Id,
                    authenticateScpTlvData) as IYubiKeyCommand<ScpResponse>;

            var authenticateResponseApdu = pipeline.Invoke(
                authenticateCommand.CreateCommandApdu(), authenticateCommand.GetType(), typeof(ScpResponse));

            var authenticateResponse = authenticateCommand.CreateResponseForApdu(authenticateResponseApdu);
            authenticateResponse.ThrowIfFailed(
                $"Error when performing {authenticateCommand.GetType().Name}: {authenticateResponse.StatusMessage}");

            var responseTlvs = TlvObjects.DecodeList(authenticateResponseApdu.Data.Span);
            var epkSdEckaTlv = responseTlvs[0];
            var epkSdEckaEncodedPoint = TlvObjects.UnpackValue(EckaTag, epkSdEckaTlv.GetBytes().Span); //Ecka Tag
            var sdReceipt = TlvObjects.UnpackValue(ReceiptTag, responseTlvs[1].GetBytes().Span);

            var epkSdEcka = new ECParameters // Yubikey generated key agreement key 
            {
                Curve = securityDomainPublicKeyCurve,
                Q = new ECPoint
                {
                    X = epkSdEckaEncodedPoint.Span[1..33].ToArray(),
                    Y = epkSdEckaEncodedPoint.Span[33..].ToArray()
                }
            };

            var skOceEcka =
                keyParams
                    .OffCardEntityEllipticCurveAgreementPrivateKey ?? // If set, we will use this for SCP11A and SCP11C. 
                ephemeralKeyPairOceEcka; // else just use the newly created ephemeral Key for (SCP11b)

            var (encryptionKey, macKey, rMacKey, dekKey)
                = GetX963KDFKeyAgreementKeys(
                    ecdhObject,
                    securityDomainPublicKey,
                    epkSdEcka,
                    ephemeralKeyPairOceEcka,
                    skOceEcka,
                    epkSdEckaTlv,
                    keyUsage,
                    keyType,
                    keyLen,
                    sdReceipt,
                    authenticateScpTlvData);

            var sessionKeys = new SessionKeys(
                macKey,
                encryptionKey,
                rMacKey,
                dekKey
                );

            return new Scp11State(sessionKeys, sdReceipt.ToArray());
        }

        private static (Memory<byte> encryptionKey, Memory<byte> macKey, Memory<byte> rMacKey, Memory<byte> dekKey)
            GetX963KDFKeyAgreementKeys(
            IEcdhPrimitives ecdhObject,
            ECParameters pkSdEcka, // Yubikey Public Key
            ECParameters epkSdEcka, // Yubikey Ephemeral Public Key 
            ECParameters eskOceEcka, // Host Ephemeral Private Key
            ECParameters skOceEcka, // Host Private Key
            TlvObject epkSdEckaTlv,
            byte[] keyUsage,
            byte[] keyType,
            byte[] keyLen,
            ReadOnlyMemory<byte> receipt,
            byte[] data)
        {
            bool allKeysAreSameCurve = new[]
            {
                epkSdEcka.Curve,
                pkSdEcka.Curve,
                eskOceEcka.Curve
            }.All(c => c.Oid == skOceEcka.Curve.Oid);

            if (!allKeysAreSameCurve)
            {
                throw new ArgumentException("All curves must be the same");
            }

            // Compute key agreement for:
            //
            // Yubikey Ephemeral Public Key + Host Ephemeral Private Key
            byte[] keyAgreementFirst = ecdhObject.ComputeSharedSecret(epkSdEcka, eskOceEcka.D);

            // Yubikey Public Key + Host Private Key
            byte[] keyAgreementSecond = ecdhObject.ComputeSharedSecret(pkSdEcka, skOceEcka.D);

            byte[] keyMaterial = MergeArrays(keyAgreementFirst, keyAgreementSecond);
            byte[] keyAgreementData = MergeArrays(data, epkSdEckaTlv.GetBytes());
            byte[] sharedInfo = MergeArrays(keyUsage, keyType, keyLen);

            const int keyCount = 4;
            var keys = new List<byte[]>(keyCount);
            byte counter = 1;
            for (int i = 0; i <= keyCount; i++)
            {
                using var hash = CryptographyProviders.Sha256Creator();

                _ = hash.TransformBlock(keyMaterial, 0, keyMaterial.Length, null, 0);
                _ = hash.TransformBlock(new byte[] { 0, 0, 0, counter }, 0, 4, null, 0);
                _ = hash.TransformFinalBlock(sharedInfo, 0, sharedInfo.Length);

                Span<byte> digest = hash.Hash;
                keys.Add(digest[..16].ToArray());
                keys.Add(digest[16..].ToArray());

                ++counter;
                CryptographicOperations.ZeroMemory(digest);
            }

            // Get keys
            byte[] encryptionKey = keys[0];
            byte[] macKey = keys[1];
            byte[] rmacKey = keys[2];
            byte[] dekKey = keys[3];

            // Do AES CMAC 
            using var cmacObj = CryptographyProviders.CmacPrimitivesCreator(CmacBlockCipherAlgorithm.Aes128);
            Span<byte> genReceipt = stackalloc byte[16];
            cmacObj.CmacInit(encryptionKey);
            cmacObj.CmacUpdate(keyAgreementData);
            cmacObj.CmacFinal(genReceipt);

            if (!CryptographicOperations.FixedTimeEquals(genReceipt, receipt.Span))
            {
                throw new SecureChannelException(ExceptionMessages.KeyAgreementReceiptMissmatch);
            }

            return (encryptionKey, macKey, rmacKey, dekKey);
        }

        /// <summary>
        /// Gets the standardized SCP identifier for the given key reference.
        /// Global Platform Secure Channel Protocol 11 Card Specification v2.3 – Amendment F § 7.1.1
        /// </summary>
        private static byte GetScpIdentifierByte(KeyReference keyReference) =>
            keyReference.Id switch
            {
                ScpKid.Scp11a => 0b01,
                ScpKid.Scp11b => 0b00,
                ScpKid.Scp11c => 0b11,
                _ => throw new ArgumentException("Invalid SCP11 KID")
            };

        private static void PerformSecurityOperation(IApduTransform pipeline, Scp11KeyParameters keyParams)
        {
            // GPC v2.3 Amendment F (SCP11) v1.4 §7.5
            if (keyParams.OffCardEntityEllipticCurveAgreementPrivateKey == null)
            {
                throw new ArgumentNullException(
                    nameof(keyParams.OffCardEntityEllipticCurveAgreementPrivateKey),
                    "SCP11a and SCP11c require a private key");
            }

            int n = keyParams.Certificates.Count - 1;
            if (n < 0)
            {
                throw new ArgumentException(
                    "SCP11a and SCP11c require a certificate chain", nameof(keyParams.Certificates));
            }

            var oceRef = keyParams.OffCardEntityKeyReference ?? new KeyReference(0, 0);
            for (int i = 0; i <= n; i++)
            {
                byte[] certificates = keyParams.Certificates[i].RawData;
                byte oceRefPadded = (byte)(oceRef.Id | (i < n
                    ? 0b10000000
                    : 0x00)); // Is this a good name?

                var securityOperationCommand = new SecurityOperationCommand(
                    oceRef.VersionNumber,
                    oceRefPadded,
                    certificates);

                // Send payload
                var responseSecurityOperation = pipeline.Invoke(
                    securityOperationCommand.CreateCommandApdu(),
                    typeof(SecurityOperationCommand),
                    typeof(SecurityOperationResponse));

                if (responseSecurityOperation.SW != SWConstants.Success)
                {
                    throw new SecureChannelException(
                        $"Security operation failed. Status: {responseSecurityOperation.SW:X4}");
                }
            }
        }

        private static byte[] MergeArrays(params ReadOnlyMemory<byte>[] values)
        {
            using var memoryStream = new MemoryStream();
            foreach (var bytes in values)
            {
#if NETSTANDARD2_1_OR_GREATER
                memoryStream.Write(bytes.Span);
#else
                memoryStream.Write(bytes.Span.ToArray(), 0, bytes.Length);
#endif
            }

            return memoryStream.ToArray();
        }
    }
}
