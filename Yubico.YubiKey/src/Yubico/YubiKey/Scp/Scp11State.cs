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
using Yubico.YubiKit.Core.Util;

namespace Yubico.YubiKey.Scp
{
    internal class Scp11State : ScpState
    {
        public Scp11State(SessionKeys sessionKeys, Memory<byte> receipt)
            : base(sessionKeys, receipt)
        {
        }

        internal static Scp11State InitScp11(
            IApduTransform pipeline,
            Scp11KeyParameters keyParams)
        {
            // const byte INS_PERFORM_SECURITY_OPERATION = 0x2A;
            const byte InsInternalAuthenticate = 0x88;
            const byte InsExternalAuthenticate = 0x82;

            // GPC v2.3 Amendment F (SCP11) v1.4 §7.1.1
            byte parameters;
            switch (keyParams.KeyReference.Id)
            {
                case ScpKid.Scp11a:
                    parameters = 0b01;
                    break;
                case ScpKid.Scp11b:
                    parameters = 0b00;
                    break;
                case ScpKid.Scp11c:
                    parameters = 0b11;
                    break;
                default:
                    throw new ArgumentException("Invalid SCP11 KID");
            }

            byte[] keyUsage = { 0x3C }; // AUTHENTICATED | C_MAC | C_DECRYPTION | R_MAC | R_ENCRYPTION
            byte[] keyType = { 0x88 }; // AES
            byte[] keyLen = { 16 }; // 128-bit

            // Host ephemeral key
            var ecdh = CryptographyProviders.EcdhPrimitivesCreator();
            var pk = keyParams.SecurityDomainEllipticCurveKeyAgreementKeyPublicKey;
            var curve = pk.Curve;
            var ephemeralOceEcka = ecdh.GenerateKeyPair(curve);

            var encodedPointOceEcka = new byte[65];
            encodedPointOceEcka[0] = 0x04;
            ephemeralOceEcka.Q.X.CopyTo(encodedPointOceEcka, 1);
            ephemeralOceEcka.Q.Y.CopyTo(encodedPointOceEcka, 33);

            // // GPC v2.3 Amendment F (SCP11) v1.4 §7.6.2.3
            byte[] data = TlvObjects.EncodeList(
                new List<TlvObject>
                {
                    new TlvObject(
                        0xA6, TlvObjects.EncodeList(
                            new List<TlvObject>
                            {
                                new TlvObject(0x90, new byte[] { 0x11, parameters }),
                                new TlvObject(0x95, keyUsage),
                                new TlvObject(0x80, keyType),
                                new TlvObject(0x81, keyLen)
                            })),
                    new TlvObject(0x5F49, encodedPointOceEcka)
                });

            var skOceEcka =
                keyParams.OffCardEntityEllipticCurveAgreementPrivateKey ??
                ephemeralOceEcka; // This is for SCP11A and C. 

            byte ins = keyParams.KeyReference.Id == ScpKid.Scp11b
                ? InsInternalAuthenticate
                : InsExternalAuthenticate; //TODO Make commands to follow NETSDK

            var cmd = new CommandApdu
            {
                Cla = 0x80,
                Ins = ins,
                P1 = keyParams.KeyReference.VersionNumber,
                P2 = keyParams.KeyReference.Id,
                Data = data
            };

            var response = pipeline.Invoke(cmd, default!, default!); //TODO check args Make commands to follow NETSDK
            if (response.SW != SWConstants.Success)
            {
                throw new ApduException(); //todo
            }

            var tlvs = TlvObjects.DecodeList(response.Data.Span);
            var epkSdEckaTlv = tlvs[0];
            var epkSdEckaEncodedPoint = TlvObjects.UnpackValue(0x5F49, epkSdEckaTlv.GetBytes().Span);
            var receipt = TlvObjects.UnpackValue(0x86, tlvs[1].GetBytes().Span);

            var epkSdEcka = new ECParameters // Yubikey generated key agreement key 
            {
                Curve = curve,
                Q = new ECPoint
                {
                    X = epkSdEckaEncodedPoint.Span[1..33].ToArray(),
                    Y = epkSdEckaEncodedPoint.Span[33..].ToArray()
                }
            };

            byte[] keyAgreementData = MergeArrays(data, epkSdEckaTlv.GetBytes());
            byte[] sharedInfo = MergeArrays(keyUsage, keyType, keyLen);
            byte[] ka1 = ecdh.ComputeSharedSecret(epkSdEcka, ephemeralOceEcka.D);
            byte[] ka2 = ecdh.ComputeSharedSecret(pk, ephemeralOceEcka.D); //skOceEcka
            byte[] keyMaterial = MergeArrays(ka1, ka2);

            // Do X9.63 KDF
            var keys = new List<byte[]>();
            byte counter = 0;
            for (int i = 0; i < 3; i++)
            {
                using var hash = CryptographyProviders.Sha256Creator();

                _ = hash.TransformBlock(keyMaterial, 0, keyMaterial.Length, null, 0);
                byte[] byteArray = { 0, 0, 0, ++counter };
                _ = hash.TransformBlock(byteArray, 0, 4, null, 0);
                _ = hash.TransformFinalBlock(sharedInfo, 0, sharedInfo.Length);

                Span<byte> digest = hash.Hash;
                keys.Add(digest[..16].ToArray()); // TODO Should be AES keys, find C# equivalent
                keys.Add(digest[16..].ToArray());

                CryptographicOperations.ZeroMemory(digest);
            }

            // Do AES CMAC 
            using var cmacObj = CryptographyProviders.CmacPrimitivesCreator(CmacBlockCipherAlgorithm.Aes128);
            byte[] key = keys[0];
            Span<byte> genReceipt = new byte[16];
            cmacObj.CmacInit(key);
            cmacObj.CmacUpdate(keyAgreementData);
            cmacObj.CmacFinal(genReceipt);

            if (!CryptographicOperations.FixedTimeEquals(genReceipt, receipt.Span)) // They are not equal
            {
                throw new Exception("Receipt does not match"); //TODO better excp
            }

            var sessionKeys = new SessionKeys(
                keys[2].AsMemory(),
                keys[1].AsMemory(),
                keys[3].AsMemory()
                //keys[4].AsMemory() dek?
                );

            return new Scp11State(sessionKeys, receipt.ToArray());
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
