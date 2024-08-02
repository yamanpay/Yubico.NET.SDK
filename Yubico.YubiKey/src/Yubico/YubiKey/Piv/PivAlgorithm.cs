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
using System.Globalization;

namespace Yubico.YubiKey.Piv
{
    /// <summary>
    /// The cryptographic algorithms supported by the PIV Application on the
    /// YubiKey.
    /// </summary>
    public enum PivAlgorithm
    {
        /// <summary>
        /// No algorithm (generally indicates a slot is empty).
        /// </summary>
        None = 0,

        /// <summary>
        /// Indicates that the algorithm is Triple-DES (Slot 9B). The key size is
        /// 192 bits (24 bytes).
        /// </summary>
        TripleDes = 0x03,

        /// <summary>
        /// Indicates that the algorithm is AES-128 (Slot 9B). The key size is
        /// 128 bits (16 bytes).
        /// </summary>
        Aes128 = 0x08,

        /// <summary>
        /// Indicates that the algorithm is AES-192 (Slot 9B). The key size is
        /// 192 bits (24 bytes).
        /// </summary>
        Aes192 = 0x0A,

        /// <summary>
        /// Indicates that the algorithm is AES-256 (Slot 9B). The key size is
        /// 256 bits (32 bytes).
        /// </summary>
        Aes256 = 0x0C,

        /// <summary>
        /// Indicates that the algorithm is RSA and the key size (modulus size) is
        /// 1024 bits.
        /// </summary>
        Rsa1024 = 0x06,

        /// <summary>
        /// Indicates that the algorithm is RSA and the key size (modulus size) is
        /// 2048 bits.
        /// </summary>
        Rsa2048 = 0x07,

        /// <summary>
        /// Indicates that the algorithm is RSA and the key size (modulus size) is
        /// 3072 bits.
        /// </summary>
        Rsa3072 = 0x05,

        /// <summary>
        /// Indicates that the algorithm is RSA and the key size (modulus size) is
        /// 4096 bits.
        /// </summary>
        Rsa4096 = 0x16,

        /// <summary>
        /// Indicates that the algorithm is ECC and the parameters are P-256,
        /// specified in FIPS 186-4 (moving to NIST SP 800-186).
        /// </summary>
        EccP256 = 0x11,

        /// <summary>
        /// Indicates that the algorithm is ECC and the parameters are P-384,
        /// specified in FIPS 186-4 (moving to NIST SP 800-186).
        /// </summary>
        EccP384 = 0x14,

        /// <summary>
        /// Indicates that the slot contains a PIN or PUK (slots 80 and 81).
        /// While not a cryptographic algorithm, it is used in the PIV Metadata.
        /// </summary>
        Pin = 0xFF
    }

    public class PivAlgorithm2
    {
        public int KeySizeBits { get; }
        public PivAlgorithmType Type { get; }

        public byte P1 { get; }

        private PivAlgorithm2(int keySizeBits, PivAlgorithmType type, byte p1)
        {
            KeySizeBits = keySizeBits;
            Type = type;
            P1 = p1;
        }

        public static PivAlgorithm2 Create(int keySizeBits, PivAlgorithmType type, byte p1) =>
            new PivAlgorithm2(keySizeBits, type, p1);

        public int GetPrivateKeySize() =>
            Type == PivAlgorithmType.Ecc
                ? KeySizeBits / 8
                : KeySizeBits / 16;

        public int GetPublicKeySize() =>
            Type == PivAlgorithmType.Ecc
                ? (KeySizeBits / 8 * 2) + 1
                : KeySizeBits / 8;

        public bool IsEcc => Type == PivAlgorithmType.Ecc;
        public bool IsRsa => Type == PivAlgorithmType.Rsa;
        public bool IsAsymmetric => Type is PivAlgorithmType.Ecc || Type is PivAlgorithmType.Rsa;
        public bool IsSymmetric => Type is PivAlgorithmType.Aes || Type is PivAlgorithmType.TripleDes;
    }

    public static class PivAlgorithms
    {
        public static PivAlgorithm2 EccP256 { get; } =
            PivAlgorithm2.Create(keySizeBits: 256, PivAlgorithmType.Ecc, p1: 0x11);

        public static PivAlgorithm2 EccP384 { get; } =
            PivAlgorithm2.Create(keySizeBits: 384, PivAlgorithmType.Ecc, p1: 0x14);

        public static PivAlgorithm2 Rsa1024 { get; } =
            PivAlgorithm2.Create(keySizeBits: 1024, PivAlgorithmType.Rsa, p1: 0x06);

        public static PivAlgorithm2 Rsa2048 { get; } =
            PivAlgorithm2.Create(keySizeBits: 2048, PivAlgorithmType.Rsa, p1: 0x07);

        public static PivAlgorithm2 Rsa3072 { get; } =
            PivAlgorithm2.Create(keySizeBits: 3072, PivAlgorithmType.Rsa, p1: 0x05);

        public static PivAlgorithm2 Rsa4096 { get; } =
            PivAlgorithm2.Create(keySizeBits: 4096, PivAlgorithmType.Rsa, p1: 0x16);

        public static PivAlgorithm2 Aes128 { get; } =
            PivAlgorithm2.Create(keySizeBits: 128, PivAlgorithmType.Aes, p1: 0x08);

        public static PivAlgorithm2 Aes192 { get; } =
            PivAlgorithm2.Create(keySizeBits: 192, PivAlgorithmType.Aes, p1: 0x0A);

        public static PivAlgorithm2 Aes256 { get; } =
            PivAlgorithm2.Create(keySizeBits: 256, PivAlgorithmType.Aes, p1: 0x0C);

        public static PivAlgorithm2 TripleDes { get; } =
            PivAlgorithm2.Create(keySizeBits: 192, PivAlgorithmType.TripleDes, p1: 0x03);

        public static readonly PivAlgorithm2[] AllAlgorithms =
        {
            EccP256, EccP384, Rsa1024, Rsa2048, Rsa3072, Rsa4096, Aes128, Aes192, Aes256, TripleDes
        };
    }

    public static class AsymmetricKeySizeHelper
    {
        public static PivAlgorithm2 DetermineFromPrivateKey(ReadOnlySpan<byte> privateKey) =>
            privateKey.Length switch
            {
                32 => PivAlgorithms.EccP256,
                48 => PivAlgorithms.EccP384,
                64 => PivAlgorithms.Rsa1024,
                128 => PivAlgorithms.Rsa2048,
                192 => PivAlgorithms.Rsa3072,
                256 => PivAlgorithms.Rsa4096,
                _ => throw new ArgumentException(
                    string.Format(
                        CultureInfo.CurrentCulture,
                        ExceptionMessages.InvalidPrivateKeyData))
            };

        public static PivAlgorithm2 DetermineFromPublicKey(ReadOnlySpan<byte> publicKey) =>
            publicKey.Length switch
            {
                // For ECC keys, the length of the public key size is: prefix+x+y,
                // E.g: EccP256: 1+32+32 = 65
                //      EccP256: 1+48+48 = 97
                65 => PivAlgorithms.EccP256,
                97 => PivAlgorithms.EccP384,
                _ => DetermineFromModulus(publicKey)
            };

        private static PivAlgorithm2 DetermineFromModulus(ReadOnlySpan<byte> modulus)
        {
            int keySize = modulus.Length * 8;
            return keySize switch
            {
                1024 => PivAlgorithms.Rsa1024,
                2048 => PivAlgorithms.Rsa2048,
                3072 => PivAlgorithms.Rsa3072,
                4096 => PivAlgorithms.Rsa4096,
                _ => throw new ArgumentException(
                    string.Format(
                        CultureInfo.CurrentCulture,
                        ExceptionMessages.InvalidPublicKeyData))
            };
        }
    }

    public enum PivAlgorithmType
    {
        Rsa,
        Ecc,
        Aes,
        TripleDes
    }
}
