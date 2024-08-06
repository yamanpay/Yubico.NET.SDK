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
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;

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

    public abstract class PivAlgorithm2
    {
        public int KeySizeBits { get; }
        public byte Identifier { get; }
        public bool IsAsymmetric => !(this is SymmetricAlgorithm);
        public bool IsRsa { get; }
        public bool IsEcc { get; }

        protected PivAlgorithm2(int keySizeBits, byte identifier, bool isRsa, bool isEcc)
        {
            KeySizeBits = keySizeBits;
            Identifier = identifier;
            IsRsa = isRsa;
            IsEcc = isEcc;
        }
    }

    public class RsaAlgorithm : PivAlgorithm2
    {
        public RsaAlgorithm(int keySizeBits, byte identifier)
            : base(keySizeBits, identifier, true, false)
        {
        }
    }

    public class EccAlgorithm : PivAlgorithm2
    {
        public EccAlgorithm(int keySizeBits, byte identifier) : base(keySizeBits, identifier, false, true) { }
    }

    public class Ed25519Algorithm : PivAlgorithm2
    {
        public Ed25519Algorithm(byte identifier) : base(256, identifier, false, true) { }
    }

    public class X25519Algorithm : PivAlgorithm2
    {
        public X25519Algorithm(byte identifier) : base(256, identifier, false, true) { }
    }

    public class SymmetricAlgorithm : PivAlgorithm2
    {
        public SymmetricAlgorithm(int keySizeBits, byte identifier)
            : base(keySizeBits, identifier, false, false)
        {
        }
    }

    [SuppressMessage("Performance", "CA1823:Avoid unused private fields")]
    public static class PivAlgorithms
    {
        public static PivAlgorithm2 EccP256 { get; } = new EccAlgorithm(256, 0x11);
        public static PivAlgorithm2 EccP384 { get; } = new EccAlgorithm(384, 0x14);
        public static PivAlgorithm2 Rsa1024 { get; } = new RsaAlgorithm(1024, 0x06);
        public static PivAlgorithm2 Rsa2048 { get; } = new RsaAlgorithm(2048, 0x07);
        public static PivAlgorithm2 Rsa3072 { get; } = new RsaAlgorithm(3072, 0x05);
        public static PivAlgorithm2 Rsa4096 { get; } = new RsaAlgorithm(4096, 0x16);
        public static PivAlgorithm2 Aes128 { get; } = new SymmetricAlgorithm(128, 0x08);
        public static PivAlgorithm2 Aes192 { get; } = new SymmetricAlgorithm(192, 0x0A);
        public static PivAlgorithm2 Aes256 { get; } = new SymmetricAlgorithm(256, 0x0C);
        public static PivAlgorithm2 TripleDes { get; } = new SymmetricAlgorithm(192, 0x03);

        // public static PivAlgorithm2 Ed25519 { get; } = new Ed25519Algorithm(0x22);
        // public static PivAlgorithm2 X25519 { get; } = new X25519Algorithm(0x23);

        private static readonly PivAlgorithm2[] AllAlgorithms =
        {
            EccP256, EccP384, Rsa1024, Rsa2048, Rsa3072, Rsa4096,
            Aes128, Aes192, Aes256, TripleDes,

            // Ed25519, X25519
        };

        private static readonly IReadOnlyDictionary<byte, PivAlgorithm2> AllAlgorithmsDictionary =
            AllAlgorithms.ToDictionary(pair => pair.Identifier, pair => pair);

        private static readonly IReadOnlyCollection<RsaAlgorithm> AllRsaAlgorithmList =
            AllAlgorithms.OfType<RsaAlgorithm>().ToList();

        private static readonly IReadOnlyDictionary<int, EccAlgorithm> AllEcclgorithmsDictionary =
            AllAlgorithms.OfType<EccAlgorithm>().ToDictionary(pa => pa.KeySizeBits, pa => pa);

        private static readonly IReadOnlyDictionary<int, RsaAlgorithm> AllRsaAlgorithmsDictionary =
            AllAlgorithms
                .OfType<RsaAlgorithm>()
                .ToDictionary(ra => ra.KeySizeBits, ra => ra);

        public static readonly IReadOnlyDictionary<int, PivAlgorithm2> AllAsymmetricAlgorithms =
            AllAlgorithms.Where(pa => pa.IsAsymmetric).ToDictionary(pa => pa.KeySizeBits, pa => pa);

        public static PivAlgorithm2? GetByIdentifier(byte identifier)
        {
            _ = AllAlgorithmsDictionary.TryGetValue(identifier, out PivAlgorithm2 result);
            return result;
        }

        public static TResult? GetAlgorithmByBlockSize<TResult>(
            int blockSizeInBits,
            Func<PivAlgorithm2, bool>? selector = null)
            where TResult : PivAlgorithm2
        {
            Type type = typeof(TResult);

            return type switch
            {
                _ when type == typeof(RsaAlgorithm) =>
                    FilterAlgorithm<TResult>(blockSizeInBits, selector, typeof(RsaAlgorithm)),
                _ when type == typeof(EccAlgorithm) =>
                    FilterAlgorithm<TResult>(blockSizeInBits, selector, typeof(EccAlgorithm)),
                _ when type == typeof(SymmetricAlgorithm) =>
                    FilterAlgorithm<TResult>(blockSizeInBits, selector, typeof(SymmetricAlgorithm)),
                _ when type == typeof(Ed25519Algorithm) =>
                    FilterAlgorithm<TResult>(blockSizeInBits, selector, typeof(Ed25519Algorithm)),
                _ when type == typeof(X25519Algorithm) =>
                    FilterAlgorithm<TResult>(blockSizeInBits, selector, typeof(X25519Algorithm)),
                _ when type == typeof(PivAlgorithm2) =>
                    FilterAlgorithm<TResult>(blockSizeInBits, selector, typeof(PivAlgorithm2)),
                _ => throw new ArgumentException($"Unsupported algorithm type: {type.Name}")
            };
        }

        private static T? FilterAlgorithm<T>(int blockSizeInBits, Func<PivAlgorithm2, bool>? selector, Type sourceType)
            where T : PivAlgorithm2 =>
            AllAlgorithms
                .Where(sourceType.IsInstanceOfType)
                .WhereIfNotNull(selector)
                .FirstOrDefault(pa => pa.KeySizeBits == blockSizeInBits) as T;

        private static IEnumerable<T> WhereIfNotNull<T>(
            this IEnumerable<T> query,
            Func<T, bool>? selector) =>
            selector != null
                ? query.Where(selector)
                : query;
    }

    public static class AsymmetricKeySizeHelper
    {
        public static PivAlgorithm2 DetermineFromPrivateKey(ReadOnlySpan<byte> privateKey)
        {
            int keySizeInBytes = privateKey.Length;
            return keySizeInBytes switch
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
        }

        public static PivAlgorithm2 DetermineFromPublicKey(ReadOnlySpan<byte> publicKey)
        {
            int keySizeInBytes = publicKey.Length;
            return keySizeInBytes switch
            {
                // For ECC keys, the length of the public key size is: prefix+x+y,
                // E.g: EccP256: 1+32+32 = 65
                //      EccP256: 1+48+48 = 97
                65 => PivAlgorithms.EccP256,
                97 => PivAlgorithms.EccP384,
                128 => PivAlgorithms.Rsa1024,
                256 => PivAlgorithms.Rsa2048,
                384 => PivAlgorithms.Rsa3072,
                512 => PivAlgorithms.Rsa4096,
                _ => throw new ArgumentException(
                    string.Format(
                        CultureInfo.CurrentCulture,
                        ExceptionMessages.InvalidPublicKeyData))
            };
        }

        public static bool TryDetermineFromPublicKey(ReadOnlySpan<byte> publicKey, out PivAlgorithm2 result)
        {
            try
            {
                result = DetermineFromPublicKey(publicKey);
                return true;
            }
            catch (ArgumentException)
            {
                result = null!;
                return false;
            }
        }

        public static bool TryDetermineFromPrivateKey(ReadOnlySpan<byte> privateKey, out PivAlgorithm2 result)
        {
            try
            {
                result = DetermineFromPrivateKey(privateKey);
                return true;
            }
            catch (ArgumentException)
            {
                result = null!;
                return false;
            }
        }
    }
}
