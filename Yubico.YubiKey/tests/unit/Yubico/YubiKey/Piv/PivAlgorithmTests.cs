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
using Xunit;

namespace Yubico.YubiKey.Piv
{
    public class PivAlgorithmTests
    {
        [Theory]
        [InlineData(PivAlgorithm.Rsa1024, true)]
        [InlineData(PivAlgorithm.Rsa2048, true)]
        [InlineData(PivAlgorithm.Rsa3072, true)]
        [InlineData(PivAlgorithm.Rsa4096, true)]
        [InlineData(PivAlgorithm.EccP256, true)]
        [InlineData(PivAlgorithm.EccP384, true)]
        [InlineData(PivAlgorithm.None, false)]
        [InlineData(PivAlgorithm.TripleDes, false)]
        [InlineData(PivAlgorithm.Pin, false)]
        public void IsValidAlg_ReturnsCorrect(PivAlgorithm algorithm, bool expectedResult)
        {
            bool result = algorithm.IsValidAlgorithmForGenerate();

            Assert.Equal(expectedResult, result);
        }

        [Theory]
        [InlineData(PivAlgorithm.Rsa1024, true)]
        [InlineData(PivAlgorithm.Rsa2048, true)]
        [InlineData(PivAlgorithm.Rsa3072, true)]
        [InlineData(PivAlgorithm.Rsa4096, true)]
        [InlineData(PivAlgorithm.EccP256, false)]
        [InlineData(PivAlgorithm.EccP384, false)]
        [InlineData(PivAlgorithm.None, false)]
        [InlineData(PivAlgorithm.TripleDes, false)]
        [InlineData(PivAlgorithm.Pin, false)]
        public void IsRsa_ReturnsCorrect(PivAlgorithm algorithm, bool expectedResult)
        {
            bool result = algorithm.IsRsa();

            Assert.Equal(expectedResult, result);
        }

        [Theory]
        [InlineData(PivAlgorithm.Rsa1024, false)]
        [InlineData(PivAlgorithm.Rsa2048, false)]
        [InlineData(PivAlgorithm.Rsa3072, false)]
        [InlineData(PivAlgorithm.Rsa4096, false)]
        [InlineData(PivAlgorithm.EccP256, true)]
        [InlineData(PivAlgorithm.EccP384, true)]
        [InlineData(PivAlgorithm.None, false)]
        [InlineData(PivAlgorithm.TripleDes, false)]
        [InlineData(PivAlgorithm.Pin, false)]
        public void IsEcc_ReturnsCorrect(PivAlgorithm algorithm, bool expectedResult)
        {
            bool result = algorithm.IsEcc();

            Assert.Equal(expectedResult, result);
        }

        [Theory]
        [InlineData(PivAlgorithm.Rsa1024, 1024)]
        [InlineData(PivAlgorithm.Rsa2048, 2048)]
        [InlineData(PivAlgorithm.Rsa3072, 3072)]
        [InlineData(PivAlgorithm.Rsa4096, 4096)]
        [InlineData(PivAlgorithm.EccP256, 256)]
        [InlineData(PivAlgorithm.EccP384, 384)]
        [InlineData(PivAlgorithm.None, 0)]
        [InlineData(PivAlgorithm.TripleDes, 192)]
        [InlineData(PivAlgorithm.Pin, 64)]
        public void KeySizeBits_ReturnsCorrect(PivAlgorithm algorithm, int expectedResult)
        {
            int result = algorithm.KeySizeBits();

            Assert.Equal(expectedResult, result);
        }

        public class PivAlgorithm2Tests
        {
            [Theory]
            [MemberData(nameof(AsymmetricAlgorithmTestData))]
            public void IsAsymmetric_WithAsymmetricAlgorithm_ReturnsTrue(
                PivAlgorithm2 algorithm, bool expectedIsAsymmetric)
            {
                // Act
                bool isAsymmetric = algorithm.IsAsymmetric;

                // Assert
                Assert.Equal(expectedIsAsymmetric, isAsymmetric);
            }

            [Theory]
            [MemberData(nameof(SymmetricAlgorithmTestData))]
            public void IsAsymmetric_WithSymmetricAlgorithm_ReturnsFalse(
                PivAlgorithm2 algorithm, bool expectedIsSymmetric)
            {
                // Act
                var isSymmetric = !algorithm.IsAsymmetric;

                // Assert
                Assert.Equal(expectedIsSymmetric, isSymmetric);
            }

            public static IEnumerable<object[]> AsymmetricAlgorithmTestData()
            {
                yield return new object[] { PivAlgorithms.EccP256, true };
                yield return new object[] { PivAlgorithms.EccP384, true };
                yield return new object[] { PivAlgorithms.Rsa1024, true };
                yield return new object[] { PivAlgorithms.Rsa2048, true };
                yield return new object[] { PivAlgorithms.Rsa3072, true };
                yield return new object[] { PivAlgorithms.Rsa4096, true };
                // yield return new object[] { PivAlgorithms.Ed25519, true };
                // yield return new object[] { PivAlgorithms.X25519, true };
                yield return new object[] { PivAlgorithms.Aes128, false };
                yield return new object[] { PivAlgorithms.Aes192, false };
                yield return new object[] { PivAlgorithms.Aes256, false };
                yield return new object[] { PivAlgorithms.TripleDes, false };
            }

            public static IEnumerable<object[]> SymmetricAlgorithmTestData()
            {
                yield return new object[] { PivAlgorithms.EccP256, false };
                yield return new object[] { PivAlgorithms.EccP384, false };
                yield return new object[] { PivAlgorithms.Rsa1024, false };
                yield return new object[] { PivAlgorithms.Rsa2048, false };
                yield return new object[] { PivAlgorithms.Rsa3072, false };
                yield return new object[] { PivAlgorithms.Rsa4096, false };
                // yield return new object[] { PivAlgorithms.Ed25519, false };
                // yield return new object[] { PivAlgorithms.X25519, false };
                yield return new object[] { PivAlgorithms.Aes128, true };
                yield return new object[] { PivAlgorithms.Aes192, true };
                yield return new object[] { PivAlgorithms.Aes256, true };
                yield return new object[] { PivAlgorithms.TripleDes, true };
            }
        }

        public class PivAlgorithmsTests
        {
            [Fact]
            public void GetAlgorithmByBlockSize_ReturnsCorrectRsaAlgorithm()
            {
                var result = PivAlgorithms.GetAlgorithmByBlockSize<RsaAlgorithm>(2048);
                Assert.IsType<RsaAlgorithm>(result);
                Assert.Equal(2048, result.KeySizeBits);
            }

            [Fact]
            public void GetAlgorithmByBlockSize_ReturnsCorrectEccAlgorithm()
            {
                var result = PivAlgorithms.GetAlgorithmByBlockSize<EccAlgorithm>(256);
                Assert.IsType<EccAlgorithm>(result);
                Assert.Equal(256, result.KeySizeBits);
            }

            [Fact]
            public void GetAlgorithmByBlockSize_ReturnsNullForNonExistentSize()
            {
                var result = PivAlgorithms.GetAlgorithmByBlockSize<RsaAlgorithm>(1234);
                Assert.Null(result);
            }

            [Fact]
            public void GetAlgorithmByBlockSize_ThrowsForUnsupportedType()
            {
                Assert.Throws<ArgumentException>(() =>
                    PivAlgorithms.GetAlgorithmByBlockSize<UnsupportedAlgorithm>(256));
            }

            [Fact]
            public void GetAlgorithmByBlockSize_AppliesSelectorCorrectly()
            {
                var result = PivAlgorithms.GetAlgorithmByBlockSize<PivAlgorithm2>(2048, a => a.Identifier == 0x07);
                Assert.NotNull(result);
                Assert.Equal(0x07, result.Identifier);
            }

            [Fact]
            public void GetAlgorithmByBlockSize_ReturnsNullWhenSelectorExcludes()
            {
                var result = PivAlgorithms.GetAlgorithmByBlockSize<RsaAlgorithm>(2048, a => a.Identifier == 0xFF);
                Assert.Null(result);
            }

            // This test would fail in the single-parameter version
            [Fact]
            public void GetAlgorithmByBlockSize_DoesNotReturnBaseClassForDerivedRequest()
            {
                var result = PivAlgorithms.GetAlgorithmByBlockSize<RsaAlgorithm>(256);
                Assert.Null(result); // Should not return EccAlgorithm even though it's a PivAlgorithm2
            }

            // Define this for the unsupported type test
            public class UnsupportedAlgorithm : PivAlgorithm2
            {
                public UnsupportedAlgorithm() : base(0, 0, false, false) { }
            }
        }

        public class AsymmetricKeySizeHelperTests
        {
            [Theory]
            [InlineData(32, typeof(EccAlgorithm))]
            [InlineData(48, typeof(EccAlgorithm))]
            [InlineData(64, typeof(RsaAlgorithm))]
            [InlineData(128, typeof(RsaAlgorithm))]
            [InlineData(192, typeof(RsaAlgorithm))]
            [InlineData(256, typeof(RsaAlgorithm))]
            public void DetermineFromPrivateKey_ValidSizes_ReturnsCorrectAlgorithm(
                int keySizeInBytes, Type expectedType)
            {
                var privateKey = new byte[keySizeInBytes];
                var result = AsymmetricKeySizeHelper.DetermineFromPrivateKey(privateKey);
                Assert.IsType(expectedType, result);
            }

            [Fact]
            public void DetermineFromPrivateKey_InvalidSize_ThrowsArgumentException()
            {
                var privateKey = new byte[100]; // Invalid size
                Assert.Throws<ArgumentException>(() => AsymmetricKeySizeHelper.DetermineFromPrivateKey(privateKey));
            }

            [Theory]
            [InlineData(65, typeof(EccAlgorithm), 256, 0x11)]
            [InlineData(97, typeof(EccAlgorithm), 384, 0x14)]
            [InlineData(128, typeof(RsaAlgorithm), 1024, 0x6)]
            [InlineData(256, typeof(RsaAlgorithm), 2048, 0x7)]
            [InlineData(384, typeof(RsaAlgorithm), 3072, 0x5)]
            [InlineData(512, typeof(RsaAlgorithm), 4096, 0x16)]
            public void DetermineFromPublicKey_ValiKeySizes_ReturnsCorrectAlgorithm(
                int keySizeBytes, Type expectedType, int expectedKeySizeBits, int expectedAlgorithmIdentifier)
            {
                var publicKey = new byte[keySizeBytes];
                var result = AsymmetricKeySizeHelper.DetermineFromPublicKey(publicKey);

                Assert.IsType(expectedType, result);
                Assert.Equal(expectedKeySizeBits, result.KeySizeBits);
                Assert.Equal(expectedAlgorithmIdentifier, result.Identifier);
            }

            [Fact]
            public void DetermineFromPublicKey_InvalidSize_ThrowsArgumentException()
            {
                var publicKey = new byte[100]; // Invalid size
                Assert.Throws<ArgumentException>(() => AsymmetricKeySizeHelper.DetermineFromPublicKey(publicKey));
            }

            [Theory]
            [InlineData(65, true, 256, 0x11)] // Valid ECC P256
            [InlineData(97, true, 384, 0x14)] // Valid ECC P384
            [InlineData(256, true, 2048, 0x7)] // Valid RSA 2048
            [InlineData(100, false, 0, 0)] // Invalid size
            public void TryDetermineFromPublicKey_ReturnsExpectedBoolean(
                int keySizeInBytes, bool expectedBoolean, int expectedKeySizeBits, int expectedAlgorithmIdentifier)
            {
                var publicKey = new byte[keySizeInBytes];
                var result = AsymmetricKeySizeHelper.TryDetermineFromPublicKey(publicKey, out var algorithm);

                Assert.Equal(expectedBoolean, result);
                if (expectedBoolean)
                {
                    Assert.NotNull(algorithm);
                    Assert.Equal(expectedKeySizeBits, algorithm.KeySizeBits);
                    Assert.Equal(expectedAlgorithmIdentifier, algorithm.Identifier);
                }
                else
                {
                    Assert.Null(algorithm);
                }
            }
        }
    }
}
