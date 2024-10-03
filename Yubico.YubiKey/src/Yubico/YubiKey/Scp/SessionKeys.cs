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

namespace Yubico.YubiKey.Scp
{
    internal class SessionKeys : IDisposable
    {
        public ReadOnlyMemory<byte> GetMacKey => _macKey;
        public ReadOnlyMemory<byte> GetEncKey => _encryptionKey;
        public ReadOnlyMemory<byte> GetRmacKey => _rmacKey;

        private readonly Memory<byte> _macKey;
        private readonly Memory<byte> _encryptionKey;
        private readonly Memory<byte> _rmacKey;
        private bool _disposed;

        public SessionKeys(
            Memory<byte> sessionMacKey, 
            Memory<byte> sessionEncryptionKey, 
            Memory<byte> sessionRmacKey)
        {
            _macKey = sessionMacKey;
            _encryptionKey = sessionEncryptionKey;
            _rmacKey = sessionRmacKey;
            _disposed = false;
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        // Overwrite the memory of the keys
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    CryptographicOperations.ZeroMemory(_macKey.Span);
                    CryptographicOperations.ZeroMemory(_encryptionKey.Span);
                    CryptographicOperations.ZeroMemory(_rmacKey.Span);

                    _disposed = true;
                }
            }
        }
    }
}
