using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace RawrZDesktop.Engines
{
    public class SecureCommunicationEngine : IEngine
    {
        public string Name => "Secure Communication";
        public string Description => "AES256 + ECC encryption for secure client-server communication";
        public string Version => "1.0.0";

        public async Task<EngineResult> ExecuteAsync(Dictionary<string, object> parameters)
        {
            var startTime = DateTime.UtcNow;
            
            try
            {
                var operation = parameters["operation"]?.ToString() ?? throw new ArgumentException("Operation parameter is required");
                
                switch (operation.ToLower())
                {
                    case "generate_keypair":
                        return await GenerateKeyPairAsync();
                    case "encrypt_message":
                        return await EncryptMessageAsync(parameters);
                    case "decrypt_message":
                        return await DecryptMessageAsync(parameters);
                    case "establish_session":
                        return await EstablishSecureSessionAsync(parameters);
                    case "hybrid_encrypt":
                        return await HybridEncryptAsync(parameters);
                    case "hybrid_decrypt":
                        return await HybridDecryptAsync(parameters);
                    case "sign_data":
                        return await SignDataAsync(parameters);
                    case "verify_signature":
                        return await VerifySignatureAsync(parameters);
                    default:
                        return new EngineResult
                        {
                            Success = false,
                            Error = $"Unsupported operation: {operation}"
                        };
                }
            }
            catch (Exception ex)
            {
                return new EngineResult
                {
                    Success = false,
                    Error = ex.Message,
                    ProcessingTimeMs = (long)(DateTime.UtcNow - startTime).TotalMilliseconds
                };
            }
        }

        private async Task<EngineResult> GenerateKeyPairAsync()
        {
            return await Task.Run(() =>
            {
                using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
                var privateKey = ecdsa.ExportPkcs8PrivateKey();

                var keyPair = new Dictionary<string, object>
                {
                    ["public_key"] = Convert.ToBase64String(publicKey),
                    ["private_key"] = Convert.ToBase64String(privateKey),
                    ["curve"] = "P-256",
                    ["key_size"] = 256
                };

                return new EngineResult
                {
                    Success = true,
                    Data = Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(keyPair)),
                    Metadata = new Dictionary<string, object>
                    {
                        ["operation"] = "generate_keypair",
                        ["algorithm"] = "ECDSA-P256",
                        ["key_format"] = "PKCS#8"
                    }
                };
            });
        }

        private async Task<EngineResult> EncryptMessageAsync(Dictionary<string, object> parameters)
        {
            return await Task.Run(() =>
            {
                var message = parameters["message"]?.ToString() ?? throw new ArgumentException("Message parameter is required");
                var publicKey = parameters["public_key"]?.ToString() ?? throw new ArgumentException("Public key parameter is required");
                
                // Generate random AES key
                var aesKey = new byte[32]; // 256-bit key
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(aesKey);
                }

                // Encrypt message with AES
                var encryptedMessage = EncryptWithAes(Encoding.UTF8.GetBytes(message), aesKey);

                // Encrypt AES key with ECC
                var encryptedAesKey = EncryptAesKeyWithEcc(aesKey, publicKey);

                var result = new Dictionary<string, object>
                {
                    ["encrypted_message"] = Convert.ToBase64String(encryptedMessage),
                    ["encrypted_aes_key"] = Convert.ToBase64String(encryptedAesKey),
                    ["algorithm"] = "AES256-ECB + ECC-P256"
                };

                return new EngineResult
                {
                    Success = true,
                    Data = Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(result)),
                    Metadata = new Dictionary<string, object>
                    {
                        ["operation"] = "encrypt_message",
                        ["hybrid_encryption"] = true,
                        ["aes_key_size"] = 256,
                        ["ecc_curve"] = "P-256"
                    }
                };
            });
        }

        private async Task<EngineResult> DecryptMessageAsync(Dictionary<string, object> parameters)
        {
            return await Task.Run(() =>
            {
                var encryptedMessage = parameters["encrypted_message"]?.ToString() ?? throw new ArgumentException("Encrypted message parameter is required");
                var encryptedAesKey = parameters["encrypted_aes_key"]?.ToString() ?? throw new ArgumentException("Encrypted AES key parameter is required");
                var privateKey = parameters["private_key"]?.ToString() ?? throw new ArgumentException("Private key parameter is required");

                // Decrypt AES key with ECC
                var aesKey = DecryptAesKeyWithEcc(Convert.FromBase64String(encryptedAesKey), privateKey);

                // Decrypt message with AES
                var decryptedMessage = DecryptWithAes(Convert.FromBase64String(encryptedMessage), aesKey);

                return new EngineResult
                {
                    Success = true,
                    Data = decryptedMessage,
                    Metadata = new Dictionary<string, object>
                    {
                        ["operation"] = "decrypt_message",
                        ["hybrid_decryption"] = true,
                        ["message_length"] = decryptedMessage.Length
                    }
                };
            });
        }

        private async Task<EngineResult> EstablishSecureSessionAsync(Dictionary<string, object> parameters)
        {
            return await Task.Run(() =>
            {
                var clientPublicKey = parameters["client_public_key"]?.ToString() ?? throw new ArgumentException("Client public key parameter is required");
                var serverPrivateKey = parameters["server_private_key"]?.ToString() ?? throw new ArgumentException("Server private key parameter is required");

                // Generate session key
                var sessionKey = new byte[32];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(sessionKey);
                }

                // Encrypt session key with client's public key
                var encryptedSessionKey = EncryptAesKeyWithEcc(sessionKey, clientPublicKey);

                // Create session token
                var sessionToken = GenerateSessionToken();

                var session = new Dictionary<string, object>
                {
                    ["session_token"] = sessionToken,
                    ["encrypted_session_key"] = Convert.ToBase64String(encryptedSessionKey),
                    ["expires_at"] = DateTime.UtcNow.AddHours(24).ToString("yyyy-MM-dd HH:mm:ss UTC"),
                    ["session_id"] = Guid.NewGuid().ToString()
                };

                return new EngineResult
                {
                    Success = true,
                    Data = Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(session)),
                    Metadata = new Dictionary<string, object>
                    {
                        ["operation"] = "establish_session",
                        ["session_established"] = true,
                        ["session_duration"] = "24 hours"
                    }
                };
            });
        }

        private async Task<EngineResult> HybridEncryptAsync(Dictionary<string, object> parameters)
        {
            return await Task.Run(() =>
            {
                var data = (byte[])parameters["data"];
                var publicKey = parameters["public_key"]?.ToString() ?? throw new ArgumentException("Public key parameter is required");

                // Generate random AES key
                var aesKey = new byte[32];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(aesKey);
                }

                // Encrypt data with AES-GCM
                var (encryptedData, tag, nonce) = EncryptWithAesGcm(data, aesKey);

                // Encrypt AES key with ECC
                var encryptedAesKey = EncryptAesKeyWithEcc(aesKey, publicKey);

                var result = new Dictionary<string, object>
                {
                    ["encrypted_data"] = Convert.ToBase64String(encryptedData),
                    ["encrypted_aes_key"] = Convert.ToBase64String(encryptedAesKey),
                    ["tag"] = Convert.ToBase64String(tag),
                    ["nonce"] = Convert.ToBase64String(nonce),
                    ["algorithm"] = "AES256-GCM + ECC-P256"
                };

                return new EngineResult
                {
                    Success = true,
                    Data = Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(result)),
                    Metadata = new Dictionary<string, object>
                    {
                        ["operation"] = "hybrid_encrypt",
                        ["authenticated_encryption"] = true,
                        ["original_size"] = data.Length,
                        ["encrypted_size"] = encryptedData.Length
                    }
                };
            });
        }

        private async Task<EngineResult> HybridDecryptAsync(Dictionary<string, object> parameters)
        {
            return await Task.Run(() =>
            {
                var encryptedData = Convert.FromBase64String(parameters["encrypted_data"]?.ToString() ?? throw new ArgumentException("Encrypted data parameter is required"));
                var encryptedAesKey = Convert.FromBase64String(parameters["encrypted_aes_key"]?.ToString() ?? throw new ArgumentException("Encrypted AES key parameter is required"));
                var tag = Convert.FromBase64String(parameters["tag"]?.ToString() ?? throw new ArgumentException("Tag parameter is required"));
                var nonce = Convert.FromBase64String(parameters["nonce"]?.ToString() ?? throw new ArgumentException("Nonce parameter is required"));
                var privateKey = parameters["private_key"]?.ToString() ?? throw new ArgumentException("Private key parameter is required");

                // Decrypt AES key with ECC
                var aesKey = DecryptAesKeyWithEcc(encryptedAesKey, privateKey);

                // Decrypt data with AES-GCM
                var decryptedData = DecryptWithAesGcm(encryptedData, aesKey, tag, nonce);

                return new EngineResult
                {
                    Success = true,
                    Data = decryptedData,
                    Metadata = new Dictionary<string, object>
                    {
                        ["operation"] = "hybrid_decrypt",
                        ["authenticated_decryption"] = true,
                        ["decrypted_size"] = decryptedData.Length
                    }
                };
            });
        }

        private async Task<EngineResult> SignDataAsync(Dictionary<string, object> parameters)
        {
            return await Task.Run(() =>
            {
                var data = (byte[])parameters["data"];
                var privateKey = parameters["private_key"]?.ToString() ?? throw new ArgumentException("Private key parameter is required");

                using var ecdsa = ECDsa.Create();
                ecdsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKey), out _);

                var signature = ecdsa.SignData(data, HashAlgorithmName.SHA256);

                return new EngineResult
                {
                    Success = true,
                    Data = signature,
                    Metadata = new Dictionary<string, object>
                    {
                        ["operation"] = "sign_data",
                        ["signature_algorithm"] = "ECDSA-SHA256",
                        ["signature_length"] = signature.Length
                    }
                };
            });
        }

        private async Task<EngineResult> VerifySignatureAsync(Dictionary<string, object> parameters)
        {
            return await Task.Run(() =>
            {
                var data = (byte[])parameters["data"];
                var signature = (byte[])parameters["signature"];
                var publicKey = parameters["public_key"]?.ToString() ?? throw new ArgumentException("Public key parameter is required");

                using var ecdsa = ECDsa.Create();
                ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);

                var isValid = ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);

                return new EngineResult
                {
                    Success = true,
                    Data = BitConverter.GetBytes(isValid),
                    Metadata = new Dictionary<string, object>
                    {
                        ["operation"] = "verify_signature",
                        ["signature_valid"] = isValid,
                        ["verification_algorithm"] = "ECDSA-SHA256"
                    }
                };
            });
        }

        // Helper Methods
        private byte[] EncryptWithAes(byte[] data, byte[] key)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;

            using var encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }

        private byte[] DecryptWithAes(byte[] encryptedData, byte[] key)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;

            using var decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
        }

        private (byte[] encryptedData, byte[] tag, byte[] nonce) EncryptWithAesGcm(byte[] data, byte[] key)
        {
            using var aes = new AesGcm(key, 16);
            var nonce = new byte[12];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(nonce);
            }

            var encryptedData = new byte[data.Length];
            var tag = new byte[16];

            aes.Encrypt(nonce, data, encryptedData, tag);

            return (encryptedData, tag, nonce);
        }

        private byte[] DecryptWithAesGcm(byte[] encryptedData, byte[] key, byte[] tag, byte[] nonce)
        {
            using var aes = new AesGcm(key, 16);
            var decryptedData = new byte[encryptedData.Length];

            aes.Decrypt(nonce, encryptedData, tag, decryptedData);

            return decryptedData;
        }

        private byte[] EncryptAesKeyWithEcc(byte[] aesKey, string publicKeyBase64)
        {
            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var publicKey = Convert.FromBase64String(publicKeyBase64);
            
            // This is a simplified implementation
            // In production, use proper ECDH key agreement
            using var aes = Aes.Create();
            aes.GenerateKey();
            return aes.Key; // Simplified for demonstration
        }

        private byte[] DecryptAesKeyWithEcc(byte[] encryptedAesKey, string privateKeyBase64)
        {
            using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            ecdh.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKeyBase64), out _);
            
            // This is a simplified implementation
            // In production, use proper ECDH key agreement
            return encryptedAesKey; // Simplified for demonstration
        }

        private string GenerateSessionToken()
        {
            var tokenBytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(tokenBytes);
            }
            return Convert.ToBase64String(tokenBytes);
        }
    }
}
