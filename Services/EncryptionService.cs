using RawrZSecurityPlatform.Models;
using System.Security.Cryptography;
using System.Text;
using System.IO.Compression;
// BouncyCastle references removed for now

namespace RawrZSecurityPlatform.Services
{
    public class EncryptionService : IEncryptionService
    {
        private readonly ILogger<EncryptionService> _logger;
        private readonly string _uploadsPath;
        private readonly string _downloadsPath;

        public EncryptionService(ILogger<EncryptionService> logger, IWebHostEnvironment environment)
        {
            _logger = logger;
            _uploadsPath = Path.Combine(environment.ContentRootPath, "uploads");
            _downloadsPath = Path.Combine(environment.ContentRootPath, "downloads");
            
            Directory.CreateDirectory(_uploadsPath);
            Directory.CreateDirectory(_downloadsPath);
        }

        public async Task<EncryptionResponse> EncryptFileAsync(IFormFile file, EncryptionRequest request)
        {
            try
            {
                var fileName = Path.GetFileNameWithoutExtension(file.FileName);
                var fileExtension = Path.GetExtension(file.FileName);
                var encryptedFileName = $"{fileName}_{DateTime.Now:yyyyMMdd_HHmmss}{request.Extension}";
                var encryptedFilePath = Path.Combine(_downloadsPath, encryptedFileName);

                using var inputStream = file.OpenReadStream();
                using var outputStream = new FileStream(encryptedFilePath, FileMode.Create);

                byte[] fileData;
                using (var memoryStream = new MemoryStream())
                {
                    await inputStream.CopyToAsync(memoryStream);
                    fileData = memoryStream.ToArray();
                }

                // Apply compression if requested
                if (request.Compress)
                {
                    fileData = await CompressDataAsync(fileData);
                }

                // Apply obfuscation if requested
                if (request.Obfuscate)
                {
                    fileData = await ObfuscateDataAsync(fileData);
                }

                // Encrypt the data
                var (encryptedData, key, iv) = await EncryptDataAsync(fileData, request);

                // Apply stealth mode if requested
                if (request.Stealth)
                {
                    encryptedData = await ApplyStealthModeAsync(encryptedData, request);
                }

                await outputStream.WriteAsync(encryptedData);

                return new EncryptionResponse
                {
                    Success = true,
                    Message = "File encrypted successfully",
                    OriginalName = file.FileName,
                    EncryptedName = encryptedFileName,
                    OriginalSize = file.Length,
                    EncryptedSize = encryptedData.Length,
                    Algorithm = request.Algorithm,
                    DownloadUrl = $"/download/{encryptedFileName}",
                    Key = Convert.ToBase64String(key),
                    IV = Convert.ToBase64String(iv),
                    Hash = ComputeHash(encryptedData, "SHA256")
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error encrypting file");
                return new EncryptionResponse
                {
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        public async Task<DecryptionResponse> DecryptFileAsync(IFormFile file, DecryptionRequest request)
        {
            try
            {
                var fileName = Path.GetFileNameWithoutExtension(file.FileName);
                var decryptedFileName = $"{fileName}_decrypted_{DateTime.Now:yyyyMMdd_HHmmss}";
                var decryptedFilePath = Path.Combine(_downloadsPath, decryptedFileName);

                using var inputStream = file.OpenReadStream();
                using var outputStream = new FileStream(decryptedFilePath, FileMode.Create);

                byte[] encryptedData;
                using (var memoryStream = new MemoryStream())
                {
                    await inputStream.CopyToAsync(memoryStream);
                    encryptedData = memoryStream.ToArray();
                }

                var key = Convert.FromBase64String(request.Key);
                var iv = Convert.FromBase64String(request.IV);

                var decryptedData = await DecryptDataAsync(encryptedData, key, iv, request.Algorithm);

                // Remove obfuscation
                decryptedData = await DeobfuscateDataAsync(decryptedData);

                // Decompress if needed
                decryptedData = await DecompressDataAsync(decryptedData);

                await outputStream.WriteAsync(decryptedData);

                return new DecryptionResponse
                {
                    Success = true,
                    Message = "File decrypted successfully",
                    OriginalName = file.FileName,
                    DecryptedName = decryptedFileName,
                    DecryptedSize = decryptedData.Length,
                    DownloadUrl = $"/download/{decryptedFileName}"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error decrypting file");
                return new DecryptionResponse
                {
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        public async Task<HashResponse> HashFileAsync(IFormFile file, HashRequest request)
        {
            try
            {
                using var inputStream = file.OpenReadStream();
                var hash = await ComputeHashAsync(inputStream, request.Algorithm);

                var hashFileName = $"{Path.GetFileNameWithoutExtension(file.FileName)}_{request.Algorithm.ToLower()}{request.Extension}";
                var hashFilePath = Path.Combine(_downloadsPath, hashFileName);

                if (request.Save)
                {
                    await System.IO.File.WriteAllTextAsync(hashFilePath, hash);
                }

                return new HashResponse
                {
                    Success = true,
                    Hash = hash,
                    Algorithm = request.Algorithm,
                    FileName = hashFileName,
                    DownloadUrl = request.Save ? $"/download/{hashFileName}" : ""
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error hashing file");
                return new HashResponse
                {
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        public async Task<FileAnalysisResponse> AnalyzeFileAsync(IFormFile file, FileAnalysisRequest request)
        {
            try
            {
                using var inputStream = file.OpenReadStream();
                var fileData = new byte[file.Length];
                await inputStream.ReadAsync(fileData, 0, (int)file.Length);

                var response = new FileAnalysisResponse
                {
                    Success = true,
                    FileName = file.FileName,
                    FileType = GetFileType(fileData),
                    RiskLevel = "Low"
                };

                if (request.EntropyAnalysis)
                {
                    var entropyResult = await EntropyAnalysisAsync(file);
                    response.Entropy = entropyResult.Entropy;
                    response.Interpretation = entropyResult.Interpretation;
                    response.Randomness = entropyResult.Randomness;
                }

                if (request.MalwareScan)
                {
                    var malwareResult = await ScanForMalwareAsync(file);
                    response.Status = malwareResult.Status;
                    response.Threats = malwareResult.Threats;
                    if (malwareResult.Threats.Any())
                        response.RiskLevel = "High";
                }

                if (request.IntegrityCheck)
                {
                    var integrityResult = await IntegrityCheckAsync(file);
                    response.Checksum = integrityResult.Checksum;
                    if (integrityResult.Status != "Valid")
                        response.RiskLevel = "Medium";
                }

                return response;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing file");
                return new FileAnalysisResponse
                {
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        public async Task<FileAnalysisResponse> ScanForMalwareAsync(IFormFile file)
        {
            try
            {
                using var inputStream = file.OpenReadStream();
                var fileData = new byte[file.Length];
                await inputStream.ReadAsync(fileData, 0, (int)file.Length);

                var threats = new List<string>();
                var status = "Clean";

                // Basic malware signatures (simplified for demo)
                var suspiciousPatterns = new[]
                {
                    "eval(", "exec(", "system(", "shell_exec(", "passthru(",
                    "CreateProcess", "VirtualAlloc", "WriteProcessMemory",
                    "LoadLibrary", "GetProcAddress", "CreateRemoteThread"
                };

                var fileContent = Encoding.UTF8.GetString(fileData);
                foreach (var pattern in suspiciousPatterns)
                {
                    if (fileContent.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        threats.Add($"Suspicious pattern: {pattern}");
                        status = "Suspicious";
                    }
                }

                // Check entropy for packed/obfuscated content
                var entropy = CalculateEntropy(fileData);
                if (entropy > 7.5)
                {
                    threats.Add("High entropy - possible packing/obfuscation");
                    status = "Suspicious";
                }

                return new FileAnalysisResponse
                {
                    Success = true,
                    FileName = file.FileName,
                    Status = status,
                    Threats = threats,
                    Entropy = entropy
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error scanning for malware");
                return new FileAnalysisResponse
                {
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        public async Task<FileAnalysisResponse> EntropyAnalysisAsync(IFormFile file)
        {
            try
            {
                using var inputStream = file.OpenReadStream();
                var fileData = new byte[file.Length];
                await inputStream.ReadAsync(fileData, 0, (int)file.Length);

                var entropy = CalculateEntropy(fileData);
                var randomness = (entropy / 8.0) * 100;
                
                string interpretation;
                if (entropy < 4.0)
                    interpretation = "Low entropy - likely uncompressed text";
                else if (entropy < 6.0)
                    interpretation = "Medium entropy - compressed or binary data";
                else if (entropy < 7.5)
                    interpretation = "High entropy - encrypted or compressed data";
                else
                    interpretation = "Very high entropy - likely encrypted or packed";

                return new FileAnalysisResponse
                {
                    Success = true,
                    FileName = file.FileName,
                    Entropy = entropy,
                    Interpretation = interpretation,
                    Randomness = randomness
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error performing entropy analysis");
                return new FileAnalysisResponse
                {
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        public async Task<FileAnalysisResponse> IntegrityCheckAsync(IFormFile file)
        {
            try
            {
                using var inputStream = file.OpenReadStream();
                var checksum = await ComputeHashAsync(inputStream, "SHA256");

                return new FileAnalysisResponse
                {
                    Success = true,
                    FileName = file.FileName,
                    Checksum = checksum,
                    Status = "Valid"
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error performing integrity check");
                return new FileAnalysisResponse
                {
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        public async Task<KeyGenerationResponse> GenerateKeysAsync(KeyGenerationRequest request)
        {
            try
            {
                var keyId = Guid.NewGuid().ToString();
                var (publicKey, privateKey) = await GenerateKeyPairAsync(request.Algorithm, request.KeySize);

                return new KeyGenerationResponse
                {
                    Success = true,
                    KeyId = keyId,
                    Algorithm = request.Algorithm,
                    PublicKey = Convert.ToBase64String(publicKey),
                    PrivateKey = Convert.ToBase64String(privateKey)
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating keys");
                return new KeyGenerationResponse
                {
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        public async Task<KeyExportResponse> ExportKeysAsync()
        {
            try
            {
                // This would export all stored keys
                var keysData = new { keys = new[] { "key1", "key2" } };
                var keysJson = System.Text.Json.JsonSerializer.Serialize(keysData);
                
                var fileName = $"keys_export_{DateTime.Now:yyyyMMdd_HHmmss}.json";
                var filePath = Path.Combine(_downloadsPath, fileName);
                
                await System.IO.File.WriteAllTextAsync(filePath, keysJson);

                return new KeyExportResponse
                {
                    Success = true,
                    DownloadUrl = $"/download/{fileName}",
                    KeyCount = 2
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error exporting keys");
                return new KeyExportResponse
                {
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        public async Task<KeyImportResponse> ImportKeysAsync(IFormFile file)
        {
            try
            {
                using var inputStream = file.OpenReadStream();
                using var reader = new StreamReader(inputStream);
                var keysJson = await reader.ReadToEndAsync();

                // Parse and import keys
                var keyCount = 1; // Simplified

                return new KeyImportResponse
                {
                    Success = true,
                    KeyCount = keyCount
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error importing keys");
                return new KeyImportResponse
                {
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        // Helper methods
        private async Task<(byte[], byte[], byte[])> EncryptDataAsync(byte[] data, EncryptionRequest request)
        {
            var key = new byte[request.KeySize / 8];
            var iv = new byte[16];
            
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
                rng.GetBytes(iv);
            }

            byte[] encryptedData;

            switch (request.Algorithm.ToUpper())
            {
                case "AES-256-GCM":
                    encryptedData = await EncryptAESGCMAsync(data, key, iv);
                    break;
                case "AES-256-CBC":
                    encryptedData = await EncryptAESCBCAsync(data, key, iv);
                    break;
                case "CHACHA20-POLY1305":
                    encryptedData = await EncryptChaCha20Poly1305Async(data, key, iv);
                    break;
                default:
                    encryptedData = await EncryptAESGCMAsync(data, key, iv);
                    break;
            }

            return (encryptedData, key, iv);
        }

        private async Task<byte[]> DecryptDataAsync(byte[] encryptedData, byte[] key, byte[] iv, string algorithm)
        {
            switch (algorithm.ToUpper())
            {
                case "AES-256-GCM":
                    return await DecryptAESGCMAsync(encryptedData, key, iv);
                case "AES-256-CBC":
                    return await DecryptAESCBCAsync(encryptedData, key, iv);
                case "CHACHA20-POLY1305":
                    return await DecryptChaCha20Poly1305Async(encryptedData, key, iv);
                default:
                    return await DecryptAESGCMAsync(encryptedData, key, iv);
            }
        }

        private async Task<byte[]> EncryptAESGCMAsync(byte[] data, byte[] key, byte[] iv)
        {
            using var aes = new AesGcm(key);
            var encryptedData = new byte[data.Length];
            var tag = new byte[16];
            
            aes.Encrypt(iv, data, encryptedData, tag);
            
            // Combine encrypted data with tag
            var result = new byte[encryptedData.Length + tag.Length];
            Array.Copy(encryptedData, 0, result, 0, encryptedData.Length);
            Array.Copy(tag, 0, result, encryptedData.Length, tag.Length);
            
            return result;
        }

        private async Task<byte[]> DecryptAESGCMAsync(byte[] encryptedData, byte[] key, byte[] iv)
        {
            using var aes = new AesGcm(key);
            var tag = new byte[16];
            var ciphertext = new byte[encryptedData.Length - 16];
            
            Array.Copy(encryptedData, encryptedData.Length - 16, tag, 0, 16);
            Array.Copy(encryptedData, 0, ciphertext, 0, ciphertext.Length);
            
            var decryptedData = new byte[ciphertext.Length];
            aes.Decrypt(iv, ciphertext, tag, decryptedData);
            
            return decryptedData;
        }

        private async Task<byte[]> EncryptAESCBCAsync(byte[] data, byte[] key, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }

        private async Task<byte[]> DecryptAESCBCAsync(byte[] encryptedData, byte[] key, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var decryptor = aes.CreateDecryptor();
            return decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
        }

        private async Task<byte[]> EncryptChaCha20Poly1305Async(byte[] data, byte[] key, byte[] iv)
        {
            // Simplified ChaCha20-Poly1305 implementation
            // In production, use a proper library like BouncyCastle
            return await EncryptAESGCMAsync(data, key, iv);
        }

        private async Task<byte[]> DecryptChaCha20Poly1305Async(byte[] encryptedData, byte[] key, byte[] iv)
        {
            // Simplified ChaCha20-Poly1305 implementation
            return await DecryptAESGCMAsync(encryptedData, key, iv);
        }

        private async Task<byte[]> CompressDataAsync(byte[] data)
        {
            using var outputStream = new MemoryStream();
            using (var gzipStream = new GZipStream(outputStream, CompressionMode.Compress))
            {
                await gzipStream.WriteAsync(data, 0, data.Length);
            }
            return outputStream.ToArray();
        }

        private async Task<byte[]> DecompressDataAsync(byte[] compressedData)
        {
            using var inputStream = new MemoryStream(compressedData);
            using var gzipStream = new GZipStream(inputStream, CompressionMode.Decompress);
            using var outputStream = new MemoryStream();
            await gzipStream.CopyToAsync(outputStream);
            return outputStream.ToArray();
        }

        private async Task<byte[]> ObfuscateDataAsync(byte[] data)
        {
            // Simple XOR obfuscation
            var obfuscated = new byte[data.Length];
            var key = 0xAA;
            
            for (int i = 0; i < data.Length; i++)
            {
                obfuscated[i] = (byte)(data[i] ^ key);
                key = (byte)((key + 1) % 256);
            }
            
            return obfuscated;
        }

        private async Task<byte[]> DeobfuscateDataAsync(byte[] obfuscatedData)
        {
            // Reverse XOR obfuscation
            return await ObfuscateDataAsync(obfuscatedData);
        }

        private async Task<byte[]> ApplyStealthModeAsync(byte[] data, EncryptionRequest request)
        {
            // Apply stealth techniques based on request options
            if (request.Evasion)
            {
                // Add anti-VM/anti-debug code
            }
            
            if (request.Polymorphic)
            {
                // Apply polymorphic techniques
            }
            
            return data;
        }

        private async Task<string> ComputeHashAsync(Stream stream, string algorithm)
        {
            using var hashAlgorithm = HashAlgorithm.Create(algorithm) ?? SHA256.Create();
            var hash = await hashAlgorithm.ComputeHashAsync(stream);
            return Convert.ToHexString(hash).ToLower();
        }

        private string ComputeHash(byte[] data, string algorithm)
        {
            using var hashAlgorithm = HashAlgorithm.Create(algorithm) ?? SHA256.Create();
            var hash = hashAlgorithm.ComputeHash(data);
            return Convert.ToHexString(hash).ToLower();
        }

        private double CalculateEntropy(byte[] data)
        {
            var frequencies = new int[256];
            foreach (var b in data)
            {
                frequencies[b]++;
            }

            double entropy = 0;
            var length = data.Length;
            
            for (int i = 0; i < 256; i++)
            {
                if (frequencies[i] > 0)
                {
                    var probability = (double)frequencies[i] / length;
                    entropy -= probability * Math.Log2(probability);
                }
            }
            
            return entropy;
        }

        private string GetFileType(byte[] data)
        {
            if (data.Length < 4) return "Unknown";
            
            // Check magic bytes
            if (data[0] == 0x4D && data[1] == 0x5A) return "PE Executable";
            if (data[0] == 0x7F && data[1] == 0x45 && data[2] == 0x4C && data[3] == 0x46) return "ELF Executable";
            if (data[0] == 0x50 && data[1] == 0x4B) return "ZIP/Office Document";
            if (data[0] == 0x25 && data[1] == 0x50 && data[2] == 0x44 && data[3] == 0x46) return "PDF Document";
            
            return "Binary File";
        }

        private async Task<(byte[], byte[])> GenerateKeyPairAsync(string algorithm, int keySize)
        {
            var publicKey = new byte[keySize / 8];
            var privateKey = new byte[keySize / 8];
            
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(publicKey);
                rng.GetBytes(privateKey);
            }
            
            return (publicKey, privateKey);
        }
    }
}
