using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Amazon.S3;
using Amazon.S3.Transfer;
using Amazon.S3.Model;

namespace AIDesktopHelper.Api.Services
{
    /// <summary>
    /// Secure file exchange service for handling file operations between extension and desktop
    /// Provides encryption, secure storage, and access control
    /// </summary>
    public class SecureFileExchangeService
    {
        private readonly IAmazonS3 _s3Client;
        private readonly EncryptionService _encryptionService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<SecureFileExchangeService> _logger;
        private readonly string _bucketName;
        private readonly string _basePath;

        public SecureFileExchangeService(
            IAmazonS3 s3Client, 
            EncryptionService encryptionService, 
            IConfiguration configuration, 
            ILogger<SecureFileExchangeService> logger)
        {
            _s3Client = s3Client;
            _encryptionService = encryptionService;
            _configuration = configuration;
            _logger = logger;
            _bucketName = _configuration["DigitalOcean:Spaces:BucketName"] ?? "ai-desktop-helper-files";
            _basePath = _configuration["DigitalOcean:Spaces:BasePath"] ?? "secure-files";
        }

        /// <summary>
        /// Uploads a file securely to cloud storage
        /// </summary>
        /// <param name="userId">User identifier</param>
        /// <param name="filename">Original filename</param>
        /// <param name="fileContent">File content as byte array</param>
        /// <param name="metadata">Optional metadata</param>
        /// <returns>Upload result with file information</returns>
        public async Task<FileUploadResult> UploadFileAsync(string userId, string filename, byte[] fileContent, Dictionary<string, string> metadata = null)
        {
            try
            {
                _logger.LogInformation($"Uploading file {filename} for user {userId}");

                // Generate unique file key
                var fileKey = GenerateFileKey(userId, filename);
                
                // Encrypt file content
                var encryptedContent = _encryptionService.AesEncrypt(fileContent);
                
                // Prepare metadata
                var s3Metadata = new Dictionary<string, string>
                {
                    ["original-filename"] = filename,
                    ["user-id"] = userId,
                    ["upload-timestamp"] = DateTime.UtcNow.ToString("O"),
                    ["content-type"] = GetContentType(filename),
                    ["encrypted"] = "true"
                };

                if (metadata != null)
                {
                    foreach (var kvp in metadata)
                    {
                        s3Metadata[kvp.Key] = kvp.Value;
                    }
                }

                // Upload to S3/DigitalOcean Spaces
                var uploadRequest = new TransferUtilityUploadRequest
                {
                    BucketName = _bucketName,
                    Key = fileKey,
                    InputStream = new MemoryStream(encryptedContent),
                    CannedACL = S3CannedACL.Private,
                    Metadata = s3Metadata
                };

                var transferUtility = new TransferUtility(_s3Client);
                await transferUtility.UploadAsync(uploadRequest);

                _logger.LogInformation($"Successfully uploaded file {filename} with key {fileKey}");

                return new FileUploadResult
                {
                    Success = true,
                    FileKey = fileKey,
                    OriginalFilename = filename,
                    FileSize = fileContent.Length,
                    UploadTimestamp = DateTime.UtcNow,
                    Metadata = s3Metadata
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error uploading file {filename} for user {userId}");
                return new FileUploadResult
                {
                    Success = false,
                    ErrorMessage = ex.Message
                };
            }
        }

        /// <summary>
        /// Downloads a file securely from cloud storage
        /// </summary>
        /// <param name="userId">User identifier</param>
        /// <param name="fileKey">File key</param>
        /// <returns>Download result with file content</returns>
        public async Task<FileDownloadResult> DownloadFileAsync(string userId, string fileKey)
        {
            try
            {
                _logger.LogInformation($"Downloading file {fileKey} for user {userId}");

                // Verify user has access to this file
                if (!await VerifyFileAccessAsync(userId, fileKey))
                {
                    return new FileDownloadResult
                    {
                        Success = false,
                        ErrorMessage = "Access denied to file"
                    };
                }

                // Download from S3/DigitalOcean Spaces
                var request = new GetObjectRequest
                {
                    BucketName = _bucketName,
                    Key = fileKey
                };

                using var response = await _s3Client.GetObjectAsync(request);
                using var memoryStream = new MemoryStream();
                await response.ResponseStream.CopyToAsync(memoryStream);
                var encryptedContent = memoryStream.ToArray();

                // Decrypt file content
                var decryptedContent = _encryptionService.AesDecrypt(encryptedContent);

                // Get metadata
                var metadata = new Dictionary<string, string>();
                foreach (var key in response.Metadata.Keys)
                {
                    metadata[key] = response.Metadata[key];
                }

                _logger.LogInformation($"Successfully downloaded file {fileKey}");

                return new FileDownloadResult
                {
                    Success = true,
                    FileContent = decryptedContent,
                    OriginalFilename = metadata.GetValueOrDefault("original-filename", "unknown"),
                    FileSize = decryptedContent.Length,
                    Metadata = metadata
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error downloading file {fileKey} for user {userId}");
                return new FileDownloadResult
                {
                    Success = false,
                    ErrorMessage = ex.Message
                };
            }
        }

        /// <summary>
        /// Lists files for a user
        /// </summary>
        /// <param name="userId">User identifier</param>
        /// <param name="prefix">Optional prefix filter</param>
        /// <returns>List of file information</returns>
        public async Task<List<FileInfo>> ListFilesAsync(string userId, string prefix = null)
        {
            try
            {
                _logger.LogInformation($"Listing files for user {userId}");

                var request = new ListObjectsV2Request
                {
                    BucketName = _bucketName,
                    Prefix = $"{_basePath}/{userId}/"
                };

                if (!string.IsNullOrEmpty(prefix))
                {
                    request.Prefix += prefix;
                }

                var response = await _s3Client.ListObjectsV2Async(request);
                var files = new List<FileInfo>();

                foreach (var s3Object in response.S3Objects)
                {
                    // Get object metadata
                    var metadataRequest = new GetObjectMetadataRequest
                    {
                        BucketName = _bucketName,
                        Key = s3Object.Key
                    };

                    var metadataResponse = await _s3Client.GetObjectMetadataAsync(metadataRequest);
                    
                    files.Add(new FileInfo
                    {
                        FileKey = s3Object.Key,
                        OriginalFilename = metadataResponse.Metadata.GetValueOrDefault("original-filename", "unknown"),
                        FileSize = s3Object.Size,
                        LastModified = s3Object.LastModified,
                        ContentType = metadataResponse.ContentType,
                        Metadata = metadataResponse.Metadata
                    });
                }

                _logger.LogInformation($"Found {files.Count} files for user {userId}");
                return files;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error listing files for user {userId}");
                return new List<FileInfo>();
            }
        }

        /// <summary>
        /// Deletes a file
        /// </summary>
        /// <param name="userId">User identifier</param>
        /// <param name="fileKey">File key</param>
        /// <returns>True if deletion successful</returns>
        public async Task<bool> DeleteFileAsync(string userId, string fileKey)
        {
            try
            {
                _logger.LogInformation($"Deleting file {fileKey} for user {userId}");

                // Verify user has access to this file
                if (!await VerifyFileAccessAsync(userId, fileKey))
                {
                    _logger.LogWarning($"Access denied for user {userId} to delete file {fileKey}");
                    return false;
                }

                var request = new DeleteObjectRequest
                {
                    BucketName = _bucketName,
                    Key = fileKey
                };

                await _s3Client.DeleteObjectAsync(request);

                _logger.LogInformation($"Successfully deleted file {fileKey}");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error deleting file {fileKey} for user {userId}");
                return false;
            }
        }

        /// <summary>
        /// Generates a secure file key
        /// </summary>
        /// <param name="userId">User identifier</param>
        /// <param name="filename">Original filename</param>
        /// <returns>Secure file key</returns>
        private string GenerateFileKey(string userId, string filename)
        {
            var timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            var randomId = Guid.NewGuid().ToString("N")[..8];
            var sanitizedFilename = SanitizeFilename(filename);
            
            return $"{_basePath}/{userId}/{timestamp}_{randomId}_{sanitizedFilename}";
        }

        /// <summary>
        /// Sanitizes filename for safe storage
        /// </summary>
        /// <param name="filename">Original filename</param>
        /// <returns>Sanitized filename</returns>
        private string SanitizeFilename(string filename)
        {
            var invalidChars = Path.GetInvalidFileNameChars();
            var sanitized = filename;
            
            foreach (var invalidChar in invalidChars)
            {
                sanitized = sanitized.Replace(invalidChar, '_');
            }
            
            return sanitized;
        }

        /// <summary>
        /// Gets content type based on file extension
        /// </summary>
        /// <param name="filename">Filename</param>
        /// <returns>Content type</returns>
        private string GetContentType(string filename)
        {
            var extension = Path.GetExtension(filename).ToLowerInvariant();
            return extension switch
            {
                ".txt" => "text/plain",
                ".json" => "application/json",
                ".xml" => "application/xml",
                ".pdf" => "application/pdf",
                ".jpg" or ".jpeg" => "image/jpeg",
                ".png" => "image/png",
                ".gif" => "image/gif",
                ".zip" => "application/zip",
                ".exe" => "application/octet-stream",
                ".dll" => "application/octet-stream",
                _ => "application/octet-stream"
            };
        }

        /// <summary>
        /// Verifies user has access to a file
        /// </summary>
        /// <param name="userId">User identifier</param>
        /// <param name="fileKey">File key</param>
        /// <returns>True if user has access</returns>
        private async Task<bool> VerifyFileAccessAsync(string userId, string fileKey)
        {
            try
            {
                // Check if file key starts with user's path
                var userPath = $"{_basePath}/{userId}/";
                if (!fileKey.StartsWith(userPath))
                {
                    return false;
                }

                // Verify file exists and get metadata
                var request = new GetObjectMetadataRequest
                {
                    BucketName = _bucketName,
                    Key = fileKey
                };

                var response = await _s3Client.GetObjectMetadataAsync(request);
                
                // Verify user ID in metadata matches
                return response.Metadata.GetValueOrDefault("user-id") == userId;
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// File upload result
    /// </summary>
    public class FileUploadResult
    {
        public bool Success { get; set; }
        public string FileKey { get; set; }
        public string OriginalFilename { get; set; }
        public long FileSize { get; set; }
        public DateTime UploadTimestamp { get; set; }
        public Dictionary<string, string> Metadata { get; set; } = new Dictionary<string, string>();
        public string ErrorMessage { get; set; }
    }

    /// <summary>
    /// File download result
    /// </summary>
    public class FileDownloadResult
    {
        public bool Success { get; set; }
        public byte[] FileContent { get; set; }
        public string OriginalFilename { get; set; }
        public long FileSize { get; set; }
        public Dictionary<string, string> Metadata { get; set; } = new Dictionary<string, string>();
        public string ErrorMessage { get; set; }
    }

    /// <summary>
    /// File information
    /// </summary>
    public class FileInfo
    {
        public string FileKey { get; set; }
        public string OriginalFilename { get; set; }
        public long FileSize { get; set; }
        public DateTime LastModified { get; set; }
        public string ContentType { get; set; }
        public Dictionary<string, string> Metadata { get; set; } = new Dictionary<string, string>();
    }
}
