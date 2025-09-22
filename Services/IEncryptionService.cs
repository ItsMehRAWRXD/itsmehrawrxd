using RawrZSecurityPlatform.Models;

namespace RawrZSecurityPlatform.Services
{
    public interface IEncryptionService
    {
        Task<EncryptionResponse> EncryptFileAsync(IFormFile file, EncryptionRequest request);
        Task<DecryptionResponse> DecryptFileAsync(IFormFile file, DecryptionRequest request);
        Task<HashResponse> HashFileAsync(IFormFile file, HashRequest request);
        Task<FileAnalysisResponse> AnalyzeFileAsync(IFormFile file, FileAnalysisRequest request);
        Task<FileAnalysisResponse> ScanForMalwareAsync(IFormFile file);
        Task<FileAnalysisResponse> EntropyAnalysisAsync(IFormFile file);
        Task<FileAnalysisResponse> IntegrityCheckAsync(IFormFile file);
        Task<KeyGenerationResponse> GenerateKeysAsync(KeyGenerationRequest request);
        Task<KeyExportResponse> ExportKeysAsync();
        Task<KeyImportResponse> ImportKeysAsync(IFormFile file);
    }
}
