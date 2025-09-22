using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace AIDesktopHelper.Api.Services
{
    /// <summary>
    /// Service for integrating with external AI providers
    /// Supports multiple AI services with unified interface
    /// </summary>
    public class ExternalAIService
    {
        private readonly HttpClient _httpClient;
        private readonly IConfiguration _configuration;
        private readonly ILogger<ExternalAIService> _logger;
        private readonly Dictionary<string, AIProvider> _providers;

        public ExternalAIService(HttpClient httpClient, IConfiguration configuration, ILogger<ExternalAIService> logger)
        {
            _httpClient = httpClient;
            _configuration = configuration;
            _logger = logger;
            _providers = InitializeProviders();
        }

        /// <summary>
        /// Gets completion from specified AI provider
        /// </summary>
        /// <param name="provider">AI provider name</param>
        /// <param name="prompt">User prompt</param>
        /// <param name="options">Generation options</param>
        /// <returns>AI response</returns>
        public async Task<AIResponse> GetCompletionAsync(string provider, string prompt, AIOptions options = null)
        {
            if (!_providers.ContainsKey(provider))
            {
                throw new ArgumentException($"Provider '{provider}' not supported");
            }

            var aiProvider = _providers[provider];
            var requestOptions = options ?? new AIOptions();

            try
            {
                _logger.LogInformation($"Getting completion from {provider} for prompt: {prompt.Substring(0, Math.Min(100, prompt.Length))}...");

                var response = await aiProvider.GetCompletionAsync(prompt, requestOptions);
                
                _logger.LogInformation($"Successfully got completion from {provider}");
                return response;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error getting completion from {provider}");
                throw;
            }
        }

        /// <summary>
        /// Gets streaming completion from specified AI provider
        /// </summary>
        /// <param name="provider">AI provider name</param>
        /// <param name="prompt">User prompt</param>
        /// <param name="options">Generation options</param>
        /// <returns>Streaming AI response</returns>
        public async IAsyncEnumerable<string> GetStreamingCompletionAsync(string provider, string prompt, AIOptions options = null)
        {
            if (!_providers.ContainsKey(provider))
            {
                throw new ArgumentException($"Provider '{provider}' not supported");
            }

            var aiProvider = _providers[provider];
            var requestOptions = options ?? new AIOptions();

            await foreach (var chunk in aiProvider.GetStreamingCompletionAsync(prompt, requestOptions))
            {
                yield return chunk;
            }
        }

        /// <summary>
        /// Gets list of available AI providers
        /// </summary>
        /// <returns>List of provider names</returns>
        public IEnumerable<string> GetAvailableProviders()
        {
            return _providers.Keys;
        }

        /// <summary>
        /// Gets provider information
        /// </summary>
        /// <param name="provider">Provider name</param>
        /// <returns>Provider information</returns>
        public ProviderInfo GetProviderInfo(string provider)
        {
            if (!_providers.ContainsKey(provider))
            {
                throw new ArgumentException($"Provider '{provider}' not supported");
            }

            return _providers[provider].GetInfo();
        }

        private Dictionary<string, AIProvider> InitializeProviders()
        {
            var providers = new Dictionary<string, AIProvider>();

            // OpenAI Provider
            var openaiApiKey = _configuration["AIProviders:OpenAI:ApiKey"];
            if (!string.IsNullOrEmpty(openaiApiKey))
            {
                providers["openai"] = new OpenAIProvider(_httpClient, openaiApiKey, _logger);
            }

            // Anthropic (Claude) Provider
            var anthropicApiKey = _configuration["AIProviders:Anthropic:ApiKey"];
            if (!string.IsNullOrEmpty(anthropicApiKey))
            {
                providers["anthropic"] = new AnthropicProvider(_httpClient, anthropicApiKey, _logger);
            }

            // Google Gemini Provider
            var geminiApiKey = _configuration["AIProviders:Gemini:ApiKey"];
            if (!string.IsNullOrEmpty(geminiApiKey))
            {
                providers["gemini"] = new GeminiProvider(_httpClient, geminiApiKey, _logger);
            }

            // DeepSeek Provider
            var deepseekApiKey = _configuration["AIProviders:DeepSeek:ApiKey"];
            if (!string.IsNullOrEmpty(deepseekApiKey))
            {
                providers["deepseek"] = new DeepSeekProvider(_httpClient, deepseekApiKey, _logger);
            }

            // Ollama Provider (Local)
            var ollamaUrl = _configuration["AIProviders:Ollama:Url"];
            if (!string.IsNullOrEmpty(ollamaUrl))
            {
                providers["ollama"] = new OllamaProvider(_httpClient, ollamaUrl, _logger);
            }

            return providers;
        }
    }

    /// <summary>
    /// AI response data
    /// </summary>
    public class AIResponse
    {
        public string Content { get; set; }
        public string Provider { get; set; }
        public string Model { get; set; }
        public int TokensUsed { get; set; }
        public TimeSpan ProcessingTime { get; set; }
        public Dictionary<string, object> Metadata { get; set; } = new Dictionary<string, object>();
    }

    /// <summary>
    /// AI generation options
    /// </summary>
    public class AIOptions
    {
        public string Model { get; set; } = "gpt-4";
        public int MaxTokens { get; set; } = 1000;
        public double Temperature { get; set; } = 0.7;
        public double TopP { get; set; } = 1.0;
        public int TopK { get; set; } = 40;
        public List<string> StopSequences { get; set; } = new List<string>();
        public bool Stream { get; set; } = false;
        public Dictionary<string, object> CustomParameters { get; set; } = new Dictionary<string, object>();
    }

    /// <summary>
    /// Provider information
    /// </summary>
    public class ProviderInfo
    {
        public string Name { get; set; }
        public string Description { get; set; }
        public List<string> SupportedModels { get; set; } = new List<string>();
        public bool SupportsStreaming { get; set; }
        public bool SupportsFunctionCalling { get; set; }
        public int MaxTokens { get; set; }
        public string Website { get; set; }
    }

    /// <summary>
    /// Base AI provider interface
    /// </summary>
    public abstract class AIProvider
    {
        protected readonly HttpClient _httpClient;
        protected readonly ILogger _logger;

        protected AIProvider(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        public abstract Task<AIResponse> GetCompletionAsync(string prompt, AIOptions options);
        public abstract IAsyncEnumerable<string> GetStreamingCompletionAsync(string prompt, AIOptions options);
        public abstract ProviderInfo GetInfo();
    }

    /// <summary>
    /// OpenAI provider implementation
    /// </summary>
    public class OpenAIProvider : AIProvider
    {
        private readonly string _apiKey;

        public OpenAIProvider(HttpClient httpClient, string apiKey, ILogger logger) : base(httpClient, logger)
        {
            _apiKey = apiKey;
        }

        public override async Task<AIResponse> GetCompletionAsync(string prompt, AIOptions options)
        {
            var requestBody = new
            {
                model = options.Model,
                messages = new[]
                {
                    new { role = "user", content = prompt }
                },
                max_tokens = options.MaxTokens,
                temperature = options.Temperature,
                top_p = options.TopP,
                stream = false
            };

            var json = JsonSerializer.Serialize(requestBody);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {_apiKey}");

            var startTime = DateTime.UtcNow;
            var response = await _httpClient.PostAsync("https://api.openai.com/v1/chat/completions", content);
            var processingTime = DateTime.UtcNow - startTime;

            var responseContent = await response.Content.ReadAsStringAsync();
            var responseObj = JsonSerializer.Deserialize<JsonElement>(responseContent);

            if (response.IsSuccessStatusCode)
            {
                var choice = responseObj.GetProperty("choices")[0];
                var message = choice.GetProperty("message");
                var contentText = message.GetProperty("content").GetString();

                var usage = responseObj.GetProperty("usage");
                var tokensUsed = usage.GetProperty("total_tokens").GetInt32();

                return new AIResponse
                {
                    Content = contentText,
                    Provider = "OpenAI",
                    Model = options.Model,
                    TokensUsed = tokensUsed,
                    ProcessingTime = processingTime
                };
            }

            throw new Exception($"OpenAI API error: {response.StatusCode} - {responseContent}");
        }

        public override async IAsyncEnumerable<string> GetStreamingCompletionAsync(string prompt, AIOptions options)
        {
            var requestBody = new
            {
                model = options.Model,
                messages = new[]
                {
                    new { role = "user", content = prompt }
                },
                max_tokens = options.MaxTokens,
                temperature = options.Temperature,
                stream = true
            };

            var json = JsonSerializer.Serialize(requestBody);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {_apiKey}");

            var response = await _httpClient.PostAsync("https://api.openai.com/v1/chat/completions", content);
            var stream = await response.Content.ReadAsStreamAsync();

            using var reader = new System.IO.StreamReader(stream);
            string line;
            while ((line = await reader.ReadLineAsync()) != null)
            {
                if (line.StartsWith("data: "))
                {
                    var data = line.Substring(6);
                    if (data == "[DONE]") break;

                    try
                    {
                        var jsonElement = JsonSerializer.Deserialize<JsonElement>(data);
                        if (jsonElement.TryGetProperty("choices", out var choices) && choices.GetArrayLength() > 0)
                        {
                            var choice = choices[0];
                            if (choice.TryGetProperty("delta", out var delta) && 
                                delta.TryGetProperty("content", out var contentProp))
                            {
                                var chunk = contentProp.GetString();
                                if (!string.IsNullOrEmpty(chunk))
                                {
                                    yield return chunk;
                                }
                            }
                        }
                    }
                    catch (JsonException)
                    {
                        // Skip invalid JSON lines
                    }
                }
            }
        }

        public override ProviderInfo GetInfo()
        {
            return new ProviderInfo
            {
                Name = "OpenAI",
                Description = "OpenAI's GPT models including GPT-4, GPT-3.5, and more",
                SupportedModels = new List<string> { "gpt-4", "gpt-4-turbo", "gpt-3.5-turbo", "gpt-3.5-turbo-16k" },
                SupportsStreaming = true,
                SupportsFunctionCalling = true,
                MaxTokens = 128000,
                Website = "https://openai.com"
            };
        }
    }

    /// <summary>
    /// Anthropic (Claude) provider implementation
    /// </summary>
    public class AnthropicProvider : AIProvider
    {
        private readonly string _apiKey;

        public AnthropicProvider(HttpClient httpClient, string apiKey, ILogger logger) : base(httpClient, logger)
        {
            _apiKey = apiKey;
        }

        public override async Task<AIResponse> GetCompletionAsync(string prompt, AIOptions options)
        {
            var requestBody = new
            {
                model = options.Model,
                max_tokens = options.MaxTokens,
                temperature = options.Temperature,
                messages = new[]
                {
                    new { role = "user", content = prompt }
                }
            };

            var json = JsonSerializer.Serialize(requestBody);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("x-api-key", _apiKey);
            _httpClient.DefaultRequestHeaders.Add("anthropic-version", "2023-06-01");

            var startTime = DateTime.UtcNow;
            var response = await _httpClient.PostAsync("https://api.anthropic.com/v1/messages", content);
            var processingTime = DateTime.UtcNow - startTime;

            var responseContent = await response.Content.ReadAsStringAsync();
            var responseObj = JsonSerializer.Deserialize<JsonElement>(responseContent);

            if (response.IsSuccessStatusCode)
            {
                var contentText = responseObj.GetProperty("content")[0].GetProperty("text").GetString();
                var usage = responseObj.GetProperty("usage");
                var tokensUsed = usage.GetProperty("input_tokens").GetInt32() + usage.GetProperty("output_tokens").GetInt32();

                return new AIResponse
                {
                    Content = contentText,
                    Provider = "Anthropic",
                    Model = options.Model,
                    TokensUsed = tokensUsed,
                    ProcessingTime = processingTime
                };
            }

            throw new Exception($"Anthropic API error: {response.StatusCode} - {responseContent}");
        }

        public override async IAsyncEnumerable<string> GetStreamingCompletionAsync(string prompt, AIOptions options)
        {
            // Anthropic streaming implementation would go here
            var response = await GetCompletionAsync(prompt, options);
            yield return response.Content;
        }

        public override ProviderInfo GetInfo()
        {
            return new ProviderInfo
            {
                Name = "Anthropic",
                Description = "Anthropic's Claude models for advanced reasoning and analysis",
                SupportedModels = new List<string> { "claude-3-opus-20240229", "claude-3-sonnet-20240229", "claude-3-haiku-20240307" },
                SupportsStreaming = true,
                SupportsFunctionCalling = false,
                MaxTokens = 200000,
                Website = "https://anthropic.com"
            };
        }
    }

    /// <summary>
    /// Google Gemini provider implementation
    /// </summary>
    public class GeminiProvider : AIProvider
    {
        private readonly string _apiKey;

        public GeminiProvider(HttpClient httpClient, string apiKey, ILogger logger) : base(httpClient, logger)
        {
            _apiKey = apiKey;
        }

        public override async Task<AIResponse> GetCompletionAsync(string prompt, AIOptions options)
        {
            var requestBody = new
            {
                contents = new[]
                {
                    new
                    {
                        parts = new[]
                        {
                            new { text = prompt }
                        }
                    }
                },
                generationConfig = new
                {
                    maxOutputTokens = options.MaxTokens,
                    temperature = options.Temperature,
                    topP = options.TopP,
                    topK = options.TopK
                }
            };

            var json = JsonSerializer.Serialize(requestBody);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var startTime = DateTime.UtcNow;
            var response = await _httpClient.PostAsync($"https://generativelanguage.googleapis.com/v1beta/models/{options.Model}:generateContent?key={_apiKey}", content);
            var processingTime = DateTime.UtcNow - startTime;

            var responseContent = await response.Content.ReadAsStringAsync();
            var responseObj = JsonSerializer.Deserialize<JsonElement>(responseContent);

            if (response.IsSuccessStatusCode)
            {
                var contentText = responseObj.GetProperty("candidates")[0].GetProperty("content").GetProperty("parts")[0].GetProperty("text").GetString();

                return new AIResponse
                {
                    Content = contentText,
                    Provider = "Google",
                    Model = options.Model,
                    TokensUsed = 0, // Gemini doesn't provide token count in response
                    ProcessingTime = processingTime
                };
            }

            throw new Exception($"Gemini API error: {response.StatusCode} - {responseContent}");
        }

        public override async IAsyncEnumerable<string> GetStreamingCompletionAsync(string prompt, AIOptions options)
        {
            var response = await GetCompletionAsync(prompt, options);
            yield return response.Content;
        }

        public override ProviderInfo GetInfo()
        {
            return new ProviderInfo
            {
                Name = "Google Gemini",
                Description = "Google's Gemini models for multimodal AI capabilities",
                SupportedModels = new List<string> { "gemini-pro", "gemini-pro-vision", "gemini-1.5-pro" },
                SupportsStreaming = false,
                SupportsFunctionCalling = true,
                MaxTokens = 1000000,
                Website = "https://ai.google.dev"
            };
        }
    }

    /// <summary>
    /// DeepSeek provider implementation
    /// </summary>
    public class DeepSeekProvider : AIProvider
    {
        private readonly string _apiKey;

        public DeepSeekProvider(HttpClient httpClient, string apiKey, ILogger logger) : base(httpClient, logger)
        {
            _apiKey = apiKey;
        }

        public override async Task<AIResponse> GetCompletionAsync(string prompt, AIOptions options)
        {
            var requestBody = new
            {
                model = options.Model,
                messages = new[]
                {
                    new { role = "user", content = prompt }
                },
                max_tokens = options.MaxTokens,
                temperature = options.Temperature,
                stream = false
            };

            var json = JsonSerializer.Serialize(requestBody);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            _httpClient.DefaultRequestHeaders.Clear();
            _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {_apiKey}");

            var startTime = DateTime.UtcNow;
            var response = await _httpClient.PostAsync("https://api.deepseek.com/v1/chat/completions", content);
            var processingTime = DateTime.UtcNow - startTime;

            var responseContent = await response.Content.ReadAsStringAsync();
            var responseObj = JsonSerializer.Deserialize<JsonElement>(responseContent);

            if (response.IsSuccessStatusCode)
            {
                var choice = responseObj.GetProperty("choices")[0];
                var message = choice.GetProperty("message");
                var contentText = message.GetProperty("content").GetString();

                var usage = responseObj.GetProperty("usage");
                var tokensUsed = usage.GetProperty("total_tokens").GetInt32();

                return new AIResponse
                {
                    Content = contentText,
                    Provider = "DeepSeek",
                    Model = options.Model,
                    TokensUsed = tokensUsed,
                    ProcessingTime = processingTime
                };
            }

            throw new Exception($"DeepSeek API error: {response.StatusCode} - {responseContent}");
        }

        public override async IAsyncEnumerable<string> GetStreamingCompletionAsync(string prompt, AIOptions options)
        {
            var response = await GetCompletionAsync(prompt, options);
            yield return response.Content;
        }

        public override ProviderInfo GetInfo()
        {
            return new ProviderInfo
            {
                Name = "DeepSeek",
                Description = "DeepSeek's advanced reasoning models for code generation and analysis",
                SupportedModels = new List<string> { "deepseek-chat", "deepseek-coder" },
                SupportsStreaming = true,
                SupportsFunctionCalling = false,
                MaxTokens = 32000,
                Website = "https://deepseek.com"
            };
        }
    }

    /// <summary>
    /// Ollama provider implementation (Local)
    /// </summary>
    public class OllamaProvider : AIProvider
    {
        private readonly string _baseUrl;

        public OllamaProvider(HttpClient httpClient, string baseUrl, ILogger logger) : base(httpClient, logger)
        {
            _baseUrl = baseUrl.TrimEnd('/');
        }

        public override async Task<AIResponse> GetCompletionAsync(string prompt, AIOptions options)
        {
            var requestBody = new
            {
                model = options.Model,
                prompt = prompt,
                stream = false,
                options = new
                {
                    temperature = options.Temperature,
                    top_p = options.TopP,
                    top_k = options.TopK,
                    num_predict = options.MaxTokens
                }
            };

            var json = JsonSerializer.Serialize(requestBody);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var startTime = DateTime.UtcNow;
            var response = await _httpClient.PostAsync($"{_baseUrl}/api/generate", content);
            var processingTime = DateTime.UtcNow - startTime;

            var responseContent = await response.Content.ReadAsStringAsync();
            var responseObj = JsonSerializer.Deserialize<JsonElement>(responseContent);

            if (response.IsSuccessStatusCode)
            {
                var contentText = responseObj.GetProperty("response").GetString();

                return new AIResponse
                {
                    Content = contentText,
                    Provider = "Ollama",
                    Model = options.Model,
                    TokensUsed = 0, // Ollama doesn't provide token count
                    ProcessingTime = processingTime
                };
            }

            throw new Exception($"Ollama API error: {response.StatusCode} - {responseContent}");
        }

        public override async IAsyncEnumerable<string> GetStreamingCompletionAsync(string prompt, AIOptions options)
        {
            var requestBody = new
            {
                model = options.Model,
                prompt = prompt,
                stream = true,
                options = new
                {
                    temperature = options.Temperature,
                    top_p = options.TopP,
                    top_k = options.TopK,
                    num_predict = options.MaxTokens
                }
            };

            var json = JsonSerializer.Serialize(requestBody);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync($"{_baseUrl}/api/generate", content);
            var stream = await response.Content.ReadAsStreamAsync();

            using var reader = new System.IO.StreamReader(stream);
            string line;
            while ((line = await reader.ReadLineAsync()) != null)
            {
                try
                {
                    var jsonElement = JsonSerializer.Deserialize<JsonElement>(line);
                    if (jsonElement.TryGetProperty("response", out var responseProp))
                    {
                        var chunk = responseProp.GetString();
                        if (!string.IsNullOrEmpty(chunk))
                        {
                            yield return chunk;
                        }
                    }
                }
                catch (JsonException)
                {
                    // Skip invalid JSON lines
                }
            }
        }

        public override ProviderInfo GetInfo()
        {
            return new ProviderInfo
            {
                Name = "Ollama",
                Description = "Local AI models running on your machine",
                SupportedModels = new List<string> { "llama3", "codellama", "mistral", "phi3" },
                SupportsStreaming = true,
                SupportsFunctionCalling = false,
                MaxTokens = 32000,
                Website = "https://ollama.ai"
            };
        }
    }
}
