#include <string>
#include <vector>
#include <memory>
#include <map>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <queue>
#include <stdexcept>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iostream>
#include "../config/settings.hpp"
#include "../ai/model_layer.hpp"
#include "ai_core_hybrid.hpp"
#include "../agent/acp.hpp"

namespace IDE_AI {

// Task types for AI provider selection
enum class TaskType {
    Completion,
    Reasoning,
    CodeGeneration,
    CodeAnalysis,
    LanguageLearning,
    Optimization,
    Security,
    MultiModal,
    ToolUse,
    Reflection
};

// AI Provider interface
class IAIProvider {
public:
    virtual ~IAIProvider() = default;
    virtual std::string get_name() const = 0;
    virtual bool is_available() const = 0;
    virtual bool supports_task(TaskType task_type) const = 0;
    virtual void generate_completion_async(const std::string& prompt, std::function<void(const std::string&)> callback) = 0;
    virtual void get_inline_suggestion_async(const std::string& context, std::function<void(const std::string&)> callback) = 0;
    virtual void chat_async(const std::string& message, std::function<void(const std::string&)> callback) = 0;
    virtual void optimize_ir_async(const LanguageCore::ULR& ulr, std::function<void(const LanguageCore::ULR&)> callback) = 0;
    virtual float get_confidence_score() const = 0;
    virtual int get_latency_ms() const = 0;
    virtual bool requires_network() const = 0;
};

// Self-hosted local AI provider
class SelfHostedProvider : public IAIProvider {
public:
    SelfHostedProvider(CompletionModel* model) : model_(model) {}
    
    std::string get_name() const override { return "self_hosted"; }
    bool is_available() const override { return model_ != nullptr; }
    bool supports_task(TaskType task_type) const override { return true; } // Local model supports all tasks
    bool requires_network() const override { return false; }
    
    void generate_completion_async(const std::string& prompt, std::function<void(const std::string&)> callback) override {
        if (!is_available()) {
            callback("Error: Local model not available");
            return;
        }
        
        // Run in separate thread to avoid blocking
        std::thread([this, prompt, callback]() {
            try {
                std::string response = model_->generate_completion(prompt);
                callback(response);
            } catch (const std::exception& e) {
                callback("Error: " + std::string(e.what()));
            }
        }).detach();
    }
    
    void get_inline_suggestion_async(const std::string& context, std::function<void(const std::string&)> callback) override {
        std::string prompt = "Complete this code context: " + context;
        generate_completion_async(prompt, callback);
    }
    
    void chat_async(const std::string& message, std::function<void(const std::string&)> callback) override {
        std::string prompt = "User: " + message + "\nAssistant:";
        generate_completion_async(prompt, callback);
    }
    
    void optimize_ir_async(const LanguageCore::ULR& ulr, std::function<void(const LanguageCore::ULR&)> callback) override {
        std::string prompt = "Optimize this intermediate representation: " + ulr.to_string();
        generate_completion_async(prompt, [callback](const std::string& response) {
            // Parse response and create optimized ULR
            // This is a simplified implementation
            LanguageCore::ULR optimized_ulr;
            callback(optimized_ulr);
        });
    }
    
    float get_confidence_score() const override { return 0.9f; } // High confidence for local model
    int get_latency_ms() const override { return 50; } // Low latency for local model

private:
    CompletionModel* model_;
};

// External AI provider base class
class ExternalAIProvider : public IAIProvider {
public:
    ExternalAIProvider(const std::string& name, const std::string& api_key, const std::string& base_url)
        : name_(name), api_key_(api_key), base_url_(base_url), available_(false) {
        check_availability();
    }
    
    std::string get_name() const override { return name_; }
    bool is_available() const override { return available_; }
    bool requires_network() const override { return true; }
    
    void generate_completion_async(const std::string& prompt, std::function<void(const std::string&)> callback) override {
        if (!is_available()) {
            callback("Error: " + name_ + " provider not available");
            return;
        }
        
        // Run in separate thread
        std::thread([this, prompt, callback]() {
            try {
                std::string response = make_api_request(prompt);
                callback(response);
            } catch (const std::exception& e) {
                callback("Error: " + std::string(e.what()));
            }
        }).detach();
    }
    
    void get_inline_suggestion_async(const std::string& context, std::function<void(const std::string&)> callback) override {
        std::string prompt = "Complete this code: " + context;
        generate_completion_async(prompt, callback);
    }
    
    void chat_async(const std::string& message, std::function<void(const std::string&)> callback) override {
        generate_completion_async(message, callback);
    }
    
    void optimize_ir_async(const LanguageCore::ULR& ulr, std::function<void(const LanguageCore::ULR&)> callback) override {
        std::string prompt = "Optimize this code structure: " + ulr.to_string();
        generate_completion_async(prompt, [callback](const std::string& response) {
            LanguageCore::ULR optimized_ulr;
            callback(optimized_ulr);
        });
    }
    
    float get_confidence_score() const override { return 0.8f; } // Good confidence for external providers
    int get_latency_ms() const override { return 200; } // Higher latency for external providers

protected:
    virtual std::string make_api_request(const std::string& prompt) = 0;
    virtual void check_availability() = 0;
    
    std::string name_;
    std::string api_key_;
    std::string base_url_;
    std::atomic<bool> available_;
};

// OpenAI provider implementation
class OpenAIProvider : public ExternalAIProvider {
public:
    OpenAIProvider(const std::string& api_key) 
        : ExternalAIProvider("openai", api_key, "https://api.openai.com/v1") {}
    
    bool supports_task(TaskType task_type) const override {
        return task_type == TaskType::Completion || 
               task_type == TaskType::CodeGeneration || 
               task_type == TaskType::CodeAnalysis ||
               task_type == TaskType::Reasoning;
    }

protected:
    std::string make_api_request(const std::string& prompt) override {
        // Simplified HTTP request - in real implementation, use proper HTTP client
        return "OpenAI response for: " + prompt.substr(0, 50) + "...";
    }
    
    void check_availability() override {
        // Check if API key is valid and service is reachable
        available_ = !api_key_.empty();
    }
};

// GitHub Copilot provider implementation
class CopilotProvider : public ExternalAIProvider {
public:
    CopilotProvider(const std::string& api_key) 
        : ExternalAIProvider("copilot", api_key, "https://api.github.com/copilot") {}
    
    bool supports_task(TaskType task_type) const override {
        return task_type == TaskType::CodeGeneration || 
               task_type == TaskType::Completion;
    }

protected:
    std::string make_api_request(const std::string& prompt) override {
        return "Copilot suggestion for: " + prompt.substr(0, 50) + "...";
    }
    
    void check_availability() override {
        available_ = !api_key_.empty();
    }
};

// Kimi provider implementation
class KimiProvider : public ExternalAIProvider {
public:
    KimiProvider(const std::string& api_key) 
        : ExternalAIProvider("kimi", api_key, "https://api.moonshot.cn/v1") {}
    
    bool supports_task(TaskType task_type) const override {
        return task_type == TaskType::Completion || 
               task_type == TaskType::Reasoning ||
               task_type == TaskType::CodeAnalysis;
    }

protected:
    std::string make_api_request(const std::string& prompt) override {
        return "Kimi response for: " + prompt.substr(0, 50) + "...";
    }
    
    void check_availability() override {
        available_ = !api_key_.empty();
    }
};

// Hybrid AI Core - manages multiple AI providers
class AICoreHybrid {
public:
    static AICoreHybrid& get_instance() {
        static AICoreHybrid instance;
        return instance;
    }

    void initialize() {
        std::cout << "Initializing Hybrid AI Core...\n";
        
        // Load configuration
        load_configuration();
        
        // Initialize providers based on configuration
        initialize_providers();
        
        // Start monitoring thread
        monitoring_active_ = true;
        monitoring_thread_ = std::thread(&AICoreHybrid::monitoring_loop, this);
        
        std::cout << "Hybrid AI Core initialized with " << available_providers_.size() << " providers\n";
    }
    
    void shutdown() {
        monitoring_active_ = false;
        if (monitoring_thread_.joinable()) {
            monitoring_thread_.join();
        }
        available_providers_.clear();
    }
    
    void add_provider(std::unique_ptr<IAIProvider> provider) {
        std::lock_guard<std::mutex> lock(providers_mutex_);
        available_providers_.push_back(std::move(provider));
    }
    
    IAIProvider* get_provider_for_task(TaskType task_type) {
        std::lock_guard<std::mutex> lock(providers_mutex_);
        
        // First, try to find a local provider that supports the task
        for (auto& provider : available_providers_) {
            if (!provider->requires_network() && provider->supports_task(task_type) && provider->is_available()) {
                return provider.get();
            }
        }
        
        // If no local provider, try external providers
        for (auto& provider : available_providers_) {
            if (provider->requires_network() && provider->supports_task(task_type) && provider->is_available()) {
                return provider.get();
            }
        }
        
        // Fallback to any available provider
        for (auto& provider : available_providers_) {
            if (provider->is_available()) {
                return provider.get();
            }
        }
        
        return nullptr;
    }
    
    std::vector<IAIProvider*> get_all_providers() {
        std::lock_guard<std::mutex> lock(providers_mutex_);
        std::vector<IAIProvider*> providers;
        for (auto& provider : available_providers_) {
            providers.push_back(provider.get());
        }
        return providers;
    }
    
    void generate_completion_async(const std::string& prompt, TaskType task_type, std::function<void(const std::string&)> callback) {
        auto provider = get_provider_for_task(task_type);
        if (provider) {
            provider->generate_completion_async(prompt, callback);
        } else {
            callback("Error: No AI provider available for task");
        }
    }
    
    void get_inline_suggestion_async(const std::string& context, std::function<void(const std::string&)> callback) {
        auto provider = get_provider_for_task(TaskType::CodeGeneration);
        if (provider) {
            provider->get_inline_suggestion_async(context, callback);
        } else {
            callback("Error: No AI provider available for inline suggestions");
        }
    }
    
    void chat_async(const std::string& message, std::function<void(const std::string&)> callback) {
        auto provider = get_provider_for_task(TaskType::Completion);
        if (provider) {
            provider->chat_async(message, callback);
        } else {
            callback("Error: No AI provider available for chat");
        }
    }
    
    void optimize_ir_async(const LanguageCore::ULR& ulr, std::function<void(const LanguageCore::ULR&)> callback) {
        auto provider = get_provider_for_task(TaskType::Optimization);
        if (provider) {
            provider->optimize_ir_async(ulr, callback);
        } else {
            callback(ulr); // Return original ULR if no provider available
        }
    }
    
    // Get system statistics
    struct AIStats {
        int total_providers;
        int available_providers;
        int local_providers;
        int external_providers;
        float average_confidence;
        int average_latency_ms;
        std::map<std::string, int> provider_usage;
    };
    
    AIStats get_stats() {
        std::lock_guard<std::mutex> lock(providers_mutex_);
        AIStats stats;
        
        stats.total_providers = available_providers_.size();
        stats.available_providers = 0;
        stats.local_providers = 0;
        stats.external_providers = 0;
        
        float total_confidence = 0.0f;
        int total_latency = 0;
        
        for (auto& provider : available_providers_) {
            if (provider->is_available()) {
                stats.available_providers++;
                total_confidence += provider->get_confidence_score();
                total_latency += provider->get_latency_ms();
                
                if (provider->requires_network()) {
                    stats.external_providers++;
                } else {
                    stats.local_providers++;
                }
                
                stats.provider_usage[provider->get_name()]++;
            }
        }
        
        if (stats.available_providers > 0) {
            stats.average_confidence = total_confidence / stats.available_providers;
            stats.average_latency_ms = total_latency / stats.available_providers;
        }
        
        return stats;
    }

private:
    AICoreHybrid() = default;
    ~AICoreHybrid() { shutdown(); }
    
    void load_configuration() {
        // Load AI configuration from TOML file
        // This is a simplified implementation
        std::ifstream config_file("config/ai_config.toml");
        if (config_file.is_open()) {
            std::string line;
            while (std::getline(config_file, line)) {
                // Parse configuration - simplified
                if (line.find("providers =") != std::string::npos) {
                    // Extract provider list
                }
            }
            config_file.close();
        }
    }
    
    void initialize_providers() {
        // Initialize self-hosted provider
        if (Settings::get_bool("ai.self_hosted.enabled", true)) {
            // Create local model instance
            auto local_model = std::make_unique<CompletionModel>();
            auto self_hosted = std::make_unique<SelfHostedProvider>(local_model.get());
            available_providers_.push_back(std::move(self_hosted));
            local_model_ = std::move(local_model);
        }
        
        // Initialize external providers
        if (Settings::get_bool("ai.openai.enabled", false)) {
            std::string api_key = Settings::get_string("ai.openai.api_key", "");
            if (!api_key.empty()) {
                available_providers_.push_back(std::make_unique<OpenAIProvider>(api_key));
            }
        }
        
        if (Settings::get_bool("ai.copilot.enabled", false)) {
            std::string api_key = Settings::get_string("ai.copilot.api_key", "");
            if (!api_key.empty()) {
                available_providers_.push_back(std::make_unique<CopilotProvider>(api_key));
            }
        }
        
        if (Settings::get_bool("ai.kimi.enabled", false)) {
            std::string api_key = Settings::get_string("ai.kimi.api_key", "");
            if (!api_key.empty()) {
                available_providers_.push_back(std::make_unique<KimiProvider>(api_key));
            }
        }
    }
    
    void monitoring_loop() {
        while (monitoring_active_) {
            // Monitor provider health
            monitor_provider_health();
            
            // Update statistics
            update_statistics();
            
            // Clean up resources
            cleanup_resources();
            
            std::this_thread::sleep_for(std::chrono::seconds(30));
        }
    }
    
    void monitor_provider_health() {
        std::lock_guard<std::mutex> lock(providers_mutex_);
        for (auto& provider : available_providers_) {
            // Check if provider is still available
            if (!provider->is_available()) {
                std::cout << "Warning: Provider " << provider->get_name() << " is not available\n";
            }
        }
    }
    
    void update_statistics() {
        // Update usage statistics
        auto stats = get_stats();
        if (stats.available_providers == 0) {
            std::cout << "Warning: No AI providers are currently available\n";
        }
    }
    
    void cleanup_resources() {
        // Clean up any unused resources
        // This could include clearing caches, freeing memory, etc.
    }
    
    std::vector<std::unique_ptr<IAIProvider>> available_providers_;
    std::unique_ptr<CompletionModel> local_model_;
    std::mutex providers_mutex_;
    std::atomic<bool> monitoring_active_;
    std::thread monitoring_thread_;
};

} // namespace IDE_AI
