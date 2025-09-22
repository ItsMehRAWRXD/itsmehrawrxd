#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <queue>
#include <iostream>
#include <fstream>
#include <sstream>
#include "../agent/zac/bus.hpp"
#include "../language_core/ulr.hpp"
#include "../ai/ai_core_hybrid.hpp"
#include "../ai/reasoning/project_knowledge_graph.hpp"

namespace Extension {
namespace ANEP {

// Extension metadata
struct ExtensionMetadata {
    std::string name;
    std::string version;
    std::string author;
    std::string description;
    std::vector<std::string> capabilities;
    std::vector<std::string> dependencies;
    std::string license;
    std::string api_version;
    std::map<std::string, std::string> configuration;
    bool enabled;
    std::chrono::steady_clock::time_point installed_at;
    
    ExtensionMetadata() : enabled(false) {
        installed_at = std::chrono::steady_clock::now();
    }
};

// Extension capability types
enum class CapabilityType {
    CodeGeneration,
    CodeAnalysis,
    LanguageSupport,
    UIEnhancement,
    BuildTool,
    Debugger,
    Testing,
    Documentation,
    Security,
    Performance
};

// Extension capability
struct ExtensionCapability {
    CapabilityType type;
    std::string name;
    std::string description;
    std::vector<std::string> supported_languages;
    std::map<std::string, std::string> parameters;
    bool requires_network;
    bool requires_file_access;
    bool requires_process_creation;
    std::string api_endpoint;
};

// Protocol message for extension communication
struct ProtocolMessage {
    std::string id;
    std::string command;
    std::map<std::string, std::string> payload;
    std::string extension_id;
    std::string timestamp;
    bool requires_response;
    std::string response_id;
    
    ProtocolMessage() : requires_response(false) {
        timestamp = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    }
};

// Extension execution context
struct ExecutionContext {
    std::string extension_id;
    std::string sandbox_id;
    std::map<std::string, std::string> environment;
    std::vector<std::string> allowed_operations;
    std::vector<std::string> restricted_operations;
    std::string working_directory;
    size_t memory_limit;
    size_t cpu_time_limit;
    bool network_access;
    bool file_system_access;
    bool process_creation;
    
    ExecutionContext() : memory_limit(128 * 1024 * 1024), cpu_time_limit(30), 
                        network_access(false), file_system_access(false), process_creation(false) {}
};

// Core API for extensions
class CoreAPI {
public:
    CoreAPI(IDE_AI::AICoreHybrid* ai_core, ProjectKnowledgeGraph* pkg, Agents::ZAC::SecureBus* secure_bus)
        : ai_core_(ai_core), pkg_(pkg), secure_bus_(secure_bus) {}
    
    // File system operations
    void get_ulr_for_file(const std::string& path, std::function<void(const std::string&)> callback) {
        // Asynchronously serialize and send ULR data
        ACP::Message msg;
        msg.receiver = "language_agent";
        msg.command = "get_ulr";
        msg.payload["file"] = path;
        secure_bus_->send_message_async(msg, callback);
    }
    
    void read_file(const std::string& path, std::function<void(const std::string&)> callback) {
        // Read file content
        std::thread([this, path, callback]() {
            std::ifstream file(path);
            if (file.is_open()) {
                std::stringstream buffer;
                buffer << file.rdbuf();
                callback(buffer.str());
            } else {
                callback("");
            }
        }).detach();
    }
    
    void write_file(const std::string& path, const std::string& content, std::function<void(bool)> callback) {
        // Write file content
        std::thread([path, content, callback]() {
            std::ofstream file(path);
            if (file.is_open()) {
                file << content;
                file.close();
                callback(true);
            } else {
                callback(false);
            }
        }).detach();
    }
    
    void list_directory(const std::string& path, std::function<void(const std::vector<std::string>&)> callback) {
        // List directory contents
        std::thread([path, callback]() {
            std::vector<std::string> files;
            // Simplified directory listing
            callback(files);
        }).detach();
    }
    
    // AI operations
    void get_ai_completion(const std::string& prompt, std::function<void(const std::string&)> callback) {
        // Proxy an AI request through the core
        ai_core_->generate_completion_async(prompt, IDE_AI::TaskType::Completion, callback);
    }
    
    void get_ai_analysis(const std::string& code, std::function<void(const std::string&)> callback) {
        // Get AI code analysis
        ai_core_->generate_completion_async("Analyze this code: " + code, IDE_AI::TaskType::CodeAnalysis, callback);
    }
    
    void get_ai_suggestion(const std::string& context, std::function<void(const std::string&)> callback) {
        // Get AI code suggestion
        ai_core_->get_inline_suggestion_async(context, callback);
    }
    
    // Knowledge graph operations
    void query_knowledge_graph(const std::string& query, std::function<void(const std::string&)> callback) {
        // Query the project knowledge graph
        std::thread([this, query, callback]() {
            // Simplified knowledge graph query
            std::string result = "Knowledge graph query result for: " + query;
            callback(result);
        }).detach();
    }
    
    void add_to_knowledge_graph(const std::string& node_type, const std::map<std::string, std::string>& properties, 
                               std::function<void(bool)> callback) {
        // Add node to knowledge graph
        std::thread([this, node_type, properties, callback]() {
            // Add node to knowledge graph
            pkg_->add_node({node_type, "extension_node", properties});
            callback(true);
        }).detach();
    }
    
    // Compilation operations
    void compile_code(const std::string& source_code, const std::string& language, 
                     std::function<void(const std::string&)> callback) {
        // Compile code using the adaptive compiler
        ACP::Message msg;
        msg.receiver = "compiler_agent";
        msg.command = "compile_request";
        msg.payload["source_code"] = source_code;
        msg.payload["language_hint"] = language;
        secure_bus_->send_message_async(msg, [callback](const std::string& response) {
            callback(response);
        });
    }
    
    // UI operations
    void show_notification(const std::string& message, const std::string& type = "info") {
        // Show notification to user
        std::cout << "Extension Notification [" << type << "]: " << message << std::endl;
    }
    
    void show_dialog(const std::string& title, const std::string& message, 
                    const std::vector<std::string>& options, std::function<void(int)> callback) {
        // Show dialog to user
        std::cout << "Extension Dialog [" << title << "]: " << message << std::endl;
        // Simplified - always return first option
        callback(0);
    }
    
    void update_status_bar(const std::string& message) {
        // Update status bar
        std::cout << "Status: " << message << std::endl;
    }
    
    // Configuration operations
    void get_configuration(const std::string& key, std::function<void(const std::string&)> callback) {
        // Get extension configuration
        std::thread([key, callback]() {
            // Simplified configuration retrieval
            std::string value = "default_value_for_" + key;
            callback(value);
        }).detach();
    }
    
    void set_configuration(const std::string& key, const std::string& value, std::function<void(bool)> callback) {
        // Set extension configuration
        std::thread([key, value, callback]() {
            // Simplified configuration setting
            callback(true);
        }).detach();
    }
    
    // Logging operations
    void log_info(const std::string& message) {
        std::cout << "[INFO] Extension: " << message << std::endl;
    }
    
    void log_warning(const std::string& message) {
        std::cout << "[WARNING] Extension: " << message << std::endl;
    }
    
    void log_error(const std::string& message) {
        std::cerr << "[ERROR] Extension: " << message << std::endl;
    }

private:
    IDE_AI::AICoreHybrid* ai_core_;
    ProjectKnowledgeGraph* pkg_;
    Agents::ZAC::SecureBus* secure_bus_;
};

// Extension manager
class ExtensionManager {
public:
    ExtensionManager(IDE_AI::AICoreHybrid* ai_core, ProjectKnowledgeGraph* pkg, Agents::ZAC::SecureBus* secure_bus)
        : ai_core_(ai_core), pkg_(pkg), secure_bus_(secure_bus) {
        
        core_api_ = std::make_unique<CoreAPI>(ai_core, pkg, secure_bus);
        
        // Start extension monitoring thread
        monitoring_active_ = true;
        monitoring_thread_ = std::thread(&ExtensionManager::monitoring_loop, this);
        
        std::cout << "ANEP Extension Manager initialized\n";
    }
    
    ~ExtensionManager() {
        monitoring_active_ = false;
        if (monitoring_thread_.joinable()) {
            monitoring_thread_.join();
        }
    }
    
    // Load extension
    bool load_extension(const std::string& extension_path) {
        std::cout << "Loading extension: " << extension_path << "\n";
        
        // Read extension metadata
        ExtensionMetadata metadata = read_extension_metadata(extension_path);
        if (metadata.name.empty()) {
            std::cerr << "Failed to read extension metadata\n";
            return false;
        }
        
        // Validate extension
        if (!validate_extension(metadata)) {
            std::cerr << "Extension validation failed\n";
            return false;
        }
        
        // Create execution context
        ExecutionContext context = create_execution_context(metadata);
        
        // Load extension capabilities
        std::vector<ExtensionCapability> capabilities = load_extension_capabilities(extension_path);
        
        // Register extension
        register_extension(metadata, context, capabilities);
        
        std::cout << "Extension loaded successfully: " << metadata.name << "\n";
        return true;
    }
    
    // Unload extension
    void unload_extension(const std::string& extension_id) {
        std::lock_guard<std::mutex> lock(extensions_mutex_);
        
        auto it = loaded_extensions_.find(extension_id);
        if (it != loaded_extensions_.end()) {
            // Cleanup extension resources
            cleanup_extension_resources(extension_id);
            
            // Remove from registry
            loaded_extensions_.erase(it);
            
            std::cout << "Extension unloaded: " << extension_id << "\n";
        }
    }
    
    // Execute extension command
    void execute_extension_command(const std::string& extension_id, const std::string& command, 
                                  const std::map<std::string, std::string>& parameters,
                                  std::function<void(const std::string&)> callback) {
        std::lock_guard<std::mutex> lock(extensions_mutex_);
        
        auto it = loaded_extensions_.find(extension_id);
        if (it != loaded_extensions_.end()) {
            // Create protocol message
            ProtocolMessage msg;
            msg.id = generate_message_id();
            msg.command = command;
            msg.payload = parameters;
            msg.extension_id = extension_id;
            msg.requires_response = true;
            
            // Execute command in extension context
            execute_in_extension_context(it->second, msg, callback);
        } else {
            callback("Error: Extension not found");
        }
    }
    
    // Get extension list
    std::vector<ExtensionMetadata> get_loaded_extensions() {
        std::lock_guard<std::mutex> lock(extensions_mutex_);
        
        std::vector<ExtensionMetadata> extensions;
        for (const auto& [id, extension] : loaded_extensions_) {
            extensions.push_back(extension.metadata);
        }
        return extensions;
    }
    
    // Get extension capabilities
    std::vector<ExtensionCapability> get_extension_capabilities(const std::string& extension_id) {
        std::lock_guard<std::mutex> lock(extensions_mutex_);
        
        auto it = loaded_extensions_.find(extension_id);
        if (it != loaded_extensions_.end()) {
            return it->second.capabilities;
        }
        return {};
    }

private:
    struct LoadedExtension {
        ExtensionMetadata metadata;
        ExecutionContext context;
        std::vector<ExtensionCapability> capabilities;
        std::chrono::steady_clock::time_point loaded_at;
        bool active;
        
        LoadedExtension() : active(false) {
            loaded_at = std::chrono::steady_clock::now();
        }
    };
    
    void monitoring_loop() {
        while (monitoring_active_) {
            // Monitor extension health
            monitor_extension_health();
            
            // Clean up inactive extensions
            cleanup_inactive_extensions();
            
            // Update extension statistics
            update_extension_statistics();
            
            std::this_thread::sleep_for(std::chrono::seconds(30));
        }
    }
    
    ExtensionMetadata read_extension_metadata(const std::string& extension_path) {
        ExtensionMetadata metadata;
        
        // Read extension manifest file
        std::ifstream manifest_file(extension_path + "/manifest.json");
        if (manifest_file.is_open()) {
            std::stringstream buffer;
            buffer << manifest_file.rdbuf();
            std::string manifest_content = buffer.str();
            
            // Parse JSON manifest (simplified)
            metadata.name = extract_json_value(manifest_content, "name");
            metadata.version = extract_json_value(manifest_content, "version");
            metadata.author = extract_json_value(manifest_content, "author");
            metadata.description = extract_json_value(manifest_content, "description");
            metadata.api_version = extract_json_value(manifest_content, "api_version");
            
            manifest_file.close();
        }
        
        return metadata;
    }
    
    std::string extract_json_value(const std::string& json, const std::string& key) {
        std::string search_key = "\"" + key + "\"";
        size_t pos = json.find(search_key);
        if (pos != std::string::npos) {
            pos = json.find(":", pos);
            if (pos != std::string::npos) {
                pos = json.find("\"", pos);
                if (pos != std::string::npos) {
                    size_t start = pos + 1;
                    size_t end = json.find("\"", start);
                    if (end != std::string::npos) {
                        return json.substr(start, end - start);
                    }
                }
            }
        }
        return "";
    }
    
    bool validate_extension(const ExtensionMetadata& metadata) {
        // Validate extension metadata
        if (metadata.name.empty() || metadata.version.empty()) {
            return false;
        }
        
        // Check API version compatibility
        if (metadata.api_version != "1.0") {
            return false;
        }
        
        // Additional validation checks
        return true;
    }
    
    ExecutionContext create_execution_context(const ExtensionMetadata& metadata) {
        ExecutionContext context;
        context.extension_id = metadata.name;
        context.sandbox_id = "sandbox_" + metadata.name;
        
        // Set up execution environment
        context.environment["EXTENSION_NAME"] = metadata.name;
        context.environment["EXTENSION_VERSION"] = metadata.version;
        context.environment["API_VERSION"] = metadata.api_version;
        
        // Set up operation permissions
        context.allowed_operations = {"read_file", "write_file", "ai_completion", "knowledge_query"};
        context.restricted_operations = {"system_command", "network_access", "process_creation"};
        
        // Set resource limits
        context.memory_limit = 64 * 1024 * 1024; // 64MB
        context.cpu_time_limit = 10; // 10 seconds
        
        return context;
    }
    
    std::vector<ExtensionCapability> load_extension_capabilities(const std::string& extension_path) {
        std::vector<ExtensionCapability> capabilities;
        
        // Load capabilities from extension definition
        // This is a simplified implementation
        ExtensionCapability capability;
        capability.type = CapabilityType::CodeGeneration;
        capability.name = "code_generator";
        capability.description = "Generate code based on user input";
        capability.supported_languages = {"C++", "Python", "JavaScript"};
        capability.requires_network = false;
        capability.requires_file_access = true;
        capability.requires_process_creation = false;
        capabilities.push_back(capability);
        
        return capabilities;
    }
    
    void register_extension(const ExtensionMetadata& metadata, const ExecutionContext& context, 
                           const std::vector<ExtensionCapability>& capabilities) {
        std::lock_guard<std::mutex> lock(extensions_mutex_);
        
        LoadedExtension extension;
        extension.metadata = metadata;
        extension.context = context;
        extension.capabilities = capabilities;
        extension.active = true;
        
        loaded_extensions_[metadata.name] = extension;
    }
    
    void execute_in_extension_context(const LoadedExtension& extension, const ProtocolMessage& msg,
                                     std::function<void(const std::string&)> callback) {
        // Execute command in extension's sandboxed context
        std::thread([this, extension, msg, callback]() {
            try {
                // Simulate extension execution
                std::string result = "Extension " + extension.metadata.name + " executed command: " + msg.command;
                callback(result);
            } catch (const std::exception& e) {
                callback("Error: " + std::string(e.what()));
            }
        }).detach();
    }
    
    void cleanup_extension_resources(const std::string& extension_id) {
        // Clean up extension resources
        std::cout << "Cleaning up resources for extension: " << extension_id << "\n";
    }
    
    void monitor_extension_health() {
        std::lock_guard<std::mutex> lock(extensions_mutex_);
        
        for (auto& [id, extension] : loaded_extensions_) {
            // Check if extension is still responsive
            auto now = std::chrono::steady_clock::now();
            if (now - extension.loaded_at > std::chrono::hours(24)) {
                std::cout << "Warning: Extension " << id << " has been running for over 24 hours\n";
            }
        }
    }
    
    void cleanup_inactive_extensions() {
        std::lock_guard<std::mutex> lock(extensions_mutex_);
        
        auto it = loaded_extensions_.begin();
        while (it != loaded_extensions_.end()) {
            if (!it->second.active) {
                std::cout << "Removing inactive extension: " << it->first << "\n";
                it = loaded_extensions_.erase(it);
            } else {
                ++it;
            }
        }
    }
    
    void update_extension_statistics() {
        std::lock_guard<std::mutex> lock(extensions_mutex_);
        
        std::cout << "Active extensions: " << loaded_extensions_.size() << "\n";
    }
    
    std::string generate_message_id() {
        static std::atomic<int> counter(0);
        return "msg_" + std::to_string(counter.fetch_add(1));
    }
    
    // Member variables
    IDE_AI::AICoreHybrid* ai_core_;
    ProjectKnowledgeGraph* pkg_;
    Agents::ZAC::SecureBus* secure_bus_;
    std::unique_ptr<CoreAPI> core_api_;
    
    std::map<std::string, LoadedExtension> loaded_extensions_;
    std::mutex extensions_mutex_;
    
    std::atomic<bool> monitoring_active_;
    std::thread monitoring_thread_;
};

} // namespace ANEP
} // namespace Extension
