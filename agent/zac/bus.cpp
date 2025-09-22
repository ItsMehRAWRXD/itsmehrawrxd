#include <string>
#include <map>
#include <vector>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <atomic>
#include <chrono>
#include <stdexcept>
#include <iostream>
#include <fstream>
#include <sstream>
#include <random>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include "../../agent/acp.hpp"

namespace Agents {
namespace ZAC {

// Message types for secure communication
enum class MessageType {
    Heartbeat,
    Command,
    Response,
    Data,
    Error,
    Authentication,
    Authorization,
    Encryption,
    Decryption
};

// Security levels
enum class SecurityLevel {
    Public,      // No encryption, basic authentication
    Protected,   // Encrypted, authenticated
    Confidential, // Encrypted, authenticated, integrity checked
    Secret       // Encrypted, authenticated, integrity checked, access controlled
};

// Secure message wrapper
struct SecureMessage {
    std::string id;
    MessageType type;
    SecurityLevel security_level;
    std::string sender_id;
    std::string receiver_id;
    std::string command;
    std::map<std::string, std::string> payload;
    std::string signature;
    std::string timestamp;
    std::string nonce;
    bool encrypted;
    
    SecureMessage() : type(MessageType::Command), security_level(SecurityLevel::Protected), encrypted(false) {
        timestamp = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    }
};

// Agent authentication information
struct AgentAuth {
    std::string agent_id;
    std::string public_key;
    std::string certificate;
    std::vector<std::string> permissions;
    std::chrono::steady_clock::time_point last_heartbeat;
    bool authenticated;
    bool authorized;
    
    AgentAuth() : authenticated(false), authorized(false) {}
};

// Cryptographic utilities
class CryptoUtils {
public:
    static std::string generate_key() {
        std::string key(32, 0);
        RAND_bytes(reinterpret_cast<unsigned char*>(key.data()), 32);
        return key;
    }
    
    static std::string generate_nonce() {
        std::string nonce(16, 0);
        RAND_bytes(reinterpret_cast<unsigned char*>(nonce.data()), 16);
        return nonce;
    }
    
    static std::string encrypt(const std::string& plaintext, const std::string& key) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return "";
        
        const EVP_CIPHER* cipher = EVP_aes_256_gcm();
        std::string iv = generate_nonce();
        
        if (EVP_EncryptInit_ex(ctx, cipher, nullptr, 
                              reinterpret_cast<const unsigned char*>(key.data()),
                              reinterpret_cast<const unsigned char*>(iv.data())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        
        std::string ciphertext;
        ciphertext.resize(plaintext.length() + EVP_CIPHER_block_size(cipher));
        
        int len;
        if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()), &len,
                             reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.length()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        
        int ciphertext_len = len;
        if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()) + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        ciphertext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        
        // Prepend IV to ciphertext
        return iv + ciphertext.substr(0, ciphertext_len);
    }
    
    static std::string decrypt(const std::string& ciphertext, const std::string& key) {
        if (ciphertext.length() < 16) return "";
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return "";
        
        const EVP_CIPHER* cipher = EVP_aes_256_gcm();
        std::string iv = ciphertext.substr(0, 16);
        std::string encrypted_data = ciphertext.substr(16);
        
        if (EVP_DecryptInit_ex(ctx, cipher, nullptr,
                              reinterpret_cast<const unsigned char*>(key.data()),
                              reinterpret_cast<const unsigned char*>(iv.data())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        
        std::string plaintext;
        plaintext.resize(encrypted_data.length());
        
        int len;
        if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plaintext.data()), &len,
                             reinterpret_cast<const unsigned char*>(encrypted_data.data()), encrypted_data.length()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        
        int plaintext_len = len;
        if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plaintext.data()) + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return "";
        }
        plaintext_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        
        return plaintext.substr(0, plaintext_len);
    }
    
    static std::string sign(const std::string& data, const std::string& private_key) {
        // Simplified signing - in real implementation, use proper digital signatures
        std::string signature;
        signature.resize(SHA256_DIGEST_LENGTH);
        
        HMAC(EVP_sha256(), private_key.data(), private_key.length(),
             reinterpret_cast<const unsigned char*>(data.data()), data.length(),
             reinterpret_cast<unsigned char*>(signature.data()), nullptr);
        
        return signature;
    }
    
    static bool verify(const std::string& data, const std::string& signature, const std::string& public_key) {
        // Simplified verification - in real implementation, use proper digital signature verification
        std::string expected_signature = sign(data, public_key);
        return signature == expected_signature;
    }
};

// Secure communication bus
class SecureBus {
private:
    std::map<std::string, AgentAuth> agent_auths_;
    std::map<std::string, std::string> agent_keys_;
    std::map<std::string, std::queue<SecureMessage>> message_queues_;
    std::mutex bus_mutex_;
    std::mutex auth_mutex_;
    std::atomic<bool> bus_active_;
    std::thread bus_thread_;
    
    // Master encryption key
    std::string master_key_;
    
    // Message routing
    std::map<std::string, std::function<void(const SecureMessage&)>> message_handlers_;

public:
    SecureBus() : bus_active_(false) {
        // Initialize OpenSSL
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        
        // Generate master key
        master_key_ = CryptoUtils::generate_key();
        
        std::cout << "ZAC Secure Bus initialized\n";
    }
    
    ~SecureBus() {
        shutdown();
        EVP_cleanup();
        ERR_free_strings();
    }
    
    void start() {
        bus_active_ = true;
        bus_thread_ = std::thread(&SecureBus::bus_loop, this);
        std::cout << "ZAC Secure Bus started\n";
    }
    
    void shutdown() {
        bus_active_ = false;
        if (bus_thread_.joinable()) {
            bus_thread_.join();
        }
        std::cout << "ZAC Secure Bus shutdown\n";
    }
    
    void register_agent(const std::string& agent_name) {
        std::lock_guard<std::mutex> lock(auth_mutex_);
        
        AgentAuth auth;
        auth.agent_id = agent_name;
        auth.public_key = CryptoUtils::generate_key();
        auth.certificate = generate_certificate(agent_name);
        auth.permissions = get_default_permissions(agent_name);
        auth.authenticated = true;
        auth.authorized = true;
        auth.last_heartbeat = std::chrono::steady_clock::now();
        
        agent_auths_[agent_name] = auth;
        agent_keys_[agent_name] = CryptoUtils::generate_key();
        
        std::cout << "Agent " << agent_name << " registered with ZAC bus\n";
    }
    
    void unregister_agent(const std::string& agent_name) {
        std::lock_guard<std::mutex> lock(auth_mutex_);
        
        agent_auths_.erase(agent_name);
        agent_keys_.erase(agent_name);
        message_queues_.erase(agent_name);
        
        std::cout << "Agent " << agent_name << " unregistered from ZAC bus\n";
    }
    
    void send_message(const ACP::Message& msg) {
        if (!is_agent_authenticated(msg.sender) || !is_agent_authenticated(msg.receiver)) {
            std::cerr << "Error: Unauthenticated agents cannot send messages\n";
            return;
        }
        
        // Convert ACP message to secure message
        SecureMessage secure_msg;
        secure_msg.id = generate_message_id();
        secure_msg.type = MessageType::Command;
        secure_msg.security_level = determine_security_level(msg);
        secure_msg.sender_id = msg.sender;
        secure_msg.receiver_id = msg.receiver;
        secure_msg.command = msg.command;
        secure_msg.payload = msg.payload;
        secure_msg.nonce = CryptoUtils::generate_nonce();
        
        // Encrypt message if needed
        if (secure_msg.security_level != SecurityLevel::Public) {
            std::string plaintext = serialize_message(secure_msg);
            std::string encrypted = CryptoUtils::encrypt(plaintext, get_agent_key(msg.receiver));
            secure_msg.payload["encrypted_data"] = encrypted;
            secure_msg.encrypted = true;
        }
        
        // Sign message
        std::string message_data = serialize_message(secure_msg);
        secure_msg.signature = CryptoUtils::sign(message_data, get_agent_key(msg.sender));
        
        // Send to receiver's queue
        std::lock_guard<std::mutex> lock(bus_mutex_);
        message_queues_[msg.receiver].push(secure_msg);
    }
    
    void send_message_async(const ACP::Message& msg, std::function<void(const std::string&)> callback) {
        // Send message asynchronously
        std::thread([this, msg, callback]() {
            send_message(msg);
            callback("Message sent successfully");
        }).detach();
    }
    
    void set_message_handler(const std::string& agent_name, std::function<void(const SecureMessage&)> handler) {
        std::lock_guard<std::mutex> lock(bus_mutex_);
        message_handlers_[agent_name] = handler;
    }
    
    // Get bus statistics
    struct BusStats {
        int total_agents;
        int authenticated_agents;
        int total_messages_sent;
        int total_messages_received;
        int failed_authentications;
        int encryption_failures;
        std::chrono::steady_clock::time_point last_activity;
    };
    
    BusStats get_bus_stats() {
        std::lock_guard<std::mutex> lock(auth_mutex_);
        BusStats stats;
        
        stats.total_agents = agent_auths_.size();
        stats.authenticated_agents = 0;
        
        for (const auto& [name, auth] : agent_auths_) {
            if (auth.authenticated) {
                stats.authenticated_agents++;
            }
        }
        
        return stats;
    }

private:
    void bus_loop() {
        while (bus_active_) {
            // Process message queues
            process_message_queues();
            
            // Check agent heartbeats
            check_agent_heartbeats();
            
            // Clean up expired messages
            cleanup_expired_messages();
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    void process_message_queues() {
        std::lock_guard<std::mutex> lock(bus_mutex_);
        
        for (auto& [agent_name, queue] : message_queues_) {
            while (!queue.empty()) {
                SecureMessage msg = queue.front();
                queue.pop();
                
                // Verify message signature
                if (!verify_message_signature(msg)) {
                    std::cerr << "Error: Invalid message signature from " << msg.sender_id << "\n";
                    continue;
                }
                
                // Decrypt message if needed
                if (msg.encrypted) {
                    std::string encrypted_data = msg.payload["encrypted_data"];
                    std::string decrypted = CryptoUtils::decrypt(encrypted_data, get_agent_key(agent_name));
                    if (decrypted.empty()) {
                        std::cerr << "Error: Failed to decrypt message from " << msg.sender_id << "\n";
                        continue;
                    }
                    // Parse decrypted data back into message
                    msg = parse_message(decrypted);
                }
                
                // Route message to handler
                auto handler_it = message_handlers_.find(agent_name);
                if (handler_it != message_handlers_.end()) {
                    handler_it->second(msg);
                }
            }
        }
    }
    
    void check_agent_heartbeats() {
        std::lock_guard<std::mutex> lock(auth_mutex_);
        
        auto now = std::chrono::steady_clock::now();
        for (auto& [name, auth] : agent_auths_) {
            if (now - auth.last_heartbeat > std::chrono::seconds(30)) {
                std::cout << "Warning: Agent " << name << " has not sent heartbeat in 30 seconds\n";
                // Could implement timeout logic here
            }
        }
    }
    
    void cleanup_expired_messages() {
        // Clean up messages older than 5 minutes
        auto now = std::chrono::steady_clock::now();
        // Implementation would remove old messages from queues
    }
    
    bool is_agent_authenticated(const std::string& agent_name) {
        std::lock_guard<std::mutex> lock(auth_mutex_);
        auto it = agent_auths_.find(agent_name);
        return it != agent_auths_.end() && it->second.authenticated;
    }
    
    std::string get_agent_key(const std::string& agent_name) {
        std::lock_guard<std::mutex> lock(auth_mutex_);
        auto it = agent_keys_.find(agent_name);
        return (it != agent_keys_.end()) ? it->second : master_key_;
    }
    
    SecurityLevel determine_security_level(const ACP::Message& msg) {
        // Determine security level based on message content
        if (msg.command == "heartbeat") {
            return SecurityLevel::Public;
        } else if (msg.command == "compile_request" || msg.command == "ai_request") {
            return SecurityLevel::Confidential;
        } else {
            return SecurityLevel::Protected;
        }
    }
    
    std::string generate_message_id() {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<> dis(100000, 999999);
        return "msg_" + std::to_string(dis(gen));
    }
    
    std::string generate_certificate(const std::string& agent_name) {
        // Simplified certificate generation
        return "cert_" + agent_name + "_" + std::to_string(std::time(nullptr));
    }
    
    std::vector<std::string> get_default_permissions(const std::string& agent_name) {
        // Default permissions for different agent types
        if (agent_name.find("compiler") != std::string::npos) {
            return {"compile", "optimize", "analyze"};
        } else if (agent_name.find("ai") != std::string::npos) {
            return {"generate", "analyze", "reason"};
        } else if (agent_name.find("security") != std::string::npos) {
            return {"verify", "scan", "monitor"};
        } else {
            return {"basic"};
        }
    }
    
    std::string serialize_message(const SecureMessage& msg) {
        std::stringstream ss;
        ss << msg.id << "|" << static_cast<int>(msg.type) << "|" << static_cast<int>(msg.security_level) << "|";
        ss << msg.sender_id << "|" << msg.receiver_id << "|" << msg.command << "|";
        ss << msg.timestamp << "|" << msg.nonce << "|";
        
        // Serialize payload
        for (const auto& [key, value] : msg.payload) {
            ss << key << "=" << value << ";";
        }
        
        return ss.str();
    }
    
    SecureMessage parse_message(const std::string& data) {
        SecureMessage msg;
        std::stringstream ss(data);
        std::string token;
        
        // Parse basic fields
        std::getline(ss, token, '|');
        msg.id = token;
        
        std::getline(ss, token, '|');
        msg.type = static_cast<MessageType>(std::stoi(token));
        
        std::getline(ss, token, '|');
        msg.security_level = static_cast<SecurityLevel>(std::stoi(token));
        
        std::getline(ss, token, '|');
        msg.sender_id = token;
        
        std::getline(ss, token, '|');
        msg.receiver_id = token;
        
        std::getline(ss, token, '|');
        msg.command = token;
        
        std::getline(ss, token, '|');
        msg.timestamp = token;
        
        std::getline(ss, token, '|');
        msg.nonce = token;
        
        // Parse payload
        std::string payload_str;
        std::getline(ss, payload_str);
        
        std::stringstream payload_ss(payload_str);
        std::string pair;
        while (std::getline(payload_ss, pair, ';')) {
            size_t equal_pos = pair.find('=');
            if (equal_pos != std::string::npos) {
                std::string key = pair.substr(0, equal_pos);
                std::string value = pair.substr(equal_pos + 1);
                msg.payload[key] = value;
            }
        }
        
        return msg;
    }
    
    bool verify_message_signature(const SecureMessage& msg) {
        std::string message_data = serialize_message(msg);
        return CryptoUtils::verify(message_data, msg.signature, get_agent_key(msg.sender_id));
    }
};

} // namespace ZAC
} // namespace Agents
