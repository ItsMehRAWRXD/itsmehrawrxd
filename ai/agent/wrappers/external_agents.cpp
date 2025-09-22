#include <string>
#include <vector>
#include <chrono>
#include <map>
#include <memory>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include "../../agent/acp.hpp"
#include "../../network/http_client.hpp"
#include "../../ui/ui_hooks.hpp"

namespace Agents {
namespace Wrappers {

// External agent status tracking
struct ExternalAgentStatus {
    std::string agent_name;
    std::chrono::steady_clock::time_point last_ui_event;
    std::chrono::steady_clock::time_point last_api_request;
    std::chrono::steady_clock::time_point last_api_response;
    std::chrono::steady_clock::time_point last_heartbeat;
    bool is_responding;
    int consecutive_timeouts;
    int total_requests;
    int successful_responses;
    std::string last_error;
    std::string current_context;
    
    ExternalAgentStatus(const std::string& name) 
        : agent_name(name), is_responding(true), consecutive_timeouts(0), 
          total_requests(0), successful_responses(0) {
        auto now = std::chrono::steady_clock::now();
        last_ui_event = now;
        last_api_request = now;
        last_api_response = now;
        last_heartbeat = now;
    }
};

// Base class for observing external AI agents
class ExternalAgentObserver : public ACP::Agent {
public:
    ExternalAgentObserver(const std::string& name) : ACP::Agent(name) {
        status_ = std::make_unique<ExternalAgentStatus>(name);
        monitoring_active_ = true;
        
        // Start monitoring thread
        monitoring_thread_ = std::thread(&ExternalAgentObserver::monitoring_loop, this);
        
        // Register with the UI and network monitoring systems
        register_ui_hooks();
        register_network_hooks();
    }
    
    virtual ~ExternalAgentObserver() {
        monitoring_active_ = false;
        if (monitoring_thread_.joinable()) {
            monitoring_thread_.join();
        }
    }

    void handle_message(const ACP::Message& msg) override {
        if (msg.command == "status_request") {
            send_status_update();
        } else if (msg.command == "intervention_request") {
            handle_intervention_request(msg.payload.at("intervention_type"));
        }
    }
    
    // Get current status
    ExternalAgentStatus get_status() const {
        std::lock_guard<std::mutex> lock(status_mutex_);
        return *status_;
    }
    
    // Check if agent appears to be hung
    bool is_hung() const {
        std::lock_guard<std::mutex> lock(status_mutex_);
        auto now = std::chrono::steady_clock::now();
        
        // Heuristic 1: No API response for more than 30 seconds
        if (now - status_->last_api_response > std::chrono::seconds(30)) {
            return true;
        }
        
        // Heuristic 2: UI activity without corresponding API response
        if (status_->last_ui_event > status_->last_api_response && 
            now - status_->last_api_response > std::chrono::seconds(10)) {
            return true;
        }
        
        // Heuristic 3: Too many consecutive timeouts
        if (status_->consecutive_timeouts > 3) {
            return true;
        }
        
        return false;
    }

protected:
    void send_observation(const std::string& type, const std::string& payload) {
        ACP::Message observation;
        observation.sender = this->name_;
        observation.receiver = "meta_agent";
        observation.command = "observation";
        observation.payload["agent"] = status_->agent_name;
        observation.payload["type"] = type;
        observation.payload["data"] = payload;
        observation.payload["timestamp"] = std::to_string(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        send_message(observation);
    }
    
    void update_status(const std::function<void(ExternalAgentStatus&)>& updater) {
        std::lock_guard<std::mutex> lock(status_mutex_);
        updater(*status_);
    }
    
    void send_status_update() {
        ACP::Message status_msg;
        status_msg.sender = this->name_;
        status_msg.receiver = "meta_agent";
        status_msg.command = "status_update";
        status_msg.payload["agent"] = status_->agent_name;
        status_msg.payload["is_responding"] = std::to_string(status_->is_responding);
        status_msg.payload["consecutive_timeouts"] = std::to_string(status_->consecutive_timeouts);
        status_msg.payload["total_requests"] = std::to_string(status_->total_requests);
        status_msg.payload["successful_responses"] = std::to_string(status_->successful_responses);
        status_msg.payload["last_error"] = status_->last_error;
        status_msg.payload["current_context"] = status_->current_context;
        send_message(status_msg);
    }
    
    virtual void register_ui_hooks() = 0;
    virtual void register_network_hooks() = 0;
    virtual void handle_intervention_request(const std::string& intervention_type) = 0;

private:
    void monitoring_loop() {
        while (monitoring_active_) {
            // Check for hangs and send periodic status updates
            if (is_hung()) {
                send_observation("hang_detected", "Agent appears to be hung");
            }
            
            // Send heartbeat
            send_observation("heartbeat", "Agent is alive");
            update_status([](ExternalAgentStatus& s) {
                s.last_heartbeat = std::chrono::steady_clock::now();
            });
            
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
    
    std::unique_ptr<ExternalAgentStatus> status_;
    std::mutex status_mutex_;
    std::atomic<bool> monitoring_active_;
    std::thread monitoring_thread_;
};

// Wrapper for monitoring ChatGPT interactions
class ChatGPTWrapper : public ExternalAgentObserver {
public:
    ChatGPTWrapper() : ExternalAgentObserver("chatgpt_wrapper") {
        std::cout << "ChatGPT Wrapper initialized\n";
    }

protected:
    void register_ui_hooks() override {
        // Hook into ChatGPT UI events
        UIHooks::on_chat_window_activity("ChatGPT", [this](const std::string& event) {
            update_status([](ExternalAgentStatus& s) {
                s.last_ui_event = std::chrono::steady_clock::now();
            });
            send_observation("ui_event", event);
        });
        
        UIHooks::on_text_input("ChatGPT", [this](const std::string& text) {
            update_status([](ExternalAgentStatus& s) {
                s.current_context = text.substr(0, 200); // Store first 200 chars
            });
            send_observation("text_input", text);
        });
    }
    
    void register_network_hooks() override {
        // Monitor OpenAI API calls
        NetworkMonitor::on_request("api.openai.com/v1/chat/completions", [this](const HttpRequest& req) {
            update_status([](ExternalAgentStatus& s) {
                s.last_api_request = std::chrono::steady_clock::now();
                s.total_requests++;
            });
            send_observation("api_request", req.body);
        });
        
        NetworkMonitor::on_response("api.openai.com/v1/chat/completions", [this](const HttpResponse& res) {
            update_status([](ExternalAgentStatus& s) {
                s.last_api_response = std::chrono::steady_clock::now();
                if (res.status_code >= 200 && res.status_code < 300) {
                    s.successful_responses++;
                    s.consecutive_timeouts = 0;
                    s.is_responding = true;
                } else {
                    s.consecutive_timeouts++;
                    s.last_error = "HTTP " + std::to_string(res.status_code);
                    s.is_responding = false;
                }
            });
            send_observation("api_response", res.body);
        });
        
        NetworkMonitor::on_timeout("api.openai.com", [this](const std::string& endpoint) {
            update_status([](ExternalAgentStatus& s) {
                s.consecutive_timeouts++;
                s.last_error = "Timeout on " + endpoint;
                s.is_responding = false;
            });
            send_observation("api_timeout", endpoint);
        });
    }
    
    void handle_intervention_request(const std::string& intervention_type) override {
        if (intervention_type == "regenerate_response") {
            UIHooks::send_key_combination("ChatGPT", "Ctrl+R");
            send_observation("intervention", "Sent regenerate response command");
        } else if (intervention_type == "clear_context") {
            UIHooks::send_key_combination("ChatGPT", "Ctrl+Shift+C");
            send_observation("intervention", "Sent clear context command");
        } else if (intervention_type == "refresh_page") {
            UIHooks::send_key_combination("ChatGPT", "F5");
            send_observation("intervention", "Sent refresh page command");
        }
    }
};

// Wrapper for monitoring GitHub Copilot
class GitHubCopilotWrapper : public ExternalAgentObserver {
public:
    GitHubCopilotWrapper() : ExternalAgentObserver("github_copilot_wrapper") {
        std::cout << "GitHub Copilot Wrapper initialized\n";
    }

protected:
    void register_ui_hooks() override {
        // Monitor Copilot suggestion UI
        UIHooks::on_code_suggestion("GitHubCopilot", [this](const std::string& suggestion) {
            update_status([](ExternalAgentStatus& s) {
                s.last_ui_event = std::chrono::steady_clock::now();
                s.current_context = suggestion.substr(0, 200);
            });
            send_observation("code_suggestion", suggestion);
        });
        
        UIHooks::on_inline_completion("GitHubCopilot", [this](const std::string& completion) {
            send_observation("inline_completion", completion);
        });
        
        UIHooks::on_suggestion_accepted("GitHubCopilot", [this](const std::string& suggestion) {
            send_observation("suggestion_accepted", suggestion);
        });
    }
    
    void register_network_hooks() override {
        // Monitor Copilot API endpoints
        NetworkMonitor::on_request("api.github.com/copilot", [this](const HttpRequest& req) {
            update_status([](ExternalAgentStatus& s) {
                s.last_api_request = std::chrono::steady_clock::now();
                s.total_requests++;
            });
            send_observation("api_request", req.body);
        });
        
        NetworkMonitor::on_response("api.github.com/copilot", [this](const HttpResponse& res) {
            update_status([](ExternalAgentStatus& s) {
                s.last_api_response = std::chrono::steady_clock::now();
                if (res.status_code >= 200 && res.status_code < 300) {
                    s.successful_responses++;
                    s.consecutive_timeouts = 0;
                    s.is_responding = true;
                } else {
                    s.consecutive_timeouts++;
                    s.last_error = "HTTP " + std::to_string(res.status_code);
                    s.is_responding = false;
                }
            });
            send_observation("api_response", res.body);
        });
    }
    
    void handle_intervention_request(const std::string& intervention_type) override {
        if (intervention_type == "refresh_suggestions") {
            UIHooks::send_key_combination("GitHubCopilot", "Ctrl+Shift+P");
            send_observation("intervention", "Sent refresh suggestions command");
        } else if (intervention_type == "toggle_copilot") {
            UIHooks::send_key_combination("GitHubCopilot", "Ctrl+Shift+C");
            send_observation("intervention", "Toggled Copilot on/off");
        } else if (intervention_type == "clear_cache") {
            UIHooks::send_key_combination("GitHubCopilot", "Ctrl+Shift+Del");
            send_observation("intervention", "Cleared Copilot cache");
        }
    }
};

// Wrapper for monitoring Microsoft Copilot
class MicrosoftCopilotWrapper : public ExternalAgentObserver {
public:
    MicrosoftCopilotWrapper() : ExternalAgentObserver("microsoft_copilot_wrapper") {
        std::cout << "Microsoft Copilot Wrapper initialized\n";
    }

protected:
    void register_ui_hooks() override {
        // Monitor Microsoft Copilot UI
        UIHooks::on_chat_window_activity("MicrosoftCopilot", [this](const std::string& event) {
            update_status([](ExternalAgentStatus& s) {
                s.last_ui_event = std::chrono::steady_clock::now();
            });
            send_observation("ui_event", event);
        });
        
        UIHooks::on_document_analysis("MicrosoftCopilot", [this](const std::string& analysis) {
            update_status([](ExternalAgentStatus& s) {
                s.current_context = analysis.substr(0, 200);
            });
            send_observation("document_analysis", analysis);
        });
    }
    
    void register_network_hooks() override {
        // Monitor Microsoft Graph API calls
        NetworkMonitor::on_request("graph.microsoft.com", [this](const HttpRequest& req) {
            update_status([](ExternalAgentStatus& s) {
                s.last_api_request = std::chrono::steady_clock::now();
                s.total_requests++;
            });
            send_observation("api_request", req.body);
        });
        
        NetworkMonitor::on_response("graph.microsoft.com", [this](const HttpResponse& res) {
            update_status([](ExternalAgentStatus& s) {
                s.last_api_response = std::chrono::steady_clock::now();
                if (res.status_code >= 200 && res.status_code < 300) {
                    s.successful_responses++;
                    s.consecutive_timeouts = 0;
                    s.is_responding = true;
                } else {
                    s.consecutive_timeouts++;
                    s.last_error = "HTTP " + std::to_string(res.status_code);
                    s.is_responding = false;
                }
            });
            send_observation("api_response", res.body);
        });
    }
    
    void handle_intervention_request(const std::string& intervention_type) override {
        if (intervention_type == "refresh_analysis") {
            UIHooks::send_key_combination("MicrosoftCopilot", "Ctrl+Shift+R");
            send_observation("intervention", "Sent refresh analysis command");
        } else if (intervention_type == "restart_copilot") {
            UIHooks::send_key_combination("MicrosoftCopilot", "Ctrl+Shift+Restart");
            send_observation("intervention", "Restarted Microsoft Copilot");
        }
    }
};

// Wrapper for monitoring Kimi.ai
class KimiWrapper : public ExternalAgentObserver {
public:
    KimiWrapper() : ExternalAgentObserver("kimi_wrapper") {
        std::cout << "Kimi Wrapper initialized\n";
    }

protected:
    void register_ui_hooks() override {
        // Monitor Kimi chat interface
        UIHooks::on_chat_window_activity("Kimi", [this](const std::string& event) {
            update_status([](ExternalAgentStatus& s) {
                s.last_ui_event = std::chrono::steady_clock::now();
            });
            send_observation("ui_event", event);
        });
        
        UIHooks::on_text_input("Kimi", [this](const std::string& text) {
            update_status([](ExternalAgentStatus& s) {
                s.current_context = text.substr(0, 200);
            });
            send_observation("text_input", text);
        });
    }
    
    void register_network_hooks() override {
        // Monitor Kimi API calls
        NetworkMonitor::on_request("api.moonshot.cn", [this](const HttpRequest& req) {
            update_status([](ExternalAgentStatus& s) {
                s.last_api_request = std::chrono::steady_clock::now();
                s.total_requests++;
            });
            send_observation("api_request", req.body);
        });
        
        NetworkMonitor::on_response("api.moonshot.cn", [this](const HttpResponse& res) {
            update_status([](ExternalAgentStatus& s) {
                s.last_api_response = std::chrono::steady_clock::now();
                if (res.status_code >= 200 && res.status_code < 300) {
                    s.successful_responses++;
                    s.consecutive_timeouts = 0;
                    s.is_responding = true;
                } else {
                    s.consecutive_timeouts++;
                    s.last_error = "HTTP " + std::to_string(res.status_code);
                    s.is_responding = false;
                }
            });
            send_observation("api_response", res.body);
        });
    }
    
    void handle_intervention_request(const std::string& intervention_type) override {
        if (intervention_type == "regenerate_response") {
            UIHooks::send_key_combination("Kimi", "Ctrl+R");
            send_observation("intervention", "Sent regenerate response command");
        } else if (intervention_type == "clear_chat") {
            UIHooks::send_key_combination("Kimi", "Ctrl+Shift+C");
            send_observation("intervention", "Cleared chat history");
        } else if (intervention_type == "refresh_page") {
            UIHooks::send_key_combination("Kimi", "F5");
            send_observation("intervention", "Refreshed page");
        }
    }
};

} // namespace Agents::Wrappers
} // namespace Agents
