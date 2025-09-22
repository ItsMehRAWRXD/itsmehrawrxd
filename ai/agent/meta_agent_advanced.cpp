#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include "acp.hpp"
#include "wrappers/external_agents.cpp"
#include "../model_layer.hpp"
#include "../ide-vdb.hpp"

namespace Agents {

// Advanced intervention strategies
enum class InterventionType {
    REGENERATE_RESPONSE,
    CLEAR_CONTEXT,
    REFRESH_PAGE,
    RESTART_SERVICE,
    TOGGLE_FEATURE,
    CLEAR_CACHE,
    REFRESH_SUGGESTIONS,
    REFRESH_ANALYSIS,
    SEND_KEYSTROKE,
    CUSTOM_COMMAND
};

struct InterventionStrategy {
    InterventionType type;
    std::string command;
    std::string description;
    int priority; // Higher number = higher priority
    std::function<bool(const std::string&)> condition; // When to apply this intervention
};

// Enhanced Meta-Agent with external agent supervision
class MetaAgentAdvanced : public ACP::Agent {
public:
    MetaAgentAdvanced(const std::string& name, 
                     std::shared_ptr<CompletionModel> llm,
                     std::shared_ptr<VectorDatabase> vdb)
        : ACP::Agent(name), llm_(llm), vdb_(vdb) {
        
        // Initialize intervention strategies
        initialize_intervention_strategies();
        
        // Start supervision thread
        supervision_active_ = true;
        supervision_thread_ = std::thread(&MetaAgentAdvanced::supervision_loop, this);
        
        std::cout << "MetaAgent Advanced initialized with external agent supervision\n";
    }
    
    ~MetaAgentAdvanced() {
        supervision_active_ = false;
        if (supervision_thread_.joinable()) {
            supervision_thread_.join();
        }
    }

    void handle_message(const ACP::Message& msg) override {
        if (msg.command == "observation") {
            handle_observation(msg);
        } else if (msg.command == "status_update") {
            handle_status_update(msg);
        } else if (msg.command == "intervention_request") {
            handle_intervention_request(msg);
        } else if (msg.command == "supervision_request") {
            handle_supervision_request(msg);
        }
    }
    
    // Add external agent wrapper for supervision
    void add_external_agent(std::shared_ptr<Wrappers::ExternalAgentObserver> wrapper) {
        std::lock_guard<std::mutex> lock(agents_mutex_);
        external_agents_[wrapper->get_name()] = wrapper;
        std::cout << "Added external agent for supervision: " << wrapper->get_name() << "\n";
    }
    
    // Get supervision status for all agents
    std::map<std::string, bool> get_supervision_status() const {
        std::lock_guard<std::mutex> lock(agents_mutex_);
        std::map<std::string, bool> status;
        for (const auto& [name, wrapper] : external_agents_) {
            status[name] = !wrapper->is_hung();
        }
        return status;
    }

private:
    void initialize_intervention_strategies() {
        // ChatGPT interventions
        intervention_strategies_["chatgpt_wrapper"] = {
            {
                InterventionType::REGENERATE_RESPONSE,
                "regenerate_response",
                "Regenerate the last response",
                3,
                [](const std::string& context) { return context.find("timeout") != std::string::npos; }
            },
            {
                InterventionType::CLEAR_CONTEXT,
                "clear_context",
                "Clear conversation context",
                2,
                [](const std::string& context) { return context.find("context_error") != std::string::npos; }
            },
            {
                InterventionType::REFRESH_PAGE,
                "refresh_page",
                "Refresh the ChatGPT page",
                1,
                [](const std::string& context) { return context.find("page_error") != std::string::npos; }
            }
        };
        
        // GitHub Copilot interventions
        intervention_strategies_["github_copilot_wrapper"] = {
            {
                InterventionType::REFRESH_SUGGESTIONS,
                "refresh_suggestions",
                "Refresh code suggestions",
                3,
                [](const std::string& context) { return context.find("suggestion_timeout") != std::string::npos; }
            },
            {
                InterventionType::TOGGLE_FEATURE,
                "toggle_copilot",
                "Toggle Copilot on/off",
                2,
                [](const std::string& context) { return context.find("service_error") != std::string::npos; }
            },
            {
                InterventionType::CLEAR_CACHE,
                "clear_cache",
                "Clear Copilot cache",
                1,
                [](const std::string& context) { return context.find("cache_error") != std::string::npos; }
            }
        };
        
        // Microsoft Copilot interventions
        intervention_strategies_["microsoft_copilot_wrapper"] = {
            {
                InterventionType::REFRESH_ANALYSIS,
                "refresh_analysis",
                "Refresh document analysis",
                3,
                [](const std::string& context) { return context.find("analysis_timeout") != std::string::npos; }
            },
            {
                InterventionType::RESTART_SERVICE,
                "restart_copilot",
                "Restart Microsoft Copilot",
                2,
                [](const std::string& context) { return context.find("service_crash") != std::string::npos; }
            }
        };
        
        // Kimi interventions
        intervention_strategies_["kimi_wrapper"] = {
            {
                InterventionType::REGENERATE_RESPONSE,
                "regenerate_response",
                "Regenerate the last response",
                3,
                [](const std::string& context) { return context.find("response_timeout") != std::string::npos; }
            },
            {
                InterventionType::CLEAR_CONTEXT,
                "clear_chat",
                "Clear chat history",
                2,
                [](const std::string& context) { return context.find("context_overflow") != std::string::npos; }
            },
            {
                InterventionType::REFRESH_PAGE,
                "refresh_page",
                "Refresh the Kimi page",
                1,
                [](const std::string& context) { return context.find("page_error") != std::string::npos; }
            }
        };
    }
    
    void supervision_loop() {
        while (supervision_active_) {
            // Check all external agents for hangs
            check_external_agents_for_hangs();
            
            // Process any pending interventions
            process_pending_interventions();
            
            // Update supervision statistics
            update_supervision_statistics();
            
            // Sleep for 5 seconds before next check
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
    
    void check_external_agents_for_hangs() {
        std::lock_guard<std::mutex> lock(agents_mutex_);
        
        for (const auto& [name, wrapper] : external_agents_) {
            if (wrapper->is_hung()) {
                std::cout << "MetaAgent: External agent " << name << " appears hung. Analyzing...\n";
                
                // Get current status and context
                auto status = wrapper->get_status();
                std::string context = analyze_agent_context(status);
                
                // Generate intervention strategy
                auto intervention = generate_intervention_strategy(name, context, status);
                
                if (intervention.has_value()) {
                    execute_intervention(name, intervention.value());
                }
            }
        }
    }
    
    std::string analyze_agent_context(const Wrappers::ExternalAgentStatus& status) {
        std::string context = "Agent: " + status.agent_name + "\n";
        context += "Last error: " + status.last_error + "\n";
        context += "Consecutive timeouts: " + std::to_string(status.consecutive_timeouts) + "\n";
        context += "Total requests: " + std::to_string(status.total_requests) + "\n";
        context += "Successful responses: " + std::to_string(status.successful_responses) + "\n";
        context += "Current context: " + status.current_context + "\n";
        
        // Use AI to analyze the context and suggest intervention type
        std::string prompt = "Analyze this agent status and suggest the most likely cause and intervention:\n\n" + context;
        
        // Get relevant examples from vector database
        auto query_embedding = llm_->generate_embedding(context);
        auto relevant_docs = vdb_->search(query_embedding, 3);
        
        std::string augmented_prompt = "Similar debugging scenarios:\n";
        for (const auto& doc_id : relevant_docs) {
            augmented_prompt += vdb_->get_metadata(doc_id) + "\n";
        }
        augmented_prompt += "\n" + prompt;
        
        return llm_->generate_completion(augmented_prompt);
    }
    
    std::optional<InterventionStrategy> generate_intervention_strategy(
        const std::string& agent_name, 
        const std::string& context, 
        const Wrappers::ExternalAgentStatus& status) {
        
        auto strategies_it = intervention_strategies_.find(agent_name);
        if (strategies_it == intervention_strategies_.end()) {
            return std::nullopt;
        }
        
        // Find the highest priority strategy that matches the condition
        InterventionStrategy* best_strategy = nullptr;
        int highest_priority = -1;
        
        for (auto& strategy : strategies_it->second) {
            if (strategy.condition(context) && strategy.priority > highest_priority) {
                best_strategy = &strategy;
                highest_priority = strategy.priority;
            }
        }
        
        if (best_strategy) {
            return *best_strategy;
        }
        
        // If no specific strategy matches, use AI to generate a custom intervention
        return generate_ai_intervention(agent_name, context, status);
    }
    
    std::optional<InterventionStrategy> generate_ai_intervention(
        const std::string& agent_name,
        const std::string& context,
        const Wrappers::ExternalAgentStatus& status) {
        
        std::string prompt = "Generate a specific intervention command for " + agent_name + 
                           " that is currently hung. Context: " + context + 
                           ". Provide a specific command that can be sent to the UI or API.";
        
        std::string ai_suggestion = llm_->generate_completion(prompt);
        
        // Parse AI suggestion and create custom intervention
        InterventionStrategy custom_strategy;
        custom_strategy.type = InterventionType::CUSTOM_COMMAND;
        custom_strategy.command = ai_suggestion;
        custom_strategy.description = "AI-generated intervention";
        custom_strategy.priority = 1;
        custom_strategy.condition = [](const std::string&) { return true; };
        
        return custom_strategy;
    }
    
    void execute_intervention(const std::string& agent_name, const InterventionStrategy& strategy) {
        std::cout << "MetaAgent: Executing intervention for " << agent_name 
                  << ": " << strategy.description << "\n";
        
        // Send intervention request to the agent wrapper
        ACP::Message intervention_msg;
        intervention_msg.sender = this->name_;
        intervention_msg.receiver = agent_name;
        intervention_msg.command = "intervention_request";
        intervention_msg.payload["intervention_type"] = strategy.command;
        intervention_msg.payload["description"] = strategy.description;
        intervention_msg.payload["priority"] = std::to_string(strategy.priority);
        
        send_message(intervention_msg);
        
        // Log the intervention
        log_intervention(agent_name, strategy);
    }
    
    void log_intervention(const std::string& agent_name, const InterventionStrategy& strategy) {
        std::lock_guard<std::mutex> lock(intervention_log_mutex_);
        
        InterventionLog log_entry;
        log_entry.timestamp = std::chrono::steady_clock::now();
        log_entry.agent_name = agent_name;
        log_entry.strategy = strategy;
        log_entry.success = false; // Will be updated when we get feedback
        
        intervention_log_.push_back(log_entry);
        
        // Keep only last 100 interventions
        if (intervention_log_.size() > 100) {
            intervention_log_.erase(intervention_log_.begin());
        }
    }
    
    void handle_observation(const ACP::Message& msg) {
        std::string agent_name = msg.payload.at("agent");
        std::string type = msg.payload.at("type");
        std::string data = msg.payload.at("data");
        
        // Update agent activity tracking
        update_agent_activity(agent_name, type, data);
        
        // Check if this observation indicates a problem
        if (type == "hang_detected" || type == "api_timeout" || type == "error") {
            std::cout << "MetaAgent: Problem detected with " << agent_name 
                      << " (" << type << "): " << data << "\n";
        }
    }
    
    void handle_status_update(const ACP::Message& msg) {
        std::string agent_name = msg.payload.at("agent");
        bool is_responding = msg.payload.at("is_responding") == "true";
        int consecutive_timeouts = std::stoi(msg.payload.at("consecutive_timeouts"));
        
        // Update internal tracking
        std::lock_guard<std::mutex> lock(agents_mutex_);
        if (external_agents_.find(agent_name) != external_agents_.end()) {
            // Agent is being tracked, update our records
        }
    }
    
    void handle_intervention_request(const ACP::Message& msg) {
        // Handle requests for intervention from other agents
        std::string target_agent = msg.payload.at("target_agent");
        std::string intervention_type = msg.payload.at("intervention_type");
        
        std::cout << "MetaAgent: Intervention requested for " << target_agent 
                  << " with type " << intervention_type << "\n";
        
        // Forward to appropriate wrapper
        std::lock_guard<std::mutex> lock(agents_mutex_);
        auto it = external_agents_.find(target_agent);
        if (it != external_agents_.end()) {
            ACP::Message forward_msg = msg;
            forward_msg.receiver = target_agent;
            send_message(forward_msg);
        }
    }
    
    void handle_supervision_request(const ACP::Message& msg) {
        // Handle requests for supervision status or control
        std::string request_type = msg.payload.at("request_type");
        
        if (request_type == "status") {
            auto status = get_supervision_status();
            ACP::Message response;
            response.sender = this->name_;
            response.receiver = msg.sender;
            response.command = "supervision_status";
            response.payload["status"] = serialize_status(status);
            send_message(response);
        }
    }
    
    void update_agent_activity(const std::string& agent_name, const std::string& type, const std::string& data) {
        std::lock_guard<std::mutex> lock(activity_mutex_);
        
        auto now = std::chrono::steady_clock::now();
        agent_activity_[agent_name].last_activity = now;
        agent_activity_[agent_name].activity_type = type;
        agent_activity_[agent_name].activity_data = data;
    }
    
    void process_pending_interventions() {
        // Process any interventions that are waiting for execution
        std::lock_guard<std::mutex> lock(pending_interventions_mutex_);
        
        while (!pending_interventions_.empty()) {
            auto intervention = pending_interventions_.front();
            pending_interventions_.pop();
            
            execute_intervention(intervention.agent_name, intervention.strategy);
        }
    }
    
    void update_supervision_statistics() {
        // Update internal statistics about supervision effectiveness
        std::lock_guard<std::mutex> lock(intervention_log_mutex_);
        
        int total_interventions = intervention_log_.size();
        int successful_interventions = 0;
        
        for (const auto& log : intervention_log_) {
            if (log.success) {
                successful_interventions++;
            }
        }
        
        if (total_interventions > 0) {
            double success_rate = (double)successful_interventions / total_interventions;
            std::cout << "MetaAgent: Supervision statistics - " 
                      << total_interventions << " interventions, " 
                      << (success_rate * 100) << "% success rate\n";
        }
    }
    
    std::string serialize_status(const std::map<std::string, bool>& status) {
        std::string result = "{";
        bool first = true;
        for (const auto& [name, is_healthy] : status) {
            if (!first) result += ",";
            result += "\"" + name + "\":" + (is_healthy ? "true" : "false");
            first = false;
        }
        result += "}";
        return result;
    }
    
    // Data structures
    struct AgentActivity {
        std::chrono::steady_clock::time_point last_activity;
        std::string activity_type;
        std::string activity_data;
    };
    
    struct InterventionLog {
        std::chrono::steady_clock::time_point timestamp;
        std::string agent_name;
        InterventionStrategy strategy;
        bool success;
    };
    
    struct PendingIntervention {
        std::string agent_name;
        InterventionStrategy strategy;
    };
    
    // Member variables
    std::shared_ptr<CompletionModel> llm_;
    std::shared_ptr<VectorDatabase> vdb_;
    
    std::map<std::string, std::shared_ptr<Wrappers::ExternalAgentObserver>> external_agents_;
    std::map<std::string, std::vector<InterventionStrategy>> intervention_strategies_;
    std::map<std::string, AgentActivity> agent_activity_;
    std::vector<InterventionLog> intervention_log_;
    std::queue<PendingIntervention> pending_interventions_;
    
    mutable std::mutex agents_mutex_;
    mutable std::mutex activity_mutex_;
    mutable std::mutex intervention_log_mutex_;
    mutable std::mutex pending_interventions_mutex_;
    
    std::atomic<bool> supervision_active_;
    std::thread supervision_thread_;
};

} // namespace Agents
