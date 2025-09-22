#include <string>
#include <vector>
#include <chrono>
#include <map>
#include <memory>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <queue>
#include "../../ai/model_layer.hpp"
#include "../../ai/reasoning/project_knowledge_graph.cpp"
#include "../../ui/ui_hooks.hpp"
#include "../../agent/acp.hpp"

namespace IDE_AI {
namespace TKE {

// Developer behavior patterns and mental model inference
struct DeveloperBehavior {
    std::string action_type;
    std::string context;
    std::chrono::steady_clock::time_point timestamp;
    std::map<std::string, std::string> metadata;
    int frequency = 1;
};

struct MentalModel {
    std::string concept;
    std::string inferred_intent;
    std::vector<std::string> related_concepts;
    float confidence = 0.0f;
    std::chrono::steady_clock::time_point last_updated;
};

// Tacit Knowledge Engine - infers developer's unspoken intentions
class Engine : public ACP::Agent {
public:
    Engine(CompletionModel* llm, ProjectKnowledgeGraph* pkg) 
        : ACP::Agent("tke_engine"), llm_(llm), pkg_(pkg) {
        
        // Initialize behavior tracking
        behavior_history_.reserve(1000);
        mental_models_.reserve(100);
        
        // Start observation thread
        observation_active_ = true;
        observation_thread_ = std::thread(&Engine::observation_loop, this);
        
        // Register UI event hooks
        register_ui_hooks();
        
        std::cout << "Tacit Knowledge Engine initialized\n";
    }
    
    ~Engine() {
        observation_active_ = false;
        if (observation_thread_.joinable()) {
            observation_thread_.join();
        }
    }

    void handle_message(const ACP::Message& msg) override {
        if (msg.command == "behavior_observation") {
            process_behavior_observation(msg.payload.at("action_type"), 
                                       msg.payload.at("context"),
                                       msg.payload.at("metadata"));
        } else if (msg.command == "infer_intent") {
            std::string context = msg.payload.at("context");
            auto intent = infer_developer_intent(context);
            
            ACP::Message response;
            response.sender = this->name_;
            response.receiver = msg.sender;
            response.command = "intent_inference";
            response.payload["intent"] = intent;
            response.payload["confidence"] = std::to_string(get_intent_confidence(intent));
            send_message(response);
        }
    }
    
    // Get current mental model for a concept
    std::optional<MentalModel> get_mental_model(const std::string& concept) {
        std::lock_guard<std::mutex> lock(mental_models_mutex_);
        auto it = mental_models_.find(concept);
        if (it != mental_models_.end()) {
            return it->second;
        }
        return std::nullopt;
    }
    
    // Get inferred next action
    std::string predict_next_action(const std::string& current_context) {
        std::string prompt = "Based on the developer's behavior patterns, predict their next likely action. Context: " + current_context;
        
        // Augment with behavior history
        std::string behavior_context = "Recent behavior patterns:\n";
        std::lock_guard<std::mutex> lock(behavior_mutex_);
        for (int i = std::max(0, (int)behavior_history_.size() - 10); i < behavior_history_.size(); ++i) {
            behavior_context += "- " + behavior_history_[i].action_type + ": " + behavior_history_[i].context + "\n";
        }
        
        std::string prediction = llm_->generate_completion(prompt + "\n" + behavior_context);
        return prediction;
    }

private:
    void register_ui_hooks() {
        // Hook into various UI events to observe developer behavior
        UIHooks::get_instance().on_idle_time_start([this]() { 
            observe_idle_behavior(); 
        });
        
        UIHooks::get_instance().on_repeated_mistake([this](const std::string& context) { 
            observe_repeated_mistake(context); 
        });
        
        UIHooks::get_instance().on_file_switch([this](const std::string& from_file, const std::string& to_file) {
            observe_file_switching(from_file, to_file);
        });
        
        UIHooks::get_instance().on_clipboard_usage([this](const std::string& content) {
            observe_clipboard_usage(content);
        });
        
        UIHooks::get_instance().on_search_pattern([this](const std::string& pattern) {
            observe_search_behavior(pattern);
        });
    }
    
    void observation_loop() {
        while (observation_active_) {
            // Analyze recent behavior patterns
            analyze_behavior_patterns();
            
            // Update mental models
            update_mental_models();
            
            // Generate proactive suggestions
            generate_proactive_suggestions();
            
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }
    
    void observe_idle_behavior() {
        std::string context = pkg_->get_recent_focus_context();
        
        DeveloperBehavior behavior;
        behavior.action_type = "idle_thinking";
        behavior.context = context;
        behavior.timestamp = std::chrono::steady_clock::now();
        behavior.metadata["duration"] = "unknown";
        
        add_behavior(behavior);
        
        // Infer what the developer might be thinking
        std::string prompt = "Developer is idle. Based on recent context, infer what they might be thinking or planning next. Context: " + context;
        std::string thought_suggestion = llm_->generate_completion(prompt);
        
        // Show non-intrusive suggestion
        UIHooks::get_instance().show_non_modal_notification("AI: Is this what you're thinking? " + thought_suggestion);
        
        // Update mental model
        update_mental_model("current_focus", thought_suggestion, 0.7f);
    }
    
    void observe_repeated_mistake(const std::string& context) {
        DeveloperBehavior behavior;
        behavior.action_type = "repeated_mistake";
        behavior.context = context;
        behavior.timestamp = std::chrono::steady_clock::now();
        
        add_behavior(behavior);
        
        // Count frequency of this mistake
        int mistake_count = count_behavior_frequency("repeated_mistake", context);
        
        if (mistake_count >= 3) {
            // Generate helpful explanation
            std::string prompt = "Developer keeps making the same mistake. Suggest a more fundamental fix or explanation. Context: " + context;
            std::string explanation = llm_->generate_completion(prompt);
            
            UIHooks::get_instance().insert_comment_inline("AI: I see you're struggling with this. Here's why: " + explanation);
            
            // Update mental model to reflect learning difficulty
            update_mental_model("learning_difficulty", context, 0.9f);
        }
    }
    
    void observe_file_switching(const std::string& from_file, const std::string& to_file) {
        DeveloperBehavior behavior;
        behavior.action_type = "file_switch";
        behavior.context = "From: " + from_file + " To: " + to_file;
        behavior.timestamp = std::chrono::steady_clock::now();
        behavior.metadata["from_file"] = from_file;
        behavior.metadata["to_file"] = to_file;
        
        add_behavior(behavior);
        
        // Infer the relationship between files
        std::string prompt = "Developer switched from " + from_file + " to " + to_file + ". What might be the relationship or reason?";
        std::string relationship = llm_->generate_completion(prompt);
        
        // Update knowledge graph with file relationship
        pkg_->add_relationship(from_file, to_file, "switched_to", relationship);
    }
    
    void observe_clipboard_usage(const std::string& content) {
        DeveloperBehavior behavior;
        behavior.action_type = "clipboard_usage";
        behavior.context = content.substr(0, 100); // First 100 chars
        behavior.timestamp = std::chrono::steady_clock::now();
        behavior.metadata["content_length"] = std::to_string(content.length());
        
        add_behavior(behavior);
        
        // Infer intent from clipboard content
        std::string prompt = "Developer copied this to clipboard. What might they be planning to do with it? Content: " + content.substr(0, 200);
        std::string intent = llm_->generate_completion(prompt);
        
        update_mental_model("clipboard_intent", intent, 0.6f);
    }
    
    void observe_search_behavior(const std::string& pattern) {
        DeveloperBehavior behavior;
        behavior.action_type = "search";
        behavior.context = pattern;
        behavior.timestamp = std::chrono::steady_clock::now();
        
        add_behavior(behavior);
        
        // Infer what the developer is looking for
        std::string prompt = "Developer searched for: " + pattern + ". What are they likely trying to find or understand?";
        std::string search_intent = llm_->generate_completion(prompt);
        
        update_mental_model("search_intent", search_intent, 0.8f);
    }
    
    void add_behavior(const DeveloperBehavior& behavior) {
        std::lock_guard<std::mutex> lock(behavior_mutex_);
        behavior_history_.push_back(behavior);
        
        // Keep only last 1000 behaviors
        if (behavior_history_.size() > 1000) {
            behavior_history_.erase(behavior_history_.begin());
        }
    }
    
    int count_behavior_frequency(const std::string& action_type, const std::string& context) {
        std::lock_guard<std::mutex> lock(behavior_mutex_);
        int count = 0;
        for (const auto& behavior : behavior_history_) {
            if (behavior.action_type == action_type && behavior.context.find(context) != std::string::npos) {
                count++;
            }
        }
        return count;
    }
    
    void analyze_behavior_patterns() {
        std::lock_guard<std::mutex> lock(behavior_mutex_);
        
        // Analyze recent behavior patterns
        std::map<std::string, int> action_frequencies;
        std::map<std::string, std::vector<std::string>> context_patterns;
        
        for (const auto& behavior : behavior_history_) {
            action_frequencies[behavior.action_type]++;
            context_patterns[behavior.action_type].push_back(behavior.context);
        }
        
        // Identify patterns
        for (const auto& [action, frequency] : action_frequencies) {
            if (frequency > 5) { // Frequent action
                std::string pattern_analysis = analyze_action_pattern(action, context_patterns[action]);
                update_mental_model("behavior_pattern_" + action, pattern_analysis, 0.8f);
            }
        }
    }
    
    std::string analyze_action_pattern(const std::string& action, const std::vector<std::string>& contexts) {
        std::string prompt = "Analyze this pattern of developer behavior. Action: " + action + ". Contexts: ";
        for (const auto& context : contexts) {
            prompt += context + "; ";
        }
        prompt += "What does this pattern reveal about the developer's workflow or thinking?";
        
        return llm_->generate_completion(prompt);
    }
    
    void update_mental_models() {
        std::lock_guard<std::mutex> lock(mental_models_mutex_);
        
        auto now = std::chrono::steady_clock::now();
        for (auto& [concept, model] : mental_models_) {
            // Decay confidence over time
            auto time_since_update = std::chrono::duration_cast<std::chrono::minutes>(now - model.last_updated);
            if (time_since_update.count() > 30) { // 30 minutes
                model.confidence *= 0.95f; // Slight decay
                model.last_updated = now;
            }
        }
    }
    
    void update_mental_model(const std::string& concept, const std::string& intent, float confidence) {
        std::lock_guard<std::mutex> lock(mental_models_mutex_);
        
        auto now = std::chrono::steady_clock::now();
        auto it = mental_models_.find(concept);
        
        if (it != mental_models_.end()) {
            // Update existing model
            it->second.inferred_intent = intent;
            it->second.confidence = std::max(it->second.confidence, confidence);
            it->second.last_updated = now;
        } else {
            // Create new model
            MentalModel model;
            model.concept = concept;
            model.inferred_intent = intent;
            model.confidence = confidence;
            model.last_updated = now;
            mental_models_[concept] = model;
        }
    }
    
    void generate_proactive_suggestions() {
        // Generate suggestions based on current mental models
        std::lock_guard<std::mutex> lock(mental_models_mutex_);
        
        for (const auto& [concept, model] : mental_models_) {
            if (model.confidence > 0.7f) {
                std::string prompt = "Based on this mental model, suggest a proactive action. Concept: " + concept + 
                                   " Intent: " + model.inferred_intent;
                std::string suggestion = llm_->generate_completion(prompt);
                
                // Send suggestion to UI
                UIHooks::get_instance().show_contextual_suggestion(concept, suggestion);
            }
        }
    }
    
    std::string infer_developer_intent(const std::string& context) {
        std::string prompt = "Infer the developer's intent from this context: " + context;
        return llm_->generate_completion(prompt);
    }
    
    float get_intent_confidence(const std::string& intent) {
        // Simple confidence calculation based on context clarity
        if (intent.length() > 50 && intent.find("likely") != std::string::npos) {
            return 0.8f;
        } else if (intent.length() > 20) {
            return 0.6f;
        } else {
            return 0.4f;
        }
    }
    
    // Member variables
    CompletionModel* llm_;
    ProjectKnowledgeGraph* pkg_;
    
    std::vector<DeveloperBehavior> behavior_history_;
    std::map<std::string, MentalModel> mental_models_;
    
    std::mutex behavior_mutex_;
    std::mutex mental_models_mutex_;
    
    std::atomic<bool> observation_active_;
    std::thread observation_thread_;
};

} // namespace TKE
} // namespace IDE_AI
