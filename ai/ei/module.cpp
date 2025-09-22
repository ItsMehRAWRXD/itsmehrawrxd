#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include "../../ai/model_layer.hpp"
#include "../../ai/multi_ingest.cpp"
#include "../../ui/ui_hooks.hpp"
#include "../../agent/acp.hpp"

namespace IDE_AI {
namespace EI {

// Emotional states and their characteristics
enum class Emotion {
    NEUTRAL,
    FRUSTRATION,
    EXCITEMENT,
    CONFUSION,
    SATISFACTION,
    ANXIETY,
    FOCUS,
    BOREDOM,
    CREATIVITY,
    DETERMINATION
};

enum class Tone {
    CALM,
    ENERGETIC,
    SUPPORTIVE,
    ANALYTICAL,
    ENCOURAGING,
    PATIENT,
    URGENT,
    PLAYFUL
};

// Emotional state tracking
struct EmotionalState {
    Emotion primary_emotion;
    float intensity;
    std::chrono::steady_clock::time_point timestamp;
    std::map<std::string, float> emotion_scores;
    std::string context;
    std::vector<std::string> triggers;
};

// Behavioral adaptation strategies
struct AdaptationStrategy {
    Tone recommended_tone;
    std::string ui_style;
    std::string interaction_mode;
    std::vector<std::string> suggested_actions;
    float confidence;
};

// Emotional Intelligence Module - adapts AI behavior based on developer's emotional state
class Module : public ACP::Agent {
public:
    Module(CompletionModel* llm) 
        : ACP::Agent("ei_module"), llm_(llm) {
        
        // Initialize emotional state
        current_state_.primary_emotion = Emotion::NEUTRAL;
        current_state_.intensity = 0.5f;
        current_state_.timestamp = std::chrono::steady_clock::now();
        
        // Start emotion monitoring thread
        monitoring_active_ = true;
        monitoring_thread_ = std::thread(&Module::emotion_monitoring_loop, this);
        
        // Register sensor hooks
        register_sensor_hooks();
        
        std::cout << "Emotional Intelligence Module initialized\n";
    }
    
    ~Module() {
        monitoring_active_ = false;
        if (monitoring_thread_.joinable()) {
            monitoring_thread_.join();
        }
    }

    void handle_message(const ACP::Message& msg) override {
        if (msg.command == "emotion_detected") {
            Emotion emotion = static_cast<Emotion>(std::stoi(msg.payload.at("emotion")));
            float intensity = std::stof(msg.payload.at("intensity"));
            std::string context = msg.payload.at("context");
            
            update_emotional_state(emotion, intensity, context);
        } else if (msg.command == "behavior_request") {
            std::string context = msg.payload.at("context");
            auto strategy = generate_adaptation_strategy(context);
            
            ACP::Message response;
            response.sender = this->name_;
            response.receiver = msg.sender;
            response.command = "adaptation_strategy";
            response.payload["tone"] = std::to_string(static_cast<int>(strategy.recommended_tone));
            response.payload["ui_style"] = strategy.ui_style;
            response.payload["interaction_mode"] = strategy.interaction_mode;
            response.payload["confidence"] = std::to_string(strategy.confidence);
            send_message(response);
        }
    }
    
    // Get current emotional state
    EmotionalState get_current_state() const {
        std::lock_guard<std::mutex> lock(state_mutex_);
        return current_state_;
    }
    
    // Get recommended adaptation strategy
    AdaptationStrategy get_adaptation_strategy() const {
        std::lock_guard<std::mutex> lock(strategy_mutex_);
        return current_strategy_;
    }

private:
    void register_sensor_hooks() {
        // Register hooks for various emotional indicators
        // Note: In a real implementation, these would connect to actual sensors
        
        // Simulate emotion detection from various sources
        UIHooks::get_instance().on_typing_speed_change([this](int wpm) {
            analyze_typing_pattern(wpm);
        });
        
        UIHooks::get_instance().on_mouse_movement_pattern([this](const std::string& pattern) {
            analyze_mouse_behavior(pattern);
        });
        
        UIHooks::get_instance().on_error_frequency([this](int error_count) {
            analyze_error_patterns(error_count);
        });
        
        UIHooks::get_instance().on_code_completion_usage([this](bool used_completion) {
            analyze_completion_behavior(used_completion);
        });
    }
    
    void emotion_monitoring_loop() {
        while (monitoring_active_) {
            // Continuously monitor for emotional changes
            detect_emotional_changes();
            
            // Update adaptation strategy
            update_adaptation_strategy();
            
            // Apply behavioral adaptations
            apply_behavioral_adaptations();
            
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
    
    void analyze_typing_pattern(int wpm) {
        if (wpm < 20) {
            // Slow typing might indicate confusion or careful thinking
            update_emotional_state(Emotion::CONFUSION, 0.6f, "slow_typing");
        } else if (wpm > 80) {
            // Fast typing might indicate excitement or urgency
            update_emotional_state(Emotion::EXCITEMENT, 0.7f, "fast_typing");
        } else if (wpm > 60) {
            // Moderate-fast typing might indicate focus
            update_emotional_state(Emotion::FOCUS, 0.5f, "focused_typing");
        }
    }
    
    void analyze_mouse_behavior(const std::string& pattern) {
        if (pattern == "erratic") {
            // Erratic mouse movement might indicate frustration
            update_emotional_state(Emotion::FRUSTRATION, 0.8f, "erratic_mouse");
        } else if (pattern == "precise") {
            // Precise mouse movement might indicate focus
            update_emotional_state(Emotion::FOCUS, 0.6f, "precise_mouse");
        } else if (pattern == "hesitant") {
            // Hesitant movement might indicate uncertainty
            update_emotional_state(Emotion::ANXIETY, 0.5f, "hesitant_mouse");
        }
    }
    
    void analyze_error_patterns(int error_count) {
        if (error_count > 5) {
            // Many errors might indicate frustration
            update_emotional_state(Emotion::FRUSTRATION, 0.9f, "high_error_rate");
        } else if (error_count == 0) {
            // No errors might indicate satisfaction
            update_emotional_state(Emotion::SATISFACTION, 0.7f, "no_errors");
        }
    }
    
    void analyze_completion_behavior(bool used_completion) {
        if (used_completion) {
            // Using completions might indicate efficiency or learning
            update_emotional_state(Emotion::SATISFACTION, 0.4f, "using_completions");
        }
    }
    
    void update_emotional_state(Emotion emotion, float intensity, const std::string& context) {
        std::lock_guard<std::mutex> lock(state_mutex_);
        
        // Update emotion scores
        current_state_.emotion_scores[emotion_to_string(emotion)] = intensity;
        
        // Update primary emotion if intensity is high enough
        if (intensity > current_state_.intensity) {
            current_state_.primary_emotion = emotion;
            current_state_.intensity = intensity;
            current_state_.context = context;
            current_state_.timestamp = std::chrono::steady_clock::now();
            
            // Add trigger
            current_state_.triggers.push_back(context);
            
            // Keep only last 10 triggers
            if (current_state_.triggers.size() > 10) {
                current_state_.triggers.erase(current_state_.triggers.begin());
            }
        }
        
        // Decay intensity over time
        auto now = std::chrono::steady_clock::now();
        auto time_since_update = std::chrono::duration_cast<std::chrono::seconds>(now - current_state_.timestamp);
        if (time_since_update.count() > 30) { // 30 seconds
            current_state_.intensity *= 0.95f; // Gradual decay
        }
    }
    
    void detect_emotional_changes() {
        std::lock_guard<std::mutex> lock(state_mutex_);
        
        // Analyze recent emotional patterns
        std::string emotional_context = build_emotional_context();
        
        // Use AI to detect subtle emotional changes
        std::string prompt = "Analyze this emotional context and detect any changes in the developer's emotional state: " + emotional_context;
        std::string analysis = llm_->generate_completion(prompt);
        
        // Parse analysis for emotional indicators
        if (analysis.find("frustrated") != std::string::npos) {
            update_emotional_state(Emotion::FRUSTRATION, 0.7f, "ai_detected_frustration");
        } else if (analysis.find("excited") != std::string::npos) {
            update_emotional_state(Emotion::EXCITEMENT, 0.7f, "ai_detected_excitement");
        } else if (analysis.find("confused") != std::string::npos) {
            update_emotional_state(Emotion::CONFUSION, 0.7f, "ai_detected_confusion");
        }
    }
    
    std::string build_emotional_context() {
        std::string context = "Current emotional state: " + emotion_to_string(current_state_.primary_emotion) + 
                            " (intensity: " + std::to_string(current_state_.intensity) + ")\n";
        context += "Recent triggers: ";
        for (const auto& trigger : current_state_.triggers) {
            context += trigger + "; ";
        }
        context += "\nEmotion scores: ";
        for (const auto& [emotion, score] : current_state_.emotion_scores) {
            context += emotion + ":" + std::to_string(score) + "; ";
        }
        return context;
    }
    
    void update_adaptation_strategy() {
        std::lock_guard<std::mutex> lock(strategy_mutex_);
        
        // Generate adaptation strategy based on current emotional state
        current_strategy_ = generate_adaptation_strategy(current_state_.context);
    }
    
    AdaptationStrategy generate_adaptation_strategy(const std::string& context) {
        AdaptationStrategy strategy;
        
        std::lock_guard<std::mutex> lock(state_mutex_);
        
        switch (current_state_.primary_emotion) {
            case Emotion::FRUSTRATION:
                strategy.recommended_tone = Tone::CALM;
                strategy.ui_style = "minimal_distraction";
                strategy.interaction_mode = "supportive";
                strategy.suggested_actions = {"offer_help", "simplify_interface", "provide_encouragement"};
                strategy.confidence = 0.9f;
                break;
                
            case Emotion::EXCITEMENT:
                strategy.recommended_tone = Tone::ENERGETIC;
                strategy.ui_style = "dynamic";
                strategy.interaction_mode = "collaborative";
                strategy.suggested_actions = {"amplify_creativity", "provide_tools", "celebrate_progress"};
                strategy.confidence = 0.8f;
                break;
                
            case Emotion::CONFUSION:
                strategy.recommended_tone = Tone::PATIENT;
                strategy.ui_style = "clear_guidance";
                strategy.interaction_mode = "explanatory";
                strategy.suggested_actions = {"provide_explanations", "offer_examples", "break_down_complexity"};
                strategy.confidence = 0.9f;
                break;
                
            case Emotion::SATISFACTION:
                strategy.recommended_tone = Tone::ENCOURAGING;
                strategy.ui_style = "positive";
                strategy.interaction_mode = "reinforcing";
                strategy.suggested_actions = {"acknowledge_success", "suggest_next_steps", "maintain_momentum"};
                strategy.confidence = 0.7f;
                break;
                
            case Emotion::ANXIETY:
                strategy.recommended_tone = Tone::SUPPORTIVE;
                strategy.ui_style = "reassuring";
                strategy.interaction_mode = "comforting";
                strategy.suggested_actions = {"reduce_complexity", "provide_reassurance", "offer_guidance"};
                strategy.confidence = 0.8f;
                break;
                
            case Emotion::FOCUS:
                strategy.recommended_tone = Tone::ANALYTICAL;
                strategy.ui_style = "efficient";
                strategy.interaction_mode = "minimal_interruption";
                strategy.suggested_actions = {"maintain_flow", "provide_relevant_info", "avoid_distractions"};
                strategy.confidence = 0.8f;
                break;
                
            case Emotion::BOREDOM:
                strategy.recommended_tone = Tone::PLAYFUL;
                strategy.ui_style = "engaging";
                strategy.interaction_mode = "stimulating";
                strategy.suggested_actions = {"suggest_challenges", "introduce_variety", "gamify_tasks"};
                strategy.confidence = 0.7f;
                break;
                
            case Emotion::CREATIVITY:
                strategy.recommended_tone = Tone::INSPIRING;
                strategy.ui_style = "creative";
                strategy.interaction_mode = "brainstorming";
                strategy.suggested_actions = {"provide_inspiration", "suggest_alternatives", "encourage_experimentation"};
                strategy.confidence = 0.8f;
                break;
                
            case Emotion::DETERMINATION:
                strategy.recommended_tone = Tone::URGENT;
                strategy.ui_style = "goal_oriented";
                strategy.interaction_mode = "efficient";
                strategy.suggested_actions = {"remove_obstacles", "provide_tools", "maintain_momentum"};
                strategy.confidence = 0.9f;
                break;
                
            default: // NEUTRAL
                strategy.recommended_tone = Tone::SUPPORTIVE;
                strategy.ui_style = "balanced";
                strategy.interaction_mode = "adaptive";
                strategy.suggested_actions = {"observe", "be_ready", "maintain_balance"};
                strategy.confidence = 0.5f;
                break;
        }
        
        return strategy;
    }
    
    void apply_behavioral_adaptations() {
        std::lock_guard<std::mutex> lock(strategy_mutex_);
        
        // Apply UI adaptations
        UIHooks::get_instance().set_tone(current_strategy_.recommended_tone);
        UIHooks::get_instance().set_ui_style(current_strategy_.ui_style);
        
        // Apply interaction mode
        UIHooks::get_instance().set_interaction_mode(current_strategy_.interaction_mode);
        
        // Execute suggested actions
        for (const auto& action : current_strategy_.suggested_actions) {
            execute_adaptation_action(action);
        }
    }
    
    void execute_adaptation_action(const std::string& action) {
        if (action == "offer_help") {
            UIHooks::get_instance().show_helpful_suggestion("I'm here to help. What would you like assistance with?");
        } else if (action == "simplify_interface") {
            UIHooks::get_instance().simplify_interface();
        } else if (action == "provide_encouragement") {
            UIHooks::get_instance().show_encouraging_message("You're doing great! Take your time.");
        } else if (action == "amplify_creativity") {
            UIHooks::get_instance().show_creative_suggestions();
        } else if (action == "provide_explanations") {
            UIHooks::get_instance().show_explanatory_tooltips();
        } else if (action == "acknowledge_success") {
            UIHooks::get_instance().show_success_indicator("Well done!");
        } else if (action == "reduce_complexity") {
            UIHooks::get_instance().hide_advanced_features();
        } else if (action == "maintain_flow") {
            UIHooks::get_instance().minimize_interruptions();
        } else if (action == "suggest_challenges") {
            UIHooks::get_instance().show_challenge_suggestions();
        } else if (action == "provide_inspiration") {
            UIHooks::get_instance().show_inspiration_panel();
        } else if (action == "remove_obstacles") {
            UIHooks::get_instance().highlight_obstacles();
        }
    }
    
    std::string emotion_to_string(Emotion emotion) {
        switch (emotion) {
            case Emotion::NEUTRAL: return "neutral";
            case Emotion::FRUSTRATION: return "frustration";
            case Emotion::EXCITEMENT: return "excitement";
            case Emotion::CONFUSION: return "confusion";
            case Emotion::SATISFACTION: return "satisfaction";
            case Emotion::ANXIETY: return "anxiety";
            case Emotion::FOCUS: return "focus";
            case Emotion::BOREDOM: return "boredom";
            case Emotion::CREATIVITY: return "creativity";
            case Emotion::DETERMINATION: return "determination";
            default: return "unknown";
        }
    }
    
    // Member variables
    CompletionModel* llm_;
    
    EmotionalState current_state_;
    AdaptationStrategy current_strategy_;
    
    std::mutex state_mutex_;
    std::mutex strategy_mutex_;
    
    std::atomic<bool> monitoring_active_;
    std::thread monitoring_thread_;
};

} // namespace EI
} // namespace IDE_AI
