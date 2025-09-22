// Translates natural language commands into structured distractions for the AI
#include <iostream>
#include <string>
#include <memory>
#include <vector>
#include <map>

namespace NLP {

class NaturalLanguageToDistraction {
public:
    NaturalLanguageToDistraction(IDE_AI::Cognitive::StateManager* state_manager, IDE_AI::CompletionModel* llm)
        : state_manager_(state_manager), llm_(llm) {}
    
    void process_user_input(const std::string& user_input) {
        // Use the LLM to interpret the user's intent
        std::string intent = llm_->generateCompletion("What is the user's core intent? " + user_input);
        
        if (intent.find("refactor") != std::string::npos) {
            state_manager_->add_distraction({
                "user_command", 
                "User requested a refactor. Context: " + user_input,
                0.9f
            });
        } else if (intent.find("explain") != std::string::npos) {
            state_manager_->add_distraction({
                "user_command",
                "User wants an explanation. Context: " + user_input,
                0.8f
            });
        } else if (intent.find("debug") != std::string::npos) {
            state_manager_->add_distraction({
                "user_command",
                "User wants to debug. Context: " + user_input,
                0.9f
            });
        } else if (intent.find("test") != std::string::npos) {
            state_manager_->add_distraction({
                "user_command",
                "User wants to add tests. Context: " + user_input,
                0.7f
            });
        } else if (intent.find("optimize") != std::string::npos) {
            state_manager_->add_distraction({
                "user_command",
                "User wants to optimize. Context: " + user_input,
                0.8f
            });
        } else {
            // Default to general assistance
            state_manager_->add_distraction({
                "user_command",
                "User needs general assistance. Context: " + user_input,
                0.6f
            });
        }
    }
    
    // Process specific command types
    void process_refactor_command(const std::string& code_context) {
        state_manager_->add_distraction({
            "refactor_command",
            "Refactor this code: " + code_context,
            0.9f
        });
    }
    
    void process_explain_command(const std::string& code_context) {
        state_manager_->add_distraction({
            "explain_command",
            "Explain this code: " + code_context,
            0.8f
        });
    }
    
    void process_debug_command(const std::string& code_context) {
        state_manager_->add_distraction({
            "debug_command",
            "Debug this code: " + code_context,
            0.9f
        });
    }
    
    void process_test_command(const std::string& code_context) {
        state_manager_->add_distraction({
            "test_command",
            "Add tests for this code: " + code_context,
            0.7f
        });
    }
    
    void process_optimize_command(const std::string& code_context) {
        state_manager_->add_distraction({
            "optimize_command",
            "Optimize this code: " + code_context,
            0.8f
        });
    }
    
private:
    IDE_AI::Cognitive::StateManager* state_manager_;
    IDE_AI::CompletionModel* llm_;
};

} // namespace NLP