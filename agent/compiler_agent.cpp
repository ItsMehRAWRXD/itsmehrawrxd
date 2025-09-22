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
#include "../agent/acp.hpp"
#include "compiler_agent.hpp"
#include "../ai/ai_core_hybrid.hpp"

namespace Agents {

// Compilation intent analysis
struct CompilationIntent {
    std::string primary_goal;  // e.g., "optimize_for_speed", "minimize_size", "debug_friendly"
    std::string target_platform;  // e.g., "x86_64", "arm64", "web"
    std::string optimization_level;  // e.g., "none", "basic", "aggressive"
    std::vector<std::string> specific_requirements;  // e.g., "no_stdlib", "thread_safe"
    float confidence;
    std::chrono::steady_clock::time_point timestamp;
    
    CompilationIntent() : confidence(0.0f) {
        timestamp = std::chrono::steady_clock::now();
    }
};

// Compilation context
struct CompilationContext {
    std::string source_code;
    std::string language_hint;
    std::string target_language;
    CompilationIntent intent;
    std::map<std::string, std::string> environment_vars;
    std::vector<std::string> include_paths;
    std::vector<std::string> library_paths;
    std::map<std::string, std::string> compiler_flags;
    bool debug_mode;
    bool verbose_output;
    
    CompilationContext() : debug_mode(false), verbose_output(false) {}
};

// LLM-Powered Compiler Agent
class CompilerAgent : public ACP::Agent {
public:
    CompilerAgent(const std::string& name, IDE_AI::AICoreHybrid* ai_core, ProjectKnowledgeGraph* pkg) 
        : ACP::Agent(name), ai_core_(ai_core), pkg_(pkg) {
        
        // Initialize compilation queue
        compilation_queue_.reserve(1000);
        
        // Start compilation processing thread
        compilation_active_ = true;
        compilation_thread_ = std::thread(&CompilerAgent::compilation_loop, this);
        
        // Initialize adaptive compiler
        adaptive_compiler_ = std::make_unique<Toolchain::AdaptiveCompiler>(nullptr, pkg);
        
        std::cout << "LLM-Powered Compiler Agent initialized\n";
    }
    
    ~CompilerAgent() {
        compilation_active_ = false;
        if (compilation_thread_.joinable()) {
            compilation_thread_.join();
        }
    }

    void handle_message(const ACP::Message& msg) override {
        if (msg.command == "compile_request") {
            handle_compile_request(msg);
        } else if (msg.command == "compile_with_intent") {
            handle_compile_with_intent(msg);
        } else if (msg.command == "optimize_code") {
            handle_optimize_code(msg);
        } else if (msg.command == "analyze_code") {
            handle_analyze_code(msg);
        } else if (msg.command == "explain_compilation") {
            handle_explain_compilation(msg);
        } else if (msg.command == "get_compilation_stats") {
            handle_get_stats(msg);
        }
    }
    
    // Main compilation method with AI-powered intent interpretation
    void compile_with_intent(const std::string& source_code, const std::string& user_intent) {
        std::cout << "CompilerAgent: Processing compilation with intent: " << user_intent << "\n";
        
        // Step 1: Analyze user intent using AI
        CompilationIntent intent = analyze_compilation_intent(user_intent, source_code);
        
        // Step 2: Create compilation context
        CompilationContext context;
        context.source_code = source_code;
        context.intent = intent;
        context.language_hint = detect_language(source_code);
        context.target_language = determine_target_language(intent);
        
        // Step 3: Optimize compilation settings based on intent
        optimize_compilation_settings(context);
        
        // Step 4: Execute compilation
        auto result = execute_compilation(context);
        
        // Step 5: Post-process and optimize result
        auto optimized_result = post_process_compilation(result, context);
        
        // Step 6: Generate explanation
        std::string explanation = generate_compilation_explanation(context, optimized_result);
        
        std::cout << "CompilerAgent: Compilation complete. " << explanation << "\n";
    }
    
    // Get compilation statistics
    struct CompilationStats {
        int total_compilations;
        int successful_compilations;
        int failed_compilations;
        std::map<std::string, int> intent_counts;
        std::map<std::string, int> language_counts;
        float average_confidence;
        int average_compilation_time_ms;
        std::chrono::steady_clock::time_point last_compilation;
    };
    
    CompilationStats get_compilation_stats() {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        return compilation_stats_;
    }

private:
    void handle_compile_request(const ACP::Message& msg) {
        std::string source_code = msg.payload.at("source_code");
        std::string language_hint = msg.payload.at("language_hint", "");
        std::string target_language = msg.payload.at("target_language", "native");
        
        auto result = adaptive_compiler_->compile(source_code, language_hint, target_language);
        
        ACP::Message response;
        response.sender = this->name_;
        response.receiver = msg.sender;
        response.command = "compilation_result";
        response.payload["success"] = result.success ? "true" : "false";
        response.payload["error_message"] = result.error_message;
        response.payload["generated_code"] = result.generated_code;
        response.payload["language_name"] = result.language_name;
        response.payload["confidence"] = std::to_string(result.confidence);
        send_message(response);
    }
    
    void handle_compile_with_intent(const ACP::Message& msg) {
        std::string source_code = msg.payload.at("source_code");
        std::string user_intent = msg.payload.at("intent");
        
        compile_with_intent(source_code, user_intent);
        
        ACP::Message response;
        response.sender = this->name_;
        response.receiver = msg.sender;
        response.command = "compilation_with_intent_complete";
        response.payload["status"] = "success";
        send_message(response);
    }
    
    void handle_optimize_code(const ACP::Message& msg) {
        std::string source_code = msg.payload.at("source_code");
        std::string optimization_goal = msg.payload.at("optimization_goal", "performance");
        
        // Use AI to optimize the code
        std::string prompt = "Optimize this code for " + optimization_goal + ":\n\n" + source_code;
        ai_core_->generate_completion_async(prompt, IDE_AI::TaskType::Optimization, 
            [this, msg](const std::string& optimized_code) {
                ACP::Message response;
                response.sender = this->name_;
                response.receiver = msg.sender;
                response.command = "optimization_result";
                response.payload["optimized_code"] = optimized_code;
                response.payload["optimization_goal"] = msg.payload.at("optimization_goal");
                send_message(response);
            });
    }
    
    void handle_analyze_code(const ACP::Message& msg) {
        std::string source_code = msg.payload.at("source_code");
        
        // Use AI to analyze the code
        std::string prompt = "Analyze this code and provide insights about:\n";
        prompt += "1. Code quality and potential issues\n";
        prompt += "2. Performance bottlenecks\n";
        prompt += "3. Security vulnerabilities\n";
        prompt += "4. Optimization opportunities\n\n";
        prompt += source_code;
        
        ai_core_->generate_completion_async(prompt, IDE_AI::TaskType::CodeAnalysis,
            [this, msg](const std::string& analysis) {
                ACP::Message response;
                response.sender = this->name_;
                response.receiver = msg.sender;
                response.command = "code_analysis_result";
                response.payload["analysis"] = analysis;
                send_message(response);
            });
    }
    
    void handle_explain_compilation(const ACP::Message& msg) {
        std::string source_code = msg.payload.at("source_code");
        std::string compilation_result = msg.payload.at("compilation_result", "");
        
        std::string prompt = "Explain this compilation process:\n\n";
        prompt += "Source code:\n" + source_code + "\n\n";
        if (!compilation_result.empty()) {
            prompt += "Compilation result:\n" + compilation_result + "\n\n";
        }
        prompt += "Provide a detailed explanation of what happened during compilation.";
        
        ai_core_->generate_completion_async(prompt, IDE_AI::TaskType::Reasoning,
            [this, msg](const std::string& explanation) {
                ACP::Message response;
                response.sender = this->name_;
                response.receiver = msg.sender;
                response.command = "compilation_explanation";
                response.payload["explanation"] = explanation;
                send_message(response);
            });
    }
    
    void handle_get_stats(const ACP::Message& msg) {
        auto stats = get_compilation_stats();
        
        ACP::Message response;
        response.sender = this->name_;
        response.receiver = msg.sender;
        response.command = "compilation_stats";
        response.payload["total_compilations"] = std::to_string(stats.total_compilations);
        response.payload["successful_compilations"] = std::to_string(stats.successful_compilations);
        response.payload["failed_compilations"] = std::to_string(stats.failed_compilations);
        response.payload["average_confidence"] = std::to_string(stats.average_confidence);
        response.payload["average_compilation_time_ms"] = std::to_string(stats.average_compilation_time_ms);
        send_message(response);
    }
    
    CompilationIntent analyze_compilation_intent(const std::string& user_intent, const std::string& source_code) {
        CompilationIntent intent;
        
        // Use AI to analyze the user's intent
        std::string prompt = "Analyze this compilation request and extract the intent:\n\n";
        prompt += "User request: " + user_intent + "\n\n";
        prompt += "Source code (first 500 chars): " + source_code.substr(0, 500) + "\n\n";
        prompt += "Extract:\n";
        prompt += "1. Primary goal (optimize_for_speed, minimize_size, debug_friendly, etc.)\n";
        prompt += "2. Target platform (x86_64, arm64, web, etc.)\n";
        prompt += "3. Optimization level (none, basic, aggressive)\n";
        prompt += "4. Specific requirements (no_stdlib, thread_safe, etc.)\n";
        prompt += "5. Confidence level (0.0 to 1.0)\n";
        
        ai_core_->generate_completion_async(prompt, IDE_AI::TaskType::Reasoning,
            [&intent](const std::string& analysis) {
                // Parse the AI analysis to extract intent
                parse_intent_analysis(analysis, intent);
            });
        
        return intent;
    }
    
    static void parse_intent_analysis(const std::string& analysis, CompilationIntent& intent) {
        // Simple parsing - in a real implementation, this would be more sophisticated
        std::string lower_analysis = analysis;
        std::transform(lower_analysis.begin(), lower_analysis.end(), lower_analysis.begin(), ::tolower);
        
        // Extract primary goal
        if (lower_analysis.find("speed") != std::string::npos || lower_analysis.find("performance") != std::string::npos) {
            intent.primary_goal = "optimize_for_speed";
        } else if (lower_analysis.find("size") != std::string::npos || lower_analysis.find("small") != std::string::npos) {
            intent.primary_goal = "minimize_size";
        } else if (lower_analysis.find("debug") != std::string::npos) {
            intent.primary_goal = "debug_friendly";
        } else {
            intent.primary_goal = "balanced";
        }
        
        // Extract target platform
        if (lower_analysis.find("x86") != std::string::npos) {
            intent.target_platform = "x86_64";
        } else if (lower_analysis.find("arm") != std::string::npos) {
            intent.target_platform = "arm64";
        } else if (lower_analysis.find("web") != std::string::npos) {
            intent.target_platform = "web";
        } else {
            intent.target_platform = "native";
        }
        
        // Extract optimization level
        if (lower_analysis.find("aggressive") != std::string::npos) {
            intent.optimization_level = "aggressive";
        } else if (lower_analysis.find("basic") != std::string::npos) {
            intent.optimization_level = "basic";
        } else {
            intent.optimization_level = "balanced";
        }
        
        // Extract specific requirements
        if (lower_analysis.find("no_stdlib") != std::string::npos) {
            intent.specific_requirements.push_back("no_stdlib");
        }
        if (lower_analysis.find("thread_safe") != std::string::npos) {
            intent.specific_requirements.push_back("thread_safe");
        }
        if (lower_analysis.find("memory_safe") != std::string::npos) {
            intent.specific_requirements.push_back("memory_safe");
        }
        
        // Extract confidence
        intent.confidence = 0.8f; // Default confidence
        if (lower_analysis.find("high") != std::string::npos) {
            intent.confidence = 0.9f;
        } else if (lower_analysis.find("low") != std::string::npos) {
            intent.confidence = 0.6f;
        }
    }
    
    std::string detect_language(const std::string& source_code) {
        // Use the adaptive compiler's language detection
        auto analysis = adaptive_compiler_->analyze_language(source_code);
        return analysis.language_name;
    }
    
    std::string determine_target_language(const CompilationIntent& intent) {
        if (intent.target_platform == "web") {
            return "JavaScript";
        } else if (intent.target_platform == "arm64") {
            return "ARM64";
        } else {
            return "native";
        }
    }
    
    void optimize_compilation_settings(CompilationContext& context) {
        // Optimize compiler flags based on intent
        if (context.intent.primary_goal == "optimize_for_speed") {
            context.compiler_flags["optimization"] = "-O3";
            context.compiler_flags["inline"] = "-finline-functions";
        } else if (context.intent.primary_goal == "minimize_size") {
            context.compiler_flags["optimization"] = "-Os";
            context.compiler_flags["strip"] = "-s";
        } else if (context.intent.primary_goal == "debug_friendly") {
            context.compiler_flags["debug"] = "-g";
            context.compiler_flags["optimization"] = "-O0";
        }
        
        // Add platform-specific flags
        if (context.intent.target_platform == "x86_64") {
            context.compiler_flags["target"] = "-march=x86-64";
        } else if (context.intent.target_platform == "arm64") {
            context.compiler_flags["target"] = "-march=armv8-a";
        }
        
        // Add requirement-specific flags
        for (const auto& requirement : context.intent.specific_requirements) {
            if (requirement == "no_stdlib") {
                context.compiler_flags["nostdlib"] = "-nostdlib";
            } else if (requirement == "thread_safe") {
                context.compiler_flags["thread_safe"] = "-pthread";
            }
        }
    }
    
    Toolchain::CompilationResult execute_compilation(const CompilationContext& context) {
        auto start_time = std::chrono::steady_clock::now();
        
        // Execute compilation using adaptive compiler
        auto result = adaptive_compiler_->compile(context.source_code, context.language_hint, context.target_language);
        
        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        // Update statistics
        update_compilation_stats(result, duration.count());
        
        return result;
    }
    
    Toolchain::CompilationResult post_process_compilation(const Toolchain::CompilationResult& result, const CompilationContext& context) {
        if (!result.success) {
            return result;
        }
        
        // Use AI to post-process and optimize the result
        std::string prompt = "Post-process and optimize this compilation result:\n\n";
        prompt += "Original code:\n" + context.source_code + "\n\n";
        prompt += "Generated code:\n" + result.generated_code + "\n\n";
        prompt += "Intent: " + context.intent.primary_goal + "\n";
        prompt += "Target platform: " + context.intent.target_platform + "\n";
        prompt += "Optimize the generated code according to the intent.";
        
        // This would be implemented as an async call in a real system
        // For now, return the original result
        return result;
    }
    
    std::string generate_compilation_explanation(const CompilationContext& context, const Toolchain::CompilationResult& result) {
        std::string explanation = "Compilation completed successfully.\n";
        explanation += "Language: " + result.language_name + "\n";
        explanation += "Intent: " + context.intent.primary_goal + "\n";
        explanation += "Target: " + context.intent.target_platform + "\n";
        explanation += "Confidence: " + std::to_string(result.confidence) + "\n";
        
        return explanation;
    }
    
    void compilation_loop() {
        while (compilation_active_) {
            // Process compilation queue
            process_compilation_queue();
            
            // Update statistics
            update_statistics();
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    void process_compilation_queue() {
        std::lock_guard<std::mutex> lock(compilation_queue_mutex_);
        while (!compilation_queue_.empty()) {
            auto task = compilation_queue_.front();
            compilation_queue_.pop();
            
            // Process the compilation task
            compile_with_intent(task.source_code, task.user_intent);
        }
    }
    
    void update_compilation_stats(const Toolchain::CompilationResult& result, int compilation_time_ms) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        
        compilation_stats_.total_compilations++;
        if (result.success) {
            compilation_stats_.successful_compilations++;
        } else {
            compilation_stats_.failed_compilations++;
        }
        
        compilation_stats_.language_counts[result.language_name]++;
        compilation_stats_.average_confidence = (compilation_stats_.average_confidence + result.confidence) / 2.0f;
        compilation_stats_.average_compilation_time_ms = (compilation_stats_.average_compilation_time_ms + compilation_time_ms) / 2;
        compilation_stats_.last_compilation = std::chrono::steady_clock::now();
    }
    
    void update_statistics() {
        // Update statistics periodically
        std::lock_guard<std::mutex> lock(stats_mutex_);
        
        if (compilation_stats_.total_compilations > 0) {
            float success_rate = (float)compilation_stats_.successful_compilations / compilation_stats_.total_compilations;
            if (success_rate < 0.8f) {
                std::cout << "Warning: Low compilation success rate: " << (success_rate * 100) << "%\n";
            }
        }
    }
    
    // Data structures
    struct CompilationTask {
        std::string source_code;
        std::string user_intent;
        std::chrono::steady_clock::time_point timestamp;
    };
    
    // Member variables
    IDE_AI::AICoreHybrid* ai_core_;
    ProjectKnowledgeGraph* pkg_;
    std::unique_ptr<Toolchain::AdaptiveCompiler> adaptive_compiler_;
    
    std::queue<CompilationTask> compilation_queue_;
    CompilationStats compilation_stats_;
    
    std::mutex compilation_queue_mutex_;
    std::mutex stats_mutex_;
    
    std::atomic<bool> compilation_active_;
    std::thread compilation_thread_;
};

} // namespace Agents
