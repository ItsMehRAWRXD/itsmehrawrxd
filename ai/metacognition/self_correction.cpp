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
#include "../../ai/model_layer.hpp"
#include "../../ai/reasoning/project_knowledge_graph.cpp"
#include "../../agent/acp.hpp"

namespace IDE_AI {
namespace Metacognition {

// Reasoning path analysis
struct ReasoningPath {
    std::string id;
    std::vector<std::string> steps;
    std::string conclusion;
    std::chrono::steady_clock::time_point timestamp;
    float confidence;
    std::map<std::string, std::string> metadata;
};

// Self-correction analysis
struct CorrectionAnalysis {
    std::string reasoning_path_id;
    std::string critique;
    std::vector<std::string> identified_flaws;
    std::string corrected_path;
    float improvement_score;
    std::chrono::steady_clock::time_point timestamp;
};

// Metacognitive insights
struct MetacognitiveInsight {
    std::string insight_type;
    std::string description;
    std::string recommendation;
    float confidence;
    std::chrono::steady_clock::time_point timestamp;
};

// Metacognitive Self-Correction Module
class SelfCorrectionModule : public ACP::Agent {
public:
    SelfCorrectionModule(CompletionModel* llm, ProjectKnowledgeGraph* pkg)
        : ACP::Agent("metacognition_module"), llm_(llm), pkg_(pkg) {
        
        // Initialize reasoning tracking
        reasoning_paths_.reserve(1000);
        corrections_.reserve(500);
        insights_.reserve(200);
        
        // Start metacognitive monitoring thread
        monitoring_active_ = true;
        monitoring_thread_ = std::thread(&SelfCorrectionModule::metacognitive_loop, this);
        
        std::cout << "Metacognitive Self-Correction Module initialized\n";
    }
    
    ~SelfCorrectionModule() {
        monitoring_active_ = false;
        if (monitoring_thread_.joinable()) {
            monitoring_thread_.join();
        }
    }

    void handle_message(const ACP::Message& msg) override {
        if (msg.command == "reasoning_path") {
            std::string path_id = msg.payload.at("path_id");
            std::string steps = msg.payload.at("steps");
            std::string conclusion = msg.payload.at("conclusion");
            float confidence = std::stof(msg.payload.at("confidence"));
            
            ReasoningPath path;
            path.id = path_id;
            path.conclusion = conclusion;
            path.confidence = confidence;
            path.timestamp = std::chrono::steady_clock::now();
            
            // Parse steps
            std::stringstream ss(steps);
            std::string step;
            while (std::getline(ss, step, '|')) {
                path.steps.push_back(step);
            }
            
            add_reasoning_path(path);
        } else if (msg.command == "self_correction_request") {
            std::string path_id = msg.payload.at("path_id");
            auto correction = perform_self_correction(path_id);
            
            ACP::Message response;
            response.sender = this->name_;
            response.receiver = msg.sender;
            response.command = "correction_result";
            response.payload["path_id"] = path_id;
            response.payload["critique"] = correction.critique;
            response.payload["corrected_path"] = correction.corrected_path;
            response.payload["improvement_score"] = std::to_string(correction.improvement_score);
            send_message(response);
        }
    }
    
    // Review a reasoning path for flaws
    void review_reasoning_path(const std::string& reasoning_path) {
        std::string prompt = "Critically analyze the following reasoning path for flaws, logical inconsistencies, or better alternatives: " + reasoning_path;
        std::string critique = llm_->generate_completion(prompt);
        
        if (critique.find("flaw") != std::string::npos || critique.find("inconsistency") != std::string::npos) {
            std::string correction_prompt = "Based on the critique, generate a new, corrected reasoning path. Critique: " + critique;
            std::string new_path = llm_->generate_completion(correction_prompt);
            
            // Log the self-correction for future learning
            CorrectionAnalysis correction;
            correction.reasoning_path_id = "path_" + std::to_string(std::rand());
            correction.critique = critique;
            correction.corrected_path = new_path;
            correction.improvement_score = calculate_improvement_score(reasoning_path, new_path);
            correction.timestamp = std::chrono::steady_clock::now();
            
            add_correction(correction);
            
            // Add to knowledge graph
            pkg_->add_node({"metacognitive_correction_" + correction.reasoning_path_id, 
                           "metacognitive_correction", 
                           {{"original_path", reasoning_path}, 
                            {"new_path", new_path}, 
                            {"critique", critique},
                            {"improvement_score", std::to_string(correction.improvement_score)}}});
        }
    }
    
    // Get latest metacognitive insights
    std::vector<MetacognitiveInsight> get_latest_insights() {
        std::lock_guard<std::mutex> lock(insights_mutex_);
        return insights_;
    }
    
    // Get correction history
    std::vector<CorrectionAnalysis> get_correction_history() {
        std::lock_guard<std::mutex> lock(corrections_mutex_);
        return corrections_;
    }

private:
    void metacognitive_loop() {
        while (monitoring_active_) {
            // Analyze recent reasoning paths
            analyze_reasoning_patterns();
            
            // Generate metacognitive insights
            generate_metacognitive_insights();
            
            // Update self-awareness
            update_self_awareness();
            
            // Learn from corrections
            learn_from_corrections();
            
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
    
    void add_reasoning_path(const ReasoningPath& path) {
        std::lock_guard<std::mutex> lock(reasoning_paths_mutex_);
        reasoning_paths_.push_back(path);
        
        // Keep only last 1000 reasoning paths
        if (reasoning_paths_.size() > 1000) {
            reasoning_paths_.erase(reasoning_paths_.begin());
        }
        
        // Trigger immediate review for low-confidence paths
        if (path.confidence < 0.7f) {
            std::string path_string = build_path_string(path);
            review_reasoning_path(path_string);
        }
    }
    
    void add_correction(const CorrectionAnalysis& correction) {
        std::lock_guard<std::mutex> lock(corrections_mutex_);
        corrections_.push_back(correction);
        
        // Keep only last 500 corrections
        if (corrections_.size() > 500) {
            corrections_.erase(corrections_.begin());
        }
    }
    
    std::string build_path_string(const ReasoningPath& path) {
        std::string path_string = "Reasoning Path ID: " + path.id + "\n";
        path_string += "Steps:\n";
        for (size_t i = 0; i < path.steps.size(); ++i) {
            path_string += std::to_string(i + 1) + ". " + path.steps[i] + "\n";
        }
        path_string += "Conclusion: " + path.conclusion + "\n";
        path_string += "Confidence: " + std::to_string(path.confidence);
        return path_string;
    }
    
    CorrectionAnalysis perform_self_correction(const std::string& path_id) {
        std::lock_guard<std::mutex> lock(reasoning_paths_mutex_);
        
        // Find the reasoning path
        auto it = std::find_if(reasoning_paths_.begin(), reasoning_paths_.end(),
                              [&path_id](const ReasoningPath& path) { return path.id == path_id; });
        
        if (it != reasoning_paths_.end()) {
            std::string path_string = build_path_string(*it);
            review_reasoning_path(path_string);
            
            // Return the latest correction
            std::lock_guard<std::mutex> lock_corrections(corrections_mutex_);
            if (!corrections_.empty()) {
                return corrections_.back();
            }
        }
        
        // Return empty correction if not found
        CorrectionAnalysis empty_correction;
        empty_correction.reasoning_path_id = path_id;
        empty_correction.critique = "No reasoning path found";
        empty_correction.corrected_path = "";
        empty_correction.improvement_score = 0.0f;
        return empty_correction;
    }
    
    void analyze_reasoning_patterns() {
        std::lock_guard<std::mutex> lock(reasoning_paths_mutex_);
        
        if (reasoning_paths_.empty()) return;
        
        // Analyze recent reasoning patterns
        std::map<std::string, int> step_patterns;
        std::map<std::string, float> confidence_patterns;
        
        // Look at last 50 reasoning paths
        int start_idx = std::max(0, (int)reasoning_paths_.size() - 50);
        for (int i = start_idx; i < reasoning_paths_.size(); ++i) {
            const auto& path = reasoning_paths_[i];
            
            // Count step patterns
            for (const auto& step : path.steps) {
                step_patterns[step]++;
            }
            
            // Track confidence patterns
            std::string confidence_range = get_confidence_range(path.confidence);
            confidence_patterns[confidence_range]++;
        }
        
        // Identify problematic patterns
        identify_problematic_patterns(step_patterns, confidence_patterns);
    }
    
    std::string get_confidence_range(float confidence) {
        if (confidence < 0.3f) return "low";
        else if (confidence < 0.7f) return "medium";
        else return "high";
    }
    
    void identify_problematic_patterns(const std::map<std::string, int>& step_patterns,
                                     const std::map<std::string, float>& confidence_patterns) {
        // Identify frequently used but potentially flawed reasoning steps
        for (const auto& [step, count] : step_patterns) {
            if (count > 10) { // Frequently used step
                std::string prompt = "Analyze this frequently used reasoning step for potential flaws: " + step;
                std::string analysis = llm_->generate_completion(prompt);
                
                if (analysis.find("flaw") != std::string::npos || analysis.find("problem") != std::string::npos) {
                    // Create insight about problematic pattern
                    MetacognitiveInsight insight;
                    insight.insight_type = "problematic_pattern";
                    insight.description = "Frequently used reasoning step may be flawed: " + step;
                    insight.recommendation = "Consider alternative approaches: " + analysis;
                    insight.confidence = 0.8f;
                    insight.timestamp = std::chrono::steady_clock::now();
                    
                    add_insight(insight);
                }
            }
        }
        
        // Analyze confidence patterns
        if (confidence_patterns["low"] > confidence_patterns["high"]) {
            MetacognitiveInsight insight;
            insight.insight_type = "confidence_issue";
            insight.description = "System shows low confidence in reasoning more often than high confidence";
            insight.recommendation = "Review reasoning methodology and improve confidence calibration";
            insight.confidence = 0.9f;
            insight.timestamp = std::chrono::steady_clock::now();
            
            add_insight(insight);
        }
    }
    
    void generate_metacognitive_insights() {
        // Generate insights about the system's own thinking processes
        std::string prompt = "Generate insights about the AI system's reasoning patterns and suggest improvements. Consider recent corrections and reasoning paths.";
        
        // Augment with recent data
        std::string context = build_metacognitive_context();
        std::string full_prompt = prompt + "\nContext: " + context;
        
        std::string insights = llm_->generate_completion(full_prompt);
        
        // Parse insights and create structured insight objects
        parse_and_store_insights(insights);
    }
    
    std::string build_metacognitive_context() {
        std::string context = "Recent metacognitive activity:\n";
        
        // Add recent corrections
        std::lock_guard<std::mutex> lock_corrections(corrections_mutex_);
        if (!corrections_.empty()) {
            context += "Recent corrections: " + std::to_string(corrections_.size()) + "\n";
            const auto& latest = corrections_.back();
            context += "Latest correction: " + latest.critique + "\n";
        }
        
        // Add reasoning path statistics
        std::lock_guard<std::mutex> lock_paths(reasoning_paths_mutex_);
        if (!reasoning_paths_.empty()) {
            context += "Total reasoning paths: " + std::to_string(reasoning_paths_.size()) + "\n";
            
            // Calculate average confidence
            float total_confidence = 0.0f;
            for (const auto& path : reasoning_paths_) {
                total_confidence += path.confidence;
            }
            float avg_confidence = total_confidence / reasoning_paths_.size();
            context += "Average confidence: " + std::to_string(avg_confidence) + "\n";
        }
        
        return context;
    }
    
    void parse_and_store_insights(const std::string& insights) {
        // Simple parsing - in a real implementation, this would be more sophisticated
        std::vector<std::string> insight_lines;
        std::stringstream ss(insights);
        std::string line;
        
        while (std::getline(ss, line)) {
            if (line.find("insight") != std::string::npos || line.find("recommendation") != std::string::npos) {
                MetacognitiveInsight insight;
                insight.insight_type = "general";
                insight.description = line;
                insight.recommendation = "Follow the insight";
                insight.confidence = 0.7f;
                insight.timestamp = std::chrono::steady_clock::now();
                
                add_insight(insight);
            }
        }
    }
    
    void add_insight(const MetacognitiveInsight& insight) {
        std::lock_guard<std::mutex> lock(insights_mutex_);
        insights_.push_back(insight);
        
        // Keep only last 200 insights
        if (insights_.size() > 200) {
            insights_.erase(insights_.begin());
        }
    }
    
    void update_self_awareness() {
        // Update the system's self-awareness based on recent activity
        std::string prompt = "Update the AI system's self-awareness based on recent metacognitive activity. What does the system now know about its own reasoning processes?";
        
        std::string context = build_metacognitive_context();
        std::string self_awareness_update = llm_->generate_completion(prompt + "\nContext: " + context);
        
        // Store self-awareness update in knowledge graph
        pkg_->add_node({"self_awareness_update_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()),
                       "self_awareness",
                       {{"update", self_awareness_update}, {"timestamp", std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())}}});
    }
    
    void learn_from_corrections() {
        std::lock_guard<std::mutex> lock(corrections_mutex_);
        
        if (corrections_.empty()) return;
        
        // Analyze correction patterns to improve future reasoning
        std::map<std::string, int> flaw_types;
        std::map<std::string, int> correction_types;
        
        for (const auto& correction : corrections_) {
            // Categorize flaws
            std::string flaw_type = categorize_flaw(correction.critique);
            flaw_types[flaw_type]++;
            
            // Categorize corrections
            std::string correction_type = categorize_correction(correction.corrected_path);
            correction_types[correction_type]++;
        }
        
        // Generate learning insights
        generate_learning_insights(flaw_types, correction_types);
    }
    
    std::string categorize_flaw(const std::string& critique) {
        if (critique.find("logical") != std::string::npos) return "logical_error";
        if (critique.find("assumption") != std::string::npos) return "false_assumption";
        if (critique.find("incomplete") != std::string::npos) return "incomplete_analysis";
        if (critique.find("bias") != std::string::npos) return "cognitive_bias";
        return "general_flaw";
    }
    
    std::string categorize_correction(const std::string& correction) {
        if (correction.find("alternative") != std::string::npos) return "alternative_approach";
        if (correction.find("additional") != std::string::npos) return "additional_analysis";
        if (correction.find("revised") != std::string::npos) return "revised_reasoning";
        return "general_correction";
    }
    
    void generate_learning_insights(const std::map<std::string, int>& flaw_types,
                                  const std::map<std::string, int>& correction_types) {
        // Find most common flaw types
        std::string most_common_flaw = "";
        int max_flaw_count = 0;
        for (const auto& [flaw, count] : flaw_types) {
            if (count > max_flaw_count) {
                max_flaw_count = count;
                most_common_flaw = flaw;
            }
        }
        
        if (!most_common_flaw.empty()) {
            MetacognitiveInsight insight;
            insight.insight_type = "learning_insight";
            insight.description = "Most common reasoning flaw: " + most_common_flaw + " (occurred " + std::to_string(max_flaw_count) + " times)";
            insight.recommendation = "Focus on improving " + most_common_flaw + " detection and prevention";
            insight.confidence = 0.9f;
            insight.timestamp = std::chrono::steady_clock::now();
            
            add_insight(insight);
        }
    }
    
    float calculate_improvement_score(const std::string& original_path, const std::string& corrected_path) {
        // Simple heuristic for improvement score
        // In a real implementation, this would be more sophisticated
        
        float score = 0.0f;
        
        // Length improvement (longer doesn't always mean better, but more detailed reasoning often does)
        if (corrected_path.length() > original_path.length()) {
            score += 0.2f;
        }
        
        // Keyword analysis
        std::vector<std::string> positive_keywords = {"alternative", "consider", "analyze", "evaluate", "verify"};
        for (const auto& keyword : positive_keywords) {
            if (corrected_path.find(keyword) != std::string::npos) {
                score += 0.1f;
            }
        }
        
        // Cap at 1.0
        return std::min(1.0f, score);
    }
    
    // Member variables
    CompletionModel* llm_;
    ProjectKnowledgeGraph* pkg_;
    
    std::vector<ReasoningPath> reasoning_paths_;
    std::vector<CorrectionAnalysis> corrections_;
    std::vector<MetacognitiveInsight> insights_;
    
    std::mutex reasoning_paths_mutex_;
    std::mutex corrections_mutex_;
    std::mutex insights_mutex_;
    
    std::atomic<bool> monitoring_active_;
    std::thread monitoring_thread_;
};

} // namespace Metacognition
} // namespace IDE_AI
