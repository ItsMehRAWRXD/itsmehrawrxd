#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include "model_layer.hpp"
#include "ide-vdb.hpp"

namespace IDE_AI {

// Represents a code change for review
struct CodeChange {
    std::string file_path;
    std::string old_content;
    std::string new_content;
    std::string diff;
    std::string commit_hash;
    std::string author;
    std::string timestamp;
};

// Represents a review comment
struct ReviewComment {
    std::string file_path;
    int line_number;
    std::string comment;
    std::string severity; // "info", "warning", "error"
    std::string category; // "style", "bug", "performance", "security"
    std::string suggestion;
};

// Represents a code review result
struct ReviewResult {
    std::vector<ReviewComment> comments;
    std::string overall_summary;
    double quality_score;
    std::vector<std::string> recommendations;
};

class AICodeReviewer {
public:
    AICodeReviewer(std::shared_ptr<CompletionModel> ai_model, std::shared_ptr<VectorDatabase> vdb)
        : ai_model_(ai_model), vdb_(vdb) {}
        
    ReviewResult review_changes(const std::vector<CodeChange>& changes) {
        ReviewResult result;
        result.quality_score = 0.0;
        
        std::cout << "Starting AI code review for " << changes.size() << " changes...\n";
        
        for (const auto& change : changes) {
            std::cout << "Reviewing changes in " << change.file_path << "\n";
            
            auto file_comments = review_single_change(change);
            result.comments.insert(result.comments.end(), file_comments.begin(), file_comments.end());
        }
        
        // Generate overall summary
        result.overall_summary = generate_overall_summary(changes, result.comments);
        result.quality_score = calculate_quality_score(result.comments);
        result.recommendations = generate_recommendations(result.comments);
        
        return result;
    }
    
    ReviewResult review_file(const std::string& file_path) {
        std::cout << "Reviewing file: " << file_path << "\n";
        
        std::ifstream file(file_path);
        if (!file.is_open()) {
            std::cerr << "Error: Could not open file " << file_path << "\n";
            return ReviewResult{};
        }
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string content = buffer.str();
        
        CodeChange change;
        change.file_path = file_path;
        change.new_content = content;
        change.diff = content; // For file review, the entire content is the "diff"
        
        return review_changes({change});
    }
    
    void review_commit(const std::string& commit_hash) {
        std::cout << "Reviewing commit: " << commit_hash << "\n";
        
        // In a real implementation, this would interface with a VCS system
        auto changes = get_changes_from_commit(commit_hash);
        auto result = review_changes(changes);
        
        display_review_result(result);
    }

private:
    std::vector<ReviewComment> review_single_change(const CodeChange& change) {
        std::vector<ReviewComment> comments;
        
        // Create comprehensive review prompt
        std::string prompt = "Perform a comprehensive code review for the following changes:\n\n";
        prompt += "File: " + change.file_path + "\n";
        prompt += "Changes:\n" + change.diff + "\n\n";
        prompt += "Please analyze for:\n";
        prompt += "1. Code style and formatting issues\n";
        prompt += "2. Potential bugs and logic errors\n";
        prompt += "3. Performance optimizations\n";
        prompt += "4. Security vulnerabilities\n";
        prompt += "5. Maintainability and readability\n";
        prompt += "6. Best practices adherence\n";
        prompt += "7. Test coverage considerations\n\n";
        prompt += "Provide specific line-by-line feedback with suggestions for improvement.";
        
        // Retrieve relevant code examples and standards from the vector database
        Embedding query_embedding = ai_model_->generate_embedding(change.diff);
        auto relevant_examples = vdb_->search(query_embedding, 5);
        
        std::string augmented_prompt = "Project coding standards and examples:\n";
        for (const auto& example_id : relevant_examples) {
            augmented_prompt += vdb_->get_metadata(example_id) + "\n";
        }
        augmented_prompt += "\n" + prompt;
        
        // Generate review using AI
        std::string review_text = ai_model_->generate_completion(augmented_prompt);
        
        // Parse the AI review into structured comments
        comments = parse_review_response(review_text, change.file_path);
        
        // Add additional automated checks
        auto automated_comments = perform_automated_checks(change);
        comments.insert(comments.end(), automated_comments.begin(), automated_comments.end());
        
        return comments;
    }
    
    std::vector<ReviewComment> parse_review_response(const std::string& review_text, const std::string& file_path) {
        std::vector<ReviewComment> comments;
        
        std::istringstream iss(review_text);
        std::string line;
        ReviewComment current_comment;
        bool in_comment = false;
        
        while (std::getline(iss, line)) {
            // Look for comment indicators
            if (line.find("Line ") != std::string::npos || 
                line.find("Issue:") != std::string::npos ||
                line.find("Problem:") != std::string::npos) {
                
                if (in_comment && !current_comment.comment.empty()) {
                    comments.push_back(current_comment);
                }
                
                current_comment = ReviewComment{};
                current_comment.file_path = file_path;
                current_comment.line_number = extract_line_number(line);
                current_comment.severity = "info";
                current_comment.category = "style";
                in_comment = true;
                
                // Extract the main comment
                size_t colon_pos = line.find(':');
                if (colon_pos != std::string::npos) {
                    current_comment.comment = line.substr(colon_pos + 1);
                }
            } else if (in_comment) {
                // Check for severity indicators
                if (line.find("ERROR") != std::string::npos || line.find("CRITICAL") != std::string::npos) {
                    current_comment.severity = "error";
                } else if (line.find("WARNING") != std::string::npos || line.find("WARN") != std::string::npos) {
                    current_comment.severity = "warning";
                }
                
                // Check for category indicators
                if (line.find("security") != std::string::npos || line.find("Security") != std::string::npos) {
                    current_comment.category = "security";
                } else if (line.find("performance") != std::string::npos || line.find("Performance") != std::string::npos) {
                    current_comment.category = "performance";
                } else if (line.find("bug") != std::string::npos || line.find("Bug") != std::string::npos) {
                    current_comment.category = "bug";
                }
                
                // Look for suggestions
                if (line.find("Suggestion:") != std::string::npos || line.find("Fix:") != std::string::npos) {
                    current_comment.suggestion = line;
                } else if (!current_comment.comment.empty()) {
                    current_comment.comment += " " + line;
                }
            }
        }
        
        // Add the last comment
        if (in_comment && !current_comment.comment.empty()) {
            comments.push_back(current_comment);
        }
        
        return comments;
    }
    
    int extract_line_number(const std::string& line) {
        // Extract line number from text like "Line 42:" or "Line 42 -"
        size_t line_pos = line.find("Line ");
        if (line_pos != std::string::npos) {
            size_t start = line_pos + 5;
            size_t end = line.find_first_not_of("0123456789", start);
            if (end == std::string::npos) end = line.length();
            
            std::string line_str = line.substr(start, end - start);
            return std::stoi(line_str);
        }
        return 0;
    }
    
    std::vector<ReviewComment> perform_automated_checks(const CodeChange& change) {
        std::vector<ReviewComment> comments;
        
        // Check for common issues
        std::istringstream iss(change.new_content);
        std::string line;
        int line_number = 0;
        
        while (std::getline(iss, line)) {
            line_number++;
            
            // Check for TODO/FIXME comments
            if (line.find("TODO") != std::string::npos || line.find("FIXME") != std::string::npos) {
                ReviewComment comment;
                comment.file_path = change.file_path;
                comment.line_number = line_number;
                comment.comment = "TODO/FIXME comment found: " + line;
                comment.severity = "warning";
                comment.category = "style";
                comments.push_back(comment);
            }
            
            // Check for hardcoded values
            if (line.find("\"http://") != std::string::npos || 
                line.find("\"https://") != std::string::npos ||
                line.find("password") != std::string::npos ||
                line.find("secret") != std::string::npos) {
                ReviewComment comment;
                comment.file_path = change.file_path;
                comment.line_number = line_number;
                comment.comment = "Potential hardcoded sensitive value: " + line;
                comment.severity = "warning";
                comment.category = "security";
                comment.suggestion = "Consider using environment variables or configuration files";
                comments.push_back(comment);
            }
            
            // Check for long lines
            if (line.length() > 120) {
                ReviewComment comment;
                comment.file_path = change.file_path;
                comment.line_number = line_number;
                comment.comment = "Line too long (" + std::to_string(line.length()) + " characters)";
                comment.severity = "info";
                comment.category = "style";
                comment.suggestion = "Consider breaking into multiple lines";
                comments.push_back(comment);
            }
            
            // Check for missing error handling
            if (line.find("malloc") != std::string::npos || 
                line.find("new ") != std::string::npos ||
                line.find("open(") != std::string::npos) {
                // Check if next few lines have error handling
                bool has_error_handling = false;
                std::istringstream check_stream(change.new_content);
                std::string check_line;
                int check_line_number = 0;
                
                while (std::getline(check_stream, check_line) && check_line_number < line_number + 3) {
                    check_line_number++;
                    if (check_line_number > line_number && 
                        (check_line.find("if") != std::string::npos || 
                         check_line.find("try") != std::string::npos ||
                         check_line.find("catch") != std::string::npos)) {
                        has_error_handling = true;
                        break;
                    }
                }
                
                if (!has_error_handling) {
                    ReviewComment comment;
                    comment.file_path = change.file_path;
                    comment.line_number = line_number;
                    comment.comment = "Potential missing error handling for resource allocation";
                    comment.severity = "warning";
                    comment.category = "bug";
                    comment.suggestion = "Add proper error checking and cleanup";
                    comments.push_back(comment);
                }
            }
        }
        
        return comments;
    }
    
    std::string generate_overall_summary(const std::vector<CodeChange>& changes, const std::vector<ReviewComment>& comments) {
        std::string prompt = "Generate a concise overall summary for a code review with:\n";
        prompt += "Files changed: " + std::to_string(changes.size()) + "\n";
        prompt += "Total comments: " + std::to_string(comments.size()) + "\n";
        
        // Count comments by severity
        int error_count = 0, warning_count = 0, info_count = 0;
        for (const auto& comment : comments) {
            if (comment.severity == "error") error_count++;
            else if (comment.severity == "warning") warning_count++;
            else info_count++;
        }
        
        prompt += "Errors: " + std::to_string(error_count) + "\n";
        prompt += "Warnings: " + std::to_string(warning_count) + "\n";
        prompt += "Info: " + std::to_string(info_count) + "\n";
        prompt += "Provide a brief summary of the review findings and overall code quality.";
        
        return ai_model_->generate_completion(prompt);
    }
    
    double calculate_quality_score(const std::vector<ReviewComment>& comments) {
        if (comments.empty()) return 100.0;
        
        double score = 100.0;
        
        for (const auto& comment : comments) {
            if (comment.severity == "error") score -= 10.0;
            else if (comment.severity == "warning") score -= 5.0;
            else if (comment.severity == "info") score -= 1.0;
        }
        
        return std::max(0.0, score);
    }
    
    std::vector<std::string> generate_recommendations(const std::vector<ReviewComment>& comments) {
        std::vector<std::string> recommendations;
        
        // Analyze comment patterns to generate recommendations
        std::map<std::string, int> category_counts;
        for (const auto& comment : comments) {
            category_counts[comment.category]++;
        }
        
        if (category_counts["security"] > 0) {
            recommendations.push_back("Review security-related issues and consider security audit");
        }
        
        if (category_counts["performance"] > 0) {
            recommendations.push_back("Address performance concerns and consider profiling");
        }
        
        if (category_counts["style"] > 3) {
            recommendations.push_back("Consider using automated code formatting tools");
        }
        
        if (category_counts["bug"] > 0) {
            recommendations.push_back("Add more comprehensive testing for bug-prone areas");
        }
        
        return recommendations;
    }
    
    std::vector<CodeChange> get_changes_from_commit(const std::string& commit_hash) {
        // In a real implementation, this would interface with git or other VCS
        std::vector<CodeChange> changes;
        
        // Placeholder implementation
        CodeChange change;
        change.commit_hash = commit_hash;
        change.file_path = "example.cpp";
        change.diff = "// Example diff content";
        changes.push_back(change);
        
        return changes;
    }
    
    void display_review_result(const ReviewResult& result) {
        std::cout << "\n=== CODE REVIEW RESULTS ===\n";
        std::cout << "Overall Quality Score: " << result.quality_score << "/100\n";
        std::cout << "Total Comments: " << result.comments.size() << "\n\n";
        
        std::cout << "Summary:\n" << result.overall_summary << "\n\n";
        
        if (!result.comments.empty()) {
            std::cout << "Comments:\n";
            for (const auto& comment : result.comments) {
                std::cout << "[" << comment.severity << "] " << comment.file_path 
                         << ":" << comment.line_number << " - " << comment.comment << "\n";
                if (!comment.suggestion.empty()) {
                    std::cout << "  Suggestion: " << comment.suggestion << "\n";
                }
            }
        }
        
        if (!result.recommendations.empty()) {
            std::cout << "\nRecommendations:\n";
            for (const auto& rec : result.recommendations) {
                std::cout << "- " << rec << "\n";
            }
        }
        
        std::cout << "\n========================\n";
    }
    
    std::shared_ptr<CompletionModel> ai_model_;
    std::shared_ptr<VectorDatabase> vdb_;
};

} // namespace IDE_AI
