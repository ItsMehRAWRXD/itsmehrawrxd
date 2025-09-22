#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>

// Forward declarations
namespace IDE_AI {
    class ProjectKnowledgeGraph;
}

namespace LanguageCore {
    class ULR;
}

namespace Toolchain {

// Adaptive Compiler - AI-powered compiler that adapts to any programming language
class AdaptiveCompiler {
public:
    AdaptiveCompiler(IDE_AI::ProjectKnowledgeGraph* pkg = nullptr, IDE_AI::ProjectKnowledgeGraph* knowledge_graph = nullptr);
    virtual ~AdaptiveCompiler() = default;
    
    // Main compilation method
    virtual std::string compile(const std::string& source_code, const std::string& target_language = "assembly") = 0;
    
    // Language identification and learning
    virtual std::string identify_language(const std::string& source_code) = 0;
    virtual void learn_language(const std::string& language_name, const std::string& sample_code) = 0;
    
    // Code transformation
    virtual LanguageCore::ULR parse_to_ulr(const std::string& source_code) = 0;
    virtual std::string generate_target_code(const LanguageCore::ULR& ulr, const std::string& target_language) = 0;
    
    // Optimization
    virtual std::string optimize_code(const std::string& source_code, const std::string& optimization_goal) = 0;
    virtual std::string apply_optimizations(const LanguageCore::ULR& ulr, const std::vector<std::string>& optimizations) = 0;
    
    // Analysis
    virtual std::map<std::string, std::string> analyze_code(const std::string& source_code) = 0;
    virtual std::vector<std::string> find_issues(const std::string& source_code) = 0;
    virtual std::string suggest_improvements(const std::string& source_code) = 0;
    
    // Utility methods
    virtual std::vector<std::string> get_supported_languages() = 0;
    virtual bool supports_language(const std::string& language) = 0;
    virtual void add_language_support(const std::string& language, const std::string& grammar_file) = 0;

private:
    IDE_AI::ProjectKnowledgeGraph* pkg_;
    IDE_AI::ProjectKnowledgeGraph* knowledge_graph_;
};

} // namespace Toolchain
