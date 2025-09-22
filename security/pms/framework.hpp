#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>

// Forward declarations
namespace Toolchain {
    class AdaptiveCompiler;
}

namespace IDE_AI {
    namespace Cognitive {
        class CognitiveArchitecture;
    }
}

namespace LanguageCore {
    class ULR;
}

namespace Security {
namespace PMS {

// Provable Memory Safety (PMS) Framework
class VerificationEngine {
public:
    VerificationEngine(Toolchain::AdaptiveCompiler* compiler, IDE_AI::Cognitive::CognitiveArchitecture* ca);
    virtual ~VerificationEngine() = default;
    
    // Main verification method
    virtual struct ProofResult verify(const std::string& component_source_code) = 0;
    
    // Verification operations
    virtual bool verify_memory_safety(const std::string& code) = 0;
    virtual bool verify_buffer_bounds(const std::string& code) = 0;
    virtual bool verify_null_pointer_safety(const std::string& code) = 0;
    virtual bool verify_memory_leak_safety(const std::string& code) = 0;
    
    // Formal verification
    virtual std::string generate_formal_model(const LanguageCore::ULR& ulr) = 0;
    virtual bool run_proof_checker(const std::string& model, const std::string& analysis) = 0;
    virtual std::string verify_properties(const std::string& model, const std::vector<std::string>& properties) = 0;
    
    // Analysis and reporting
    virtual std::vector<std::string> find_memory_vulnerabilities(const std::string& code) = 0;
    virtual std::string generate_verification_report(const std::string& code) = 0;
    virtual std::map<std::string, bool> check_safety_properties(const std::string& code) = 0;

private:
    Toolchain::AdaptiveCompiler* compiler_;
    IDE_AI::Cognitive::CognitiveArchitecture* ca_;
};

// Proof result structure
struct ProofResult {
    bool is_safe;
    std::string proof_details;
    std::vector<std::string> vulnerabilities_found;
    std::map<std::string, bool> property_checks;
    std::chrono::steady_clock::time_point verification_time;
    
    ProofResult() : is_safe(false) {
        verification_time = std::chrono::steady_clock::now();
    }
};

} // namespace PMS
} // namespace Security
