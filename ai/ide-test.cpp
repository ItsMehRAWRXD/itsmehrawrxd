#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include "model_layer.hpp"
#include "ide-vdb.hpp"
#include "language_sdk/api.hpp"

namespace IDE_AI {

// Represents a function signature extracted from source code
struct FunctionSignature {
    std::string name;
    std::string return_type;
    std::vector<std::string> parameters;
    std::string file_path;
    int line_number;
    std::string docstring;
};

// Represents a generated test case
struct TestCase {
    std::string test_name;
    std::string test_code;
    std::string description;
    std::vector<std::string> test_data;
};

class AITestGenerator {
public:
    AITestGenerator(std::shared_ptr<CompletionModel> ai_model, std::shared_ptr<VectorDatabase> vdb)
        : ai_model_(ai_model), vdb_(vdb) {}
        
    void generate_tests(const std::string& file_path) {
        std::cout << "Generating tests for " << file_path << "...\n";
        
        // Extract function signatures from the file
        auto function_signatures = extract_function_signatures(file_path);
        
        if (function_signatures.empty()) {
            std::cout << "No functions found in " << file_path << "\n";
            return;
        }
        
        // Generate tests for each function
        for (const auto& signature : function_signatures) {
            std::cout << "Generating tests for function: " << signature.name << "\n";
            auto test_cases = generate_test_cases_for_function(signature);
            save_test_cases(test_cases, signature);
        }
        
        std::cout << "Test generation complete for " << file_path << "\n";
    }
    
    void generate_integration_tests(const std::string& project_root) {
        std::cout << "Generating integration tests for project...\n";
        
        // Find all main entry points and public APIs
        auto entry_points = find_entry_points(project_root);
        
        for (const auto& entry_point : entry_points) {
            auto integration_test = generate_integration_test_case(entry_point);
            save_integration_test(integration_test, entry_point);
        }
    }

private:
    std::vector<FunctionSignature> extract_function_signatures(const std::string& file_path) {
        std::vector<FunctionSignature> signatures;
        
        std::ifstream file(file_path);
        if (!file.is_open()) {
            std::cerr << "Error: Could not open file " << file_path << "\n";
            return signatures;
        }
        
        std::string line;
        int line_number = 0;
        std::string current_function;
        std::string current_docstring;
        
        while (std::getline(file, line)) {
            line_number++;
            
            // Look for function definitions (simplified pattern matching)
            if (line.find("FUNC ") != std::string::npos || 
                line.find("def ") != std::string::npos ||
                line.find("function ") != std::string::npos) {
                
                FunctionSignature sig;
                sig.file_path = file_path;
                sig.line_number = line_number;
                sig.docstring = current_docstring;
                
                // Parse function signature (simplified)
                if (parse_function_signature(line, sig)) {
                    signatures.push_back(sig);
                }
                
                current_docstring.clear();
            }
            // Look for docstrings/comments
            else if (line.find("//") != std::string::npos || 
                     line.find("#") != std::string::npos ||
                     line.find("/*") != std::string::npos) {
                if (!current_docstring.empty()) current_docstring += " ";
                current_docstring += line;
            }
        }
        
        return signatures;
    }
    
    bool parse_function_signature(const std::string& line, FunctionSignature& sig) {
        // Simplified parsing - in a real implementation, this would use a proper parser
        std::istringstream iss(line);
        std::string token;
        
        // Extract function name (simplified)
        size_t func_pos = line.find("FUNC ");
        if (func_pos != std::string::npos) {
            size_t name_start = func_pos + 5;
            size_t paren_pos = line.find('(', name_start);
            if (paren_pos != std::string::npos) {
                sig.name = line.substr(name_start, paren_pos - name_start);
                sig.return_type = "void"; // Default
                
                // Extract parameters (simplified)
                size_t param_start = paren_pos + 1;
                size_t param_end = line.find(')', param_start);
                if (param_end != std::string::npos) {
                    std::string params = line.substr(param_start, param_end - param_start);
                    if (!params.empty()) {
                        std::istringstream param_stream(params);
                        std::string param;
                        while (std::getline(param_stream, param, ',')) {
                            sig.parameters.push_back(param);
                        }
                    }
                }
                return true;
            }
        }
        
        return false;
    }
    
    std::vector<TestCase> generate_test_cases_for_function(const FunctionSignature& signature) {
        std::vector<TestCase> test_cases;
        
        // Create prompt for AI to generate test cases
        std::string prompt = "Generate comprehensive unit tests for the following function:\n\n";
        prompt += "Function: " + signature.name + "\n";
        prompt += "Return Type: " + signature.return_type + "\n";
        prompt += "Parameters: ";
        for (size_t i = 0; i < signature.parameters.size(); ++i) {
            prompt += signature.parameters[i];
            if (i < signature.parameters.size() - 1) prompt += ", ";
        }
        prompt += "\n";
        prompt += "Documentation: " + signature.docstring + "\n\n";
        prompt += "Generate test cases including:\n";
        prompt += "1. Normal case with valid inputs\n";
        prompt += "2. Edge cases with boundary values\n";
        prompt += "3. Error cases with invalid inputs\n";
        prompt += "4. Performance test if applicable\n\n";
        prompt += "Return the test code in the same language as the function.";
        
        // Retrieve relevant test examples from the vector database
        Embedding query_embedding = ai_model_->generate_embedding(prompt);
        auto relevant_tests = vdb_->search(query_embedding, 3);
        
        std::string augmented_prompt = "Example test patterns from project:\n";
        for (const auto& test_id : relevant_tests) {
            augmented_prompt += vdb_->get_metadata(test_id) + "\n";
        }
        augmented_prompt += "\n" + prompt;
        
        // Generate test code using AI
        std::string generated_test_code = ai_model_->generate_completion(augmented_prompt);
        
        // Parse the generated code into individual test cases
        test_cases = parse_generated_tests(generated_test_code, signature);
        
        return test_cases;
    }
    
    std::vector<TestCase> parse_generated_tests(const std::string& test_code, const FunctionSignature& signature) {
        std::vector<TestCase> test_cases;
        
        // Simplified parsing - split by test function patterns
        std::istringstream iss(test_code);
        std::string line;
        std::string current_test;
        std::string current_name;
        
        while (std::getline(iss, line)) {
            if (line.find("TEST(") != std::string::npos || 
                line.find("def test_") != std::string::npos ||
                line.find("it('") != std::string::npos) {
                
                if (!current_test.empty() && !current_name.empty()) {
                    TestCase tc;
                    tc.test_name = current_name;
                    tc.test_code = current_test;
                    tc.description = "Generated test for " + signature.name;
                    test_cases.push_back(tc);
                }
                
                current_test = line + "\n";
                current_name = extract_test_name(line);
            } else if (!current_test.empty()) {
                current_test += line + "\n";
            }
        }
        
        // Add the last test case
        if (!current_test.empty() && !current_name.empty()) {
            TestCase tc;
            tc.test_name = current_name;
            tc.test_code = current_test;
            tc.description = "Generated test for " + signature.name;
            test_cases.push_back(tc);
        }
        
        return test_cases;
    }
    
    std::string extract_test_name(const std::string& line) {
        // Extract test name from various test frameworks
        size_t start = line.find("TEST(");
        if (start != std::string::npos) {
            start += 5;
            size_t end = line.find(",", start);
            if (end != std::string::npos) {
                return line.substr(start, end - start);
            }
        }
        
        start = line.find("def test_");
        if (start != std::string::npos) {
            start += 4;
            size_t end = line.find("(", start);
            if (end != std::string::npos) {
                return line.substr(start, end - start);
            }
        }
        
        return "test_" + std::to_string(std::rand());
    }
    
    void save_test_cases(const std::vector<TestCase>& test_cases, const FunctionSignature& signature) {
        std::string test_file_path = get_test_file_path(signature.file_path);
        
        std::ofstream test_file(test_file_path, std::ios::app);
        if (!test_file.is_open()) {
            std::cerr << "Error: Could not create test file " << test_file_path << "\n";
            return;
        }
        
        test_file << "\n// Generated tests for " << signature.name << "\n";
        test_file << "// Function location: " << signature.file_path << ":" << signature.line_number << "\n\n";
        
        for (const auto& test_case : test_cases) {
            test_file << "// " << test_case.description << "\n";
            test_file << test_case.test_code << "\n\n";
        }
        
        test_file.close();
        std::cout << "Saved " << test_cases.size() << " test cases to " << test_file_path << "\n";
    }
    
    std::string get_test_file_path(const std::string& source_file_path) {
        // Convert source file path to test file path
        std::string test_path = source_file_path;
        
        // Replace src/ with tests/ or add _test suffix
        size_t src_pos = test_path.find("src/");
        if (src_pos != std::string::npos) {
            test_path.replace(src_pos, 4, "tests/");
        }
        
        // Add _test suffix before extension
        size_t dot_pos = test_path.find_last_of('.');
        if (dot_pos != std::string::npos) {
            test_path.insert(dot_pos, "_test");
        } else {
            test_path += "_test";
        }
        
        return test_path;
    }
    
    std::vector<std::string> find_entry_points(const std::string& project_root) {
        std::vector<std::string> entry_points;
        
        // Look for main functions, public APIs, etc.
        // This is a simplified implementation
        entry_points.push_back("main");
        entry_points.push_back("public_api");
        entry_points.push_back("entry_point");
        
        return entry_points;
    }
    
    TestCase generate_integration_test_case(const std::string& entry_point) {
        std::string prompt = "Generate an integration test for the entry point: " + entry_point;
        std::string test_code = ai_model_->generate_completion(prompt);
        
        TestCase tc;
        tc.test_name = "integration_test_" + entry_point;
        tc.test_code = test_code;
        tc.description = "Integration test for " + entry_point;
        
        return tc;
    }
    
    void save_integration_test(const TestCase& test_case, const std::string& entry_point) {
        std::string test_file = "tests/integration_" + entry_point + "_test.cpp";
        
        std::ofstream file(test_file);
        if (file.is_open()) {
            file << "// Integration test for " << entry_point << "\n";
            file << test_case.test_code << "\n";
            file.close();
            std::cout << "Saved integration test to " << test_file << "\n";
        }
    }
    
    std::shared_ptr<CompletionModel> ai_model_;
    std::shared_ptr<VectorDatabase> vdb_;
};

} // namespace IDE_AI
