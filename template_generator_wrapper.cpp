// template_generator_wrapper.cpp
// C++ wrapper for the assembly-based template generator
// Provides a more user-friendly interface and error handling

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <filesystem>
#include <fstream>

// Forward declarations for assembly functions
extern "C" {
    int template_generator_init();
    int template_generator_set_source(const char* source_path);
    int template_generator_set_template(const char* template_path);
    int template_generator_set_output(const char* output_path);
    int template_generator_set_language(int language);
    int template_generator_run();
    int template_generator_get_state();
    void template_generator_cleanup();
}

namespace TemplateGenerator {

// Language enumeration
enum class Language {
    EON = 1,
    CPP = 2,
    PYTHON = 3,
    JAVASCRIPT = 4,
    RUST = 5,
    GO = 6
};

// Generator state enumeration
enum class State {
    INIT = 0,
    PARSING = 1,
    TEMPLATING = 2,
    GENERATING = 3,
    COMPLETE = 4,
    ERROR = 5
};

// Exception classes
class TemplateGeneratorException : public std::runtime_error {
public:
    explicit TemplateGeneratorException(const std::string& message)
        : std::runtime_error("TemplateGenerator: " + message) {}
};

class FileNotFoundException : public TemplateGeneratorException {
public:
    explicit FileNotFoundException(const std::string& filename)
        : TemplateGeneratorException("File not found: " + filename) {}
};

class ParseException : public TemplateGeneratorException {
public:
    explicit ParseException(const std::string& message)
        : TemplateGeneratorException("Parse error: " + message) {}
};

class GenerationException : public TemplateGeneratorException {
public:
    explicit GenerationException(const std::string& message)
        : TemplateGeneratorException("Generation error: " + message) {}
};

// Main template generator class
class TemplateGenerator {
private:
    bool initialized_;
    std::string source_file_;
    std::string template_file_;
    std::string output_file_;
    Language target_language_;

public:
    TemplateGenerator() : initialized_(false), target_language_(Language::EON) {
        if (template_generator_init() != 1) {
            throw TemplateGeneratorException("Failed to initialize template generator");
        }
        initialized_ = true;
    }

    ~TemplateGenerator() {
        if (initialized_) {
            template_generator_cleanup();
        }
    }

    // Non-copyable
    TemplateGenerator(const TemplateGenerator&) = delete;
    TemplateGenerator& operator=(const TemplateGenerator&) = delete;

    // Move constructor
    TemplateGenerator(TemplateGenerator&& other) noexcept
        : initialized_(other.initialized_),
          source_file_(std::move(other.source_file_)),
          template_file_(std::move(other.template_file_)),
          output_file_(std::move(other.output_file_)),
          target_language_(other.target_language_) {
        other.initialized_ = false;
    }

    // Move assignment
    TemplateGenerator& operator=(TemplateGenerator&& other) noexcept {
        if (this != &other) {
            if (initialized_) {
                template_generator_cleanup();
            }
            initialized_ = other.initialized_;
            source_file_ = std::move(other.source_file_);
            template_file_ = std::move(other.template_file_);
            output_file_ = std::move(other.output_file_);
            target_language_ = other.target_language_;
            other.initialized_ = false;
        }
        return *this;
    }

    // Configuration methods
    void setSourceFile(const std::string& source_file) {
        if (!std::filesystem::exists(source_file)) {
            throw FileNotFoundException(source_file);
        }
        source_file_ = source_file;
        if (template_generator_set_source(source_file.c_str()) != 1) {
            throw TemplateGeneratorException("Failed to set source file");
        }
    }

    void setTemplateFile(const std::string& template_file) {
        if (!std::filesystem::exists(template_file)) {
            throw FileNotFoundException(template_file);
        }
        template_file_ = template_file;
        if (template_generator_set_template(template_file.c_str()) != 1) {
            throw TemplateGeneratorException("Failed to set template file");
        }
    }

    void setOutputFile(const std::string& output_file) {
        output_file_ = output_file;
        if (template_generator_set_output(output_file.c_str()) != 1) {
            throw TemplateGeneratorException("Failed to set output file");
        }
    }

    void setTargetLanguage(Language language) {
        target_language_ = language;
        if (template_generator_set_language(static_cast<int>(language)) != 1) {
            throw TemplateGeneratorException("Failed to set target language");
        }
    }

    // Generation method
    void generate() {
        if (source_file_.empty()) {
            throw TemplateGeneratorException("Source file not set");
        }
        if (template_file_.empty()) {
            throw TemplateGeneratorException("Template file not set");
        }
        if (output_file_.empty()) {
            throw TemplateGeneratorException("Output file not set");
        }

        int result = template_generator_run();
        if (result != 1) {
            State state = static_cast<State>(template_generator_get_state());
            switch (state) {
                case State::ERROR:
                    throw GenerationException("Generation failed");
                default:
                    throw GenerationException("Unknown error occurred");
            }
        }
    }

    // Utility methods
    State getState() const {
        return static_cast<State>(template_generator_get_state());
    }

    const std::string& getSourceFile() const { return source_file_; }
    const std::string& getTemplateFile() const { return template_file_; }
    const std::string& getOutputFile() const { return output_file_; }
    Language getTargetLanguage() const { return target_language_; }
};

// Utility functions
std::string languageToString(Language language) {
    switch (language) {
        case Language::EON: return "Eon";
        case Language::CPP: return "C++";
        case Language::PYTHON: return "Python";
        case Language::JAVASCRIPT: return "JavaScript";
        case Language::RUST: return "Rust";
        case Language::GO: return "Go";
        default: return "Unknown";
    }
}

std::string stateToString(State state) {
    switch (state) {
        case State::INIT: return "Initialized";
        case State::PARSING: return "Parsing";
        case State::TEMPLATING: return "Processing Template";
        case State::GENERATING: return "Generating Code";
        case State::COMPLETE: return "Complete";
        case State::ERROR: return "Error";
        default: return "Unknown";
    }
}

// Command-line interface
class CommandLineInterface {
private:
    std::vector<std::string> args_;

public:
    CommandLineInterface(int argc, char* argv[]) {
        for (int i = 0; i < argc; ++i) {
            args_.emplace_back(argv[i]);
        }
    }

    void run() {
        try {
            auto config = parseArguments();
            generateCode(config);
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            printUsage();
            std::exit(1);
        }
    }

private:
    struct Config {
        std::string source_file;
        std::string template_file;
        std::string output_file;
        Language language = Language::EON;
        bool verbose = false;
        bool help = false;
    };

    Config parseArguments() {
        Config config;
        
        for (size_t i = 1; i < args_.size(); ++i) {
            const std::string& arg = args_[i];
            
            if (arg == "--help" || arg == "-h") {
                config.help = true;
            } else if (arg == "--verbose" || arg == "-v") {
                config.verbose = true;
            } else if (arg == "--source" || arg == "-s") {
                if (i + 1 >= args_.size()) {
                    throw std::invalid_argument("--source requires a filename");
                }
                config.source_file = args_[++i];
            } else if (arg == "--template" || arg == "-t") {
                if (i + 1 >= args_.size()) {
                    throw std::invalid_argument("--template requires a filename");
                }
                config.template_file = args_[++i];
            } else if (arg == "--output" || arg == "-o") {
                if (i + 1 >= args_.size()) {
                    throw std::invalid_argument("--output requires a filename");
                }
                config.output_file = args_[++i];
            } else if (arg == "--language" || arg == "-l") {
                if (i + 1 >= args_.size()) {
                    throw std::invalid_argument("--language requires a language name");
                }
                config.language = parseLanguage(args_[++i]);
            } else {
                throw std::invalid_argument("Unknown argument: " + arg);
            }
        }

        if (config.help) {
            printUsage();
            std::exit(0);
        }

        if (config.source_file.empty()) {
            throw std::invalid_argument("Source file is required");
        }
        if (config.template_file.empty()) {
            throw std::invalid_argument("Template file is required");
        }
        if (config.output_file.empty()) {
            throw std::invalid_argument("Output file is required");
        }

        return config;
    }

    Language parseLanguage(const std::string& lang) {
        if (lang == "eon") return Language::EON;
        if (lang == "cpp" || lang == "c++") return Language::CPP;
        if (lang == "python" || lang == "py") return Language::PYTHON;
        if (lang == "javascript" || lang == "js") return Language::JAVASCRIPT;
        if (lang == "rust") return Language::RUST;
        if (lang == "go") return Language::GO;
        throw std::invalid_argument("Unknown language: " + lang);
    }

    void generateCode(const Config& config) {
        if (config.verbose) {
            std::cout << "Template Generator v1.0.0" << std::endl;
            std::cout << "Source: " << config.source_file << std::endl;
            std::cout << "Template: " << config.template_file << std::endl;
            std::cout << "Output: " << config.output_file << std::endl;
            std::cout << "Language: " << languageToString(config.language) << std::endl;
            std::cout << std::endl;
        }

        TemplateGenerator generator;
        generator.setSourceFile(config.source_file);
        generator.setTemplateFile(config.template_file);
        generator.setOutputFile(config.output_file);
        generator.setTargetLanguage(config.language);

        if (config.verbose) {
            std::cout << "Generating code..." << std::endl;
        }

        generator.generate();

        if (config.verbose) {
            std::cout << "Generation complete!" << std::endl;
        }
    }

    void printUsage() {
        std::cout << "Usage: template_generator [OPTIONS]" << std::endl;
        std::cout << std::endl;
        std::cout << "Options:" << std::endl;
        std::cout << "  -s, --source FILE     Source file (C++ header, JSON, etc.)" << std::endl;
        std::cout << "  -t, --template FILE   Template file (.eont)" << std::endl;
        std::cout << "  -o, --output FILE     Output file" << std::endl;
        std::cout << "  -l, --language LANG   Target language (eon, cpp, python, javascript, rust, go)" << std::endl;
        std::cout << "  -v, --verbose         Verbose output" << std::endl;
        std::cout << "  -h, --help            Show this help message" << std::endl;
        std::cout << std::endl;
        std::cout << "Examples:" << std::endl;
        std::cout << "  template_generator -s header.h -t template.eont -o output.eon -l eon" << std::endl;
        std::cout << "  template_generator --source data.json --template bindings.eont --output bindings.py --language python" << std::endl;
    }
};

} // namespace TemplateGenerator

// Main function
int main(int argc, char* argv[]) {
    try {
        TemplateGenerator::CommandLineInterface cli(argc, argv);
        cli.run();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
}
