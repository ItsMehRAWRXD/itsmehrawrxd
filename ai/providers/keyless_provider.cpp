// AI provider integrating the keyless and fileless local LLM
#include "../ai_provider_interface.hpp"
#include "../../llm/inference_engine.cpp"
#include <vector>
#include <memory>
#include <functional>

namespace IDE_AI {
    
    class KeylessProvider : public IAIProvider {
    private:
        LLM::InferenceEngine llm_engine;
        std::vector<unsigned char> model_data;
        
    public:
        KeylessProvider(const std::vector<unsigned char>& model_data) 
            : model_data(model_data) {
            // Load the model from the provided in-memory data
            LLM::DynamicLoader::load_from_stream(llm_engine, model_data);
        }
        
        void generate_completion_async(const std::string& prompt, 
                                     std::function<void(const std::string&)> callback) override {
            // Generate completion using the local LLM
            std::string response = llm_engine.generate(prompt);
            callback(response);
        }
        
        void generate_completion_streaming(const std::string& prompt,
                                         std::function<void(const std::string&)> callback) override {
            // Generate streaming completion
            llm_engine.generate_streaming(prompt, callback);
        }
        
        std::string get_provider_name() const override {
            return "KeylessProvider";
        }
        
        bool supports_streaming() const override {
            return true;
        }
        
        bool supports_function_calling() const override {
            return false; // Simplified for now
        }
        
        int get_max_tokens() const override {
            return 4096; // Default max tokens
        }
        
        std::vector<std::string> get_supported_models() const override {
            return {"local-model"};
        }
        
        bool is_available() const override {
            return !model_data.empty();
        }
        
        std::map<std::string, std::string> get_capabilities() const override {
            return {
                {"streaming", "true"},
                {"function_calling", "false"},
                {"max_tokens", "4096"},
                {"model_type", "local"}
            };
        }
        
        void set_parameters(const std::map<std::string, std::string>& params) override {
            // Set model parameters if needed
            for (const auto& [key, value] : params) {
                if (key == "temperature") {
                    llm_engine.set_temperature(std::stof(value));
                } else if (key == "max_tokens") {
                    llm_engine.set_max_tokens(std::stoi(value));
                }
            }
        }
        
        std::map<std::string, std::string> get_parameters() const override {
            return {
                {"temperature", std::to_string(llm_engine.get_temperature())},
                {"max_tokens", std::to_string(llm_engine.get_max_tokens())}
            };
        }
        
        void reset_context() override {
            llm_engine.reset_context();
        }
        
        void add_to_context(const std::string& text) override {
            llm_engine.add_to_context(text);
        }
        
        std::string get_context() const override {
            return llm_engine.get_context();
        }
        
        size_t get_context_length() const override {
            return llm_engine.get_context_length();
        }
        
        bool is_context_full() const override {
            return llm_engine.is_context_full();
        }
        
        void clear_context() override {
            llm_engine.clear_context();
        }
        
        std::vector<std::string> get_recent_completions(int count = 10) const override {
            return llm_engine.get_recent_completions(count);
        }
        
        void set_system_prompt(const std::string& prompt) override {
            llm_engine.set_system_prompt(prompt);
        }
        
        std::string get_system_prompt() const override {
            return llm_engine.get_system_prompt();
        }
        
        void set_stop_sequences(const std::vector<std::string>& sequences) override {
            llm_engine.set_stop_sequences(sequences);
        }
        
        std::vector<std::string> get_stop_sequences() const override {
            return llm_engine.get_stop_sequences();
        }
        
        void set_repetition_penalty(float penalty) override {
            llm_engine.set_repetition_penalty(penalty);
        }
        
        float get_repetition_penalty() const override {
            return llm_engine.get_repetition_penalty();
        }
        
        void set_top_p(float top_p) override {
            llm_engine.set_top_p(top_p);
        }
        
        float get_top_p() const override {
            return llm_engine.get_top_p();
        }
        
        void set_top_k(int top_k) override {
            llm_engine.set_top_k(top_k);
        }
        
        int get_top_k() const override {
            return llm_engine.get_top_k();
        }
        
        void set_frequency_penalty(float penalty) override {
            llm_engine.set_frequency_penalty(penalty);
        }
        
        float get_frequency_penalty() const override {
            return llm_engine.get_frequency_penalty();
        }
        
        void set_presence_penalty(float penalty) override {
            llm_engine.set_presence_penalty(penalty);
        }
        
        float get_presence_penalty() const override {
            return llm_engine.get_presence_penalty();
        }
        
        std::string get_model_info() const override {
            return "Local Keyless Model - No API keys required";
        }
        
        std::map<std::string, std::string> get_model_details() const override {
            return {
                {"name", "local-model"},
                {"type", "transformer"},
                {"parameters", "7B"},
                {"context_length", "4096"},
                {"provider", "keyless"}
            };
        }
        
        bool can_handle_request(const std::string& request_type) const override {
            return request_type == "completion" || request_type == "chat";
        }
        
        std::string get_error_message() const override {
            return llm_engine.get_last_error();
        }
        
        void clear_error() override {
            llm_engine.clear_error();
        }
        
        bool has_error() const override {
            return !llm_engine.get_last_error().empty();
        }
        
        void set_timeout(int timeout_ms) override {
            llm_engine.set_timeout(timeout_ms);
        }
        
        int get_timeout() const override {
            return llm_engine.get_timeout();
        }
        
        void set_retry_count(int count) override {
            llm_engine.set_retry_count(count);
        }
        
        int get_retry_count() const override {
            return llm_engine.get_retry_count();
        }
        
        std::string get_version() const override {
            return "1.0.0";
        }
        
        std::string get_build_info() const override {
            return "KeylessProvider v1.0.0 - Built for fileless operation";
        }
        
        void shutdown() override {
            llm_engine.shutdown();
        }
        
        ~KeylessProvider() {
            shutdown();
        }
    };
    
} // namespace IDE_AI