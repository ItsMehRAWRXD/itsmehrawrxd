#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <map>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <cmath>
#include <random>
#include <sstream>

namespace IDE_AI {

// Forward declarations
class EmbeddingModel;
class CompletionModel;
class SelfHostedModel;
class ModelManager;

// Token types for the model
enum class TokenType {
    UNKNOWN = 0,
    IDENTIFIER = 1,
    KEYWORD = 2,
    OPERATOR = 3,
    LITERAL = 4,
    PUNCTUATION = 5,
    WHITESPACE = 6,
    COMMENT = 7,
    STRING = 8,
    NUMBER = 9
};

// Token structure
struct Token {
    std::string value;
    TokenType type;
    size_t position;
    size_t line;
    size_t column;
    
    Token(const std::string& val = "", TokenType t = TokenType::UNKNOWN, 
          size_t pos = 0, size_t l = 0, size_t c = 0)
        : value(val), type(t), position(pos), line(l), column(c) {}
};

// Vocabulary for the model
class Vocabulary {
private:
    std::vector<std::string> id_to_token;
    std::unordered_map<std::string, int> token_to_id;
    int next_id = 0;
    
public:
    Vocabulary() {
        // Add special tokens
        add_token("<PAD>");
        add_token("<UNK>");
        add_token("<BOS>");
        add_token("<EOS>");
    }
    
    int add_token(const std::string& token) {
        if (token_to_id.find(token) == token_to_id.end()) {
            token_to_id[token] = next_id;
            id_to_token.push_back(token);
            return next_id++;
        }
        return token_to_id[token];
    }
    
    int get_id(const std::string& token) const {
        auto it = token_to_id.find(token);
        return (it != token_to_id.end()) ? it->second : token_to_id.at("<UNK>");
    }
    
    const std::string& get_token(int id) const {
        return id_to_token[id];
    }
    
    size_t size() const { return id_to_token.size(); }
};

// Base class for all AI models
class BaseModel {
protected:
    std::string model_name;
    size_t model_size;
    bool is_loaded;
    
public:
    BaseModel(const std::string& name) 
        : model_name(name), model_size(0), is_loaded(false) {}
    
    virtual ~BaseModel() = default;
    
    virtual bool load(const std::string& path) = 0;
    virtual bool save(const std::string& path) = 0;
    virtual void unload() = 0;
    
    const std::string& get_name() const { return model_name; }
    size_t get_size() const { return model_size; }
    bool loaded() const { return is_loaded; }
};

} // namespace IDE_AI