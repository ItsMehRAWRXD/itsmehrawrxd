// Custom tokenizer for code-optimized subword tokenization
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include <regex>

namespace IDE_AI {
namespace LLM {

class CodeTokenizer {
public:
    CodeTokenizer() {
        initializeVocabulary();
    }
    
    // Tokenize text into tokens
    std::vector<int> tokenize(const std::string& text) {
        std::vector<int> tokens;
        std::string current_token;
        
        for (char c : text) {
            if (isDelimiter(c)) {
                if (!current_token.empty()) {
                    tokens.push_back(getTokenId(current_token));
                    current_token.clear();
                }
                tokens.push_back(getTokenId(std::string(1, c)));
            } else {
                current_token += c;
            }
        }
        
        if (!current_token.empty()) {
            tokens.push_back(getTokenId(current_token));
        }
        
        return tokens;
    }
    
    // Convert tokens back to text
    std::string detokenize(const std::vector<int>& tokens) {
        std::string text;
        for (int token : tokens) {
            text += getTokenText(token);
        }
        return text;
    }
    
    size_t getVocabSize() const { return vocabulary_.size(); }
    
private:
    void initializeVocabulary() {
        // Initialize with common programming tokens
        vocabulary_["<pad>"] = 0;
        vocabulary_["<unk>"] = 1;
        vocabulary_["<s>"] = 2;
        vocabulary_["</s>"] = 3;
        
        // Add common programming keywords
        std::vector<std::string> keywords = {
            "function", "class", "if", "else", "for", "while", "return", "var", "let", "const",
            "public", "private", "protected", "static", "void", "int", "string", "bool",
            "namespace", "using", "include", "define", "typedef", "struct", "enum",
            "try", "catch", "throw", "finally", "async", "await", "import", "export"
        };
        
        for (const auto& keyword : keywords) {
            vocabulary_[keyword] = vocabulary_.size();
        }
        
        // Add common symbols
        std::vector<std::string> symbols = {
            "{", "}", "(", ")", "[", "]", ";", ",", ".", "=", "+", "-", "*", "/", "%",
            "==", "!=", "<", ">", "<=", ">=", "&&", "||", "!", "&", "|", "^", "~",
            "<<", ">>", "++", "--", "+=", "-=", "*=", "/=", "%=", "->", "::"
        };
        
        for (const auto& symbol : symbols) {
            vocabulary_[symbol] = vocabulary_.size();
        }
        
        // Add common data types
        std::vector<std::string> types = {
            "int", "float", "double", "char", "string", "bool", "void", "auto",
            "vector", "map", "set", "list", "array", "pointer", "reference"
        };
        
        for (const auto& type : types) {
            if (vocabulary_.find(type) == vocabulary_.end()) {
                vocabulary_[type] = vocabulary_.size();
            }
        }
    }
    
    bool isDelimiter(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
               c == '{' || c == '}' || c == '(' || c == ')' ||
               c == '[' || c == ']' || c == ';' || c == ',' ||
               c == '.' || c == '=' || c == '+' || c == '-' ||
               c == '*' || c == '/' || c == '%' || c == '!' ||
               c == '&' || c == '|' || c == '^' || c == '~' ||
               c == '<' || c == '>' || c == ':' || c == '?';
    }
    
    int getTokenId(const std::string& token) {
        auto it = vocabulary_.find(token);
        if (it != vocabulary_.end()) {
            return it->second;
        }
        
        // Handle unknown tokens by adding them to vocabulary
        if (vocabulary_.size() < 10000) { // Limit vocabulary size
            vocabulary_[token] = vocabulary_.size();
            return vocabulary_[token];
        }
        
        return vocabulary_["<unk>"];
    }
    
    std::string getTokenText(int token_id) {
        for (const auto& [text, id] : vocabulary_) {
            if (id == token_id) {
                return text;
            }
        }
        return "<unk>";
    }
    
    std::map<std::string, int> vocabulary_;
};

} // namespace LLM
} // namespace IDE_AI
