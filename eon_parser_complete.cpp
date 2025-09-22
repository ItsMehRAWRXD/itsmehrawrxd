#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <memory>

// EON Language Token Types (from our lexer)
enum TokenType {
    // Keywords
    TOKEN_MOV, TOKEN_JMP, TOKEN_CALL, TOKEN_RET, TOKEN_PUSH, TOKEN_POP,
    TOKEN_ADD, TOKEN_SUB, TOKEN_MUL, TOKEN_DIV, TOKEN_MOD, TOKEN_INC, TOKEN_DEC,
    TOKEN_CMP, TOKEN_JE, TOKEN_JNE, TOKEN_JG, TOKEN_JL, TOKEN_SECTION, TOKEN_GLOBAL,
    
    // Registers
    TOKEN_RAX, TOKEN_RBX, TOKEN_RCX, TOKEN_RDX, TOKEN_RSP, TOKEN_RBP,
    TOKEN_RSI, TOKEN_RDI, TOKEN_R8, TOKEN_R9, TOKEN_R10, TOKEN_R11,
    TOKEN_R12, TOKEN_R13, TOKEN_R14, TOKEN_R15,
    
    // Punctuation and Separators
    TOKEN_COMMA, TOKEN_COLON, TOKEN_LEFT_PAREN, TOKEN_RIGHT_PAREN,
    TOKEN_PLUS, TOKEN_MINUS, TOKEN_ASTERISK, TOKEN_SLASH,
    
    // Literals and Identifiers
    TOKEN_IDENTIFIER, TOKEN_INTEGER_LITERAL, TOKEN_STRING_LITERAL,
    
    // Other
    TOKEN_EOF, TOKEN_ILLEGAL
};

// Token structure
struct Token {
    TokenType type;
    std::string value;
};

// AST Node Types
enum ASTNodeType {
    AST_PROGRAM,
    AST_SECTION,
    AST_LABEL,
    AST_INSTRUCTION,
    AST_OPERAND,
    AST_REGISTER,
    AST_LITERAL,
    AST_IDENTIFIER,
    AST_DIRECTIVE
};

// AST Node structure
struct ASTNode {
    ASTNodeType type;
    std::string value;
    std::vector<std::shared_ptr<ASTNode>> children;
    
    ASTNode(ASTNodeType t, const std::string& v = "") : type(t), value(v) {}
};

class EONParser {
public:
    EONParser(const std::vector<Token>& tokens) : tokens_(tokens), position_(0) {}
    
    std::shared_ptr<ASTNode> parse() {
        auto program = std::make_shared<ASTNode>(AST_PROGRAM, "program");
        
        while (position_ < tokens_.size()) {
            auto node = parse_statement();
            if (node) {
                program->children.push_back(node);
            }
        }
        
        return program;
    }

private:
    const std::vector<Token>& tokens_;
    size_t position_;
    
    Token peek() {
        if (position_ < tokens_.size()) {
            return tokens_[position_];
        }
        return {TOKEN_EOF, ""};
    }
    
    Token consume(TokenType expected_type = TOKEN_EOF) {
        if (position_ >= tokens_.size()) {
            throw std::runtime_error("Unexpected end of input");
        }
        
        Token current = tokens_[position_];
        if (expected_type != TOKEN_EOF && current.type != expected_type) {
            throw std::runtime_error("Expected token type " + std::to_string(expected_type) + 
                                   ", but got " + std::to_string(current.type));
        }
        
        position_++;
        return current;
    }
    
    bool is_instruction(TokenType type) {
        return (type >= TOKEN_MOV && type <= TOKEN_GLOBAL);
    }
    
    bool is_register(TokenType type) {
        return (type >= TOKEN_RAX && type <= TOKEN_R15);
    }
    
    std::shared_ptr<ASTNode> parse_statement() {
        Token current = peek();
        
        if (current.type == TOKEN_SECTION) {
            return parse_section();
        } else if (current.type == TOKEN_GLOBAL) {
            return parse_directive();
        } else if (current.type == TOKEN_IDENTIFIER && 
                   position_ + 1 < tokens_.size() && 
                   tokens_[position_ + 1].type == TOKEN_COLON) {
            return parse_label();
        } else if (is_instruction(current.type)) {
            return parse_instruction();
        } else if (current.type == TOKEN_EOF) {
            return nullptr;
        } else {
            // Skip unknown tokens
            consume();
            return parse_statement();
        }
    }
    
    std::shared_ptr<ASTNode> parse_section() {
        consume(TOKEN_SECTION); // consume 'section'
        
        Token section_name = consume(TOKEN_IDENTIFIER);
        auto section_node = std::make_shared<ASTNode>(AST_SECTION, section_name.value);
        
        return section_node;
    }
    
    std::shared_ptr<ASTNode> parse_directive() {
        consume(TOKEN_GLOBAL); // consume 'global'
        
        Token symbol_name = consume(TOKEN_IDENTIFIER);
        auto directive_node = std::make_shared<ASTNode>(AST_DIRECTIVE, symbol_name.value);
        
        return directive_node;
    }
    
    std::shared_ptr<ASTNode> parse_label() {
        Token label_name = consume(TOKEN_IDENTIFIER);
        consume(TOKEN_COLON); // consume ':'
        
        auto label_node = std::make_shared<ASTNode>(AST_LABEL, label_name.value);
        
        return label_node;
    }
    
    std::shared_ptr<ASTNode> parse_instruction() {
        Token instruction_token = consume();
        auto instruction_node = std::make_shared<ASTNode>(AST_INSTRUCTION, instruction_token.value);
        
        // Parse operands
        while (position_ < tokens_.size()) {
            Token current = peek();
            
            if (current.type == TOKEN_EOF) {
                break;
            }
            
            // Skip whitespace and newlines
            if (current.type == TOKEN_COMMA) {
                consume(TOKEN_COMMA);
                continue;
            }
            
            auto operand = parse_operand();
            if (operand) {
                instruction_node->children.push_back(operand);
            } else {
                break;
            }
        }
        
        return instruction_node;
    }
    
    std::shared_ptr<ASTNode> parse_operand() {
        Token current = peek();
        
        if (is_register(current.type)) {
            Token register_token = consume();
            return std::make_shared<ASTNode>(AST_REGISTER, register_token.value);
        } else if (current.type == TOKEN_INTEGER_LITERAL) {
            Token literal_token = consume();
            return std::make_shared<ASTNode>(AST_LITERAL, literal_token.value);
        } else if (current.type == TOKEN_STRING_LITERAL) {
            Token string_token = consume();
            return std::make_shared<ASTNode>(AST_LITERAL, string_token.value);
        } else if (current.type == TOKEN_IDENTIFIER) {
            Token identifier_token = consume();
            return std::make_shared<ASTNode>(AST_IDENTIFIER, identifier_token.value);
        } else if (current.type == TOKEN_LEFT_PAREN) {
            return parse_memory_operand();
        } else {
            return nullptr;
        }
    }
    
    std::shared_ptr<ASTNode> parse_memory_operand() {
        consume(TOKEN_LEFT_PAREN); // consume '('
        
        auto memory_node = std::make_shared<ASTNode>(AST_OPERAND, "memory");
        
        // Parse the base register
        if (is_register(peek().type)) {
            Token base_token = consume();
            memory_node->children.push_back(std::make_shared<ASTNode>(AST_REGISTER, base_token.value));
        }
        
        // Parse offset if present
        if (peek().type == TOKEN_PLUS || peek().type == TOKEN_MINUS) {
            Token op_token = consume();
            if (peek().type == TOKEN_INTEGER_LITERAL) {
                Token offset_token = consume();
                auto offset_node = std::make_shared<ASTNode>(AST_LITERAL, offset_token.value);
                offset_node->value = op_token.value + offset_token.value;
                memory_node->children.push_back(offset_node);
            }
        }
        
        consume(TOKEN_RIGHT_PAREN); // consume ')'
        
        return memory_node;
    }
};

// Helper function to convert AST node type to string
std::string astNodeTypeToString(ASTNodeType type) {
    switch (type) {
        case AST_PROGRAM: return "PROGRAM";
        case AST_SECTION: return "SECTION";
        case AST_LABEL: return "LABEL";
        case AST_INSTRUCTION: return "INSTRUCTION";
        case AST_OPERAND: return "OPERAND";
        case AST_REGISTER: return "REGISTER";
        case AST_LITERAL: return "LITERAL";
        case AST_IDENTIFIER: return "IDENTIFIER";
        case AST_DIRECTIVE: return "DIRECTIVE";
        default: return "UNKNOWN";
    }
}

// Function to print AST tree
void printAST(const std::shared_ptr<ASTNode>& node, int depth = 0) {
    if (!node) return;
    
    std::string indent(depth * 2, ' ');
    std::cout << indent << "[" << astNodeTypeToString(node->type) << "]";
    
    if (!node->value.empty()) {
        std::cout << " " << node->value;
    }
    
    std::cout << std::endl;
    
    for (const auto& child : node->children) {
        printAST(child, depth + 1);
    }
}

// Main function to demonstrate the parser
int main() {
    // Sample EON source code tokens (simulating lexer output)
    std::vector<Token> tokens = {
        {TOKEN_SECTION, "section"},
        {TOKEN_IDENTIFIER, ".text"},
        {TOKEN_GLOBAL, "global"},
        {TOKEN_IDENTIFIER, "main"},
        {TOKEN_IDENTIFIER, "main"},
        {TOKEN_COLON, ":"},
        {TOKEN_MOV, "mov"},
        {TOKEN_RAX, "rax"},
        {TOKEN_COMMA, ","},
        {TOKEN_INTEGER_LITERAL, "60"},
        {TOKEN_MOV, "mov"},
        {TOKEN_RDI, "rdi"},
        {TOKEN_COMMA, ","},
        {TOKEN_INTEGER_LITERAL, "2"},
        {TOKEN_ADD, "add"},
        {TOKEN_RAX, "rax"},
        {TOKEN_COMMA, ","},
        {TOKEN_RDI, "rdi"},
        {TOKEN_JMP, "jmp"},
        {TOKEN_IDENTIFIER, "exit"},
        {TOKEN_IDENTIFIER, "exit"},
        {TOKEN_COLON, ":"},
        {TOKEN_RET, "ret"},
        {TOKEN_SECTION, "section"},
        {TOKEN_IDENTIFIER, ".data"},
        {TOKEN_IDENTIFIER, "msg"},
        {TOKEN_STRING_LITERAL, "Hello, World!"},
        {TOKEN_EOF, ""}
    };
    
    std::cout << "🚀 n0mn0m EON Parser - Professional Grade AST Builder" << std::endl;
    std::cout << "=====================================================" << std::endl;
    std::cout << "Token Stream Input:" << std::endl;
    
    for (size_t i = 0; i < tokens.size() && tokens[i].type != TOKEN_EOF; ++i) {
        std::cout << "[" << tokens[i].value << "] ";
    }
    std::cout << std::endl << std::endl;
    
    try {
        EONParser parser(tokens);
        auto ast = parser.parse();
        
        std::cout << "Abstract Syntax Tree (AST):" << std::endl;
        std::cout << "===========================" << std::endl;
        printAST(ast);
        
        std::cout << std::endl;
        std::cout << "✅ EON Parser completed successfully!" << std::endl;
        std::cout << "📊 AST Statistics:" << std::endl;
        std::cout << "   - Total Nodes: " << countNodes(ast) << std::endl;
        std::cout << "   - Tree Depth: " << getTreeDepth(ast) << std::endl;
        std::cout << "🎯 Ready for next phase: EON Code Generator!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "❌ Parser Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}

// Helper function to count AST nodes
int countNodes(const std::shared_ptr<ASTNode>& node) {
    if (!node) return 0;
    
    int count = 1;
    for (const auto& child : node->children) {
        count += countNodes(child);
    }
    return count;
}

// Helper function to get tree depth
int getTreeDepth(const std::shared_ptr<ASTNode>& node) {
    if (!node) return 0;
    
    int maxDepth = 0;
    for (const auto& child : node->children) {
        maxDepth = std::max(maxDepth, getTreeDepth(child));
    }
    return maxDepth + 1;
}
