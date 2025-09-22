// cpp_bootstrap_compiler.cpp
// Primitive bootstrap compiler in C++
// Implements basic Eon language features for bootstrapping

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <fstream>
#include <sstream>
#include <cctype>
#include <algorithm>

// === Token Types ===
enum class TokenType {
    EOF_TOKEN,
    IDENTIFIER,
    NUMBER,
    STRING,
    DEF,
    MODEL,
    FUNC,
    LOOP,
    IF,
    ELSE,
    LET,
    RET,
    LBRACE,
    RBRACE,
    LPAREN,
    RPAREN,
    SEMICOLON,
    ASSIGN,
    PLUS,
    MINUS,
    MULTIPLY,
    DIVIDE,
    EQUALS,
    NOT_EQUALS,
    GREATER,
    LESS,
    GREATER_EQUAL,
    LESS_EQUAL
};

// === Token Structure ===
struct Token {
    TokenType type;
    std::string value;
    int line;
    int column;
    
    Token(TokenType t = TokenType::EOF_TOKEN, const std::string& v = "", int l = 0, int c = 0)
        : type(t), value(v), line(l), column(c) {}
};

// === AST Node Types ===
enum class ASTNodeType {
    PROGRAM,
    FUNCTION_DEF,
    MODEL_DEF,
    VARIABLE_DECL,
    ASSIGNMENT,
    IF_STMT,
    LOOP_STMT,
    RETURN_STMT,
    BLOCK,
    BINARY_OP,
    UNARY_OP,
    IDENTIFIER,
    LITERAL,
    FUNCTION_CALL
};

// === AST Node Structure ===
struct ASTNode {
    ASTNodeType type;
    std::string value;
    std::vector<std::unique_ptr<ASTNode>> children;
    int line;
    int column;
    
    ASTNode(ASTNodeType t = ASTNodeType::PROGRAM, const std::string& v = "", int l = 0, int c = 0)
        : type(t), value(v), line(l), column(c) {}
    
    void add_child(std::unique_ptr<ASTNode> child) {
        children.push_back(std::move(child));
    }
};

// === Lexer Class ===
class Lexer {
private:
    std::string source;
    size_t position;
    int line;
    int column;
    char current_char;
    
    std::map<std::string, TokenType> keywords;
    
    void advance() {
        if (position < source.length()) {
            current_char = source[position++];
            column++;
            if (current_char == '\n') {
                line++;
                column = 1;
            }
        } else {
            current_char = '\0';
        }
    }
    
    void skip_whitespace() {
        while (current_char == ' ' || current_char == '\t' || current_char == '\r') {
            advance();
        }
    }
    
    bool is_letter(char c) {
        return std::isalpha(c) || c == '_';
    }
    
    bool is_digit(char c) {
        return std::isdigit(c);
    }
    
    bool is_alphanumeric(char c) {
        return is_letter(c) || is_digit(c);
    }
    
    std::string read_identifier() {
        std::string result;
        while (is_alphanumeric(current_char)) {
            result += current_char;
            advance();
        }
        return result;
    }
    
    std::string read_number() {
        std::string result;
        while (is_digit(current_char)) {
            result += current_char;
            advance();
        }
        return result;
    }
    
    std::string read_string() {
        std::string result;
        advance(); // skip opening quote
        while (current_char != '"' && current_char != '\0') {
            if (current_char == '\\') {
                advance();
                switch (current_char) {
                    case 'n': result += '\n'; break;
                    case 't': result += '\t'; break;
                    case 'r': result += '\r'; break;
                    case '\\': result += '\\'; break;
                    case '"': result += '"'; break;
                    default: result += current_char; break;
                }
            } else {
                result += current_char;
            }
            advance();
        }
        if (current_char == '"') {
            advance(); // skip closing quote
        }
        return result;
    }
    
public:
    Lexer(const std::string& src) : source(src), position(0), line(1), column(1) {
        // Initialize keywords
        keywords["def"] = TokenType::DEF;
        keywords["model"] = TokenType::MODEL;
        keywords["func"] = TokenType::FUNC;
        keywords["loop"] = TokenType::LOOP;
        keywords["if"] = TokenType::IF;
        keywords["else"] = TokenType::ELSE;
        keywords["let"] = TokenType::LET;
        keywords["ret"] = TokenType::RET;
        
        if (!source.empty()) {
            current_char = source[0];
        } else {
            current_char = '\0';
        }
    }
    
    Token next_token() {
        while (current_char != '\0') {
            skip_whitespace();
            
            if (current_char == '\0') break;
            
            int start_line = line;
            int start_column = column;
            
            if (is_letter(current_char)) {
                std::string identifier = read_identifier();
                auto it = keywords.find(identifier);
                if (it != keywords.end()) {
                    return Token(it->second, identifier, start_line, start_column);
                }
                return Token(TokenType::IDENTIFIER, identifier, start_line, start_column);
            }
            
            if (is_digit(current_char)) {
                std::string number = read_number();
                return Token(TokenType::NUMBER, number, start_line, start_column);
            }
            
            if (current_char == '"') {
                std::string str = read_string();
                return Token(TokenType::STRING, str, start_line, start_column);
            }
            
            switch (current_char) {
                case '{':
                    advance();
                    return Token(TokenType::LBRACE, "{", start_line, start_column);
                case '}':
                    advance();
                    return Token(TokenType::RBRACE, "}", start_line, start_column);
                case '(':
                    advance();
                    return Token(TokenType::LPAREN, "(", start_line, start_column);
                case ')':
                    advance();
                    return Token(TokenType::RPAREN, ")", start_line, start_column);
                case ';':
                    advance();
                    return Token(TokenType::SEMICOLON, ";", start_line, start_column);
                case '=':
                    advance();
                    if (current_char == '=') {
                        advance();
                        return Token(TokenType::EQUALS, "==", start_line, start_column);
                    }
                    return Token(TokenType::ASSIGN, "=", start_line, start_column);
                case '+':
                    advance();
                    return Token(TokenType::PLUS, "+", start_line, start_column);
                case '-':
                    advance();
                    return Token(TokenType::MINUS, "-", start_line, start_column);
                case '*':
                    advance();
                    return Token(TokenType::MULTIPLY, "*", start_line, start_column);
                case '/':
                    advance();
                    return Token(TokenType::DIVIDE, "/", start_line, start_column);
                case '>':
                    advance();
                    if (current_char == '=') {
                        advance();
                        return Token(TokenType::GREATER_EQUAL, ">=", start_line, start_column);
                    }
                    return Token(TokenType::GREATER, ">", start_line, start_column);
                case '<':
                    advance();
                    if (current_char == '=') {
                        advance();
                        return Token(TokenType::LESS_EQUAL, "<=", start_line, start_column);
                    }
                    return Token(TokenType::LESS, "<", start_line, start_column);
                case '!':
                    advance();
                    if (current_char == '=') {
                        advance();
                        return Token(TokenType::NOT_EQUALS, "!=", start_line, start_column);
                    }
                    break;
                default:
                    advance();
                    break;
            }
        }
        
        return Token(TokenType::EOF_TOKEN, "", line, column);
    }
};

// === Parser Class ===
class Parser {
private:
    Lexer lexer;
    Token current_token;
    
    void advance() {
        current_token = lexer.next_token();
    }
    
    void expect(TokenType expected) {
        if (current_token.type != expected) {
            std::cerr << "Error: Expected " << static_cast<int>(expected) 
                      << " but got " << static_cast<int>(current_token.type) << std::endl;
        }
        advance();
    }
    
    bool match(TokenType expected) {
        if (current_token.type == expected) {
            advance();
            return true;
        }
        return false;
    }
    
public:
    Parser(const std::string& source) : lexer(source) {
        advance();
    }
    
    std::unique_ptr<ASTNode> parse_program() {
        auto program = std::make_unique<ASTNode>(ASTNodeType::PROGRAM);
        
        while (current_token.type != TokenType::EOF_TOKEN) {
            auto declaration = parse_declaration();
            if (declaration) {
                program->add_child(std::move(declaration));
            }
        }
        
        return program;
    }
    
    std::unique_ptr<ASTNode> parse_declaration() {
        switch (current_token.type) {
            case TokenType::DEF:
                return parse_function_definition();
            case TokenType::MODEL:
                return parse_model_definition();
            default:
                return parse_statement();
        }
    }
    
    std::unique_ptr<ASTNode> parse_function_definition() {
        expect(TokenType::DEF);
        expect(TokenType::FUNC);
        
        auto func = std::make_unique<ASTNode>(ASTNodeType::FUNCTION_DEF, current_token.value);
        expect(TokenType::IDENTIFIER);
        
        expect(TokenType::LPAREN);
        // Parse parameters (simplified)
        while (current_token.type != TokenType::RPAREN) {
            advance();
        }
        expect(TokenType::RPAREN);
        
        auto body = parse_block();
        func->add_child(std::move(body));
        
        return func;
    }
    
    std::unique_ptr<ASTNode> parse_model_definition() {
        expect(TokenType::MODEL);
        
        auto model = std::make_unique<ASTNode>(ASTNodeType::MODEL_DEF, current_token.value);
        expect(TokenType::IDENTIFIER);
        
        expect(TokenType::LBRACE);
        // Parse fields (simplified)
        while (current_token.type != TokenType::RBRACE) {
            advance();
        }
        expect(TokenType::RBRACE);
        
        return model;
    }
    
    std::unique_ptr<ASTNode> parse_statement() {
        switch (current_token.type) {
            case TokenType::LET:
                return parse_variable_declaration();
            case TokenType::IF:
                return parse_if_statement();
            case TokenType::LOOP:
                return parse_loop_statement();
            case TokenType::RET:
                return parse_return_statement();
            case TokenType::LBRACE:
                return parse_block();
            default:
                return parse_expression();
        }
    }
    
    std::unique_ptr<ASTNode> parse_variable_declaration() {
        expect(TokenType::LET);
        
        auto var = std::make_unique<ASTNode>(ASTNodeType::VARIABLE_DECL, current_token.value);
        expect(TokenType::IDENTIFIER);
        
        if (match(TokenType::ASSIGN)) {
            auto expr = parse_expression();
            var->add_child(std::move(expr));
        }
        
        return var;
    }
    
    std::unique_ptr<ASTNode> parse_if_statement() {
        expect(TokenType::IF);
        
        auto if_stmt = std::make_unique<ASTNode>(ASTNodeType::IF_STMT);
        
        expect(TokenType::LPAREN);
        auto condition = parse_expression();
        if_stmt->add_child(std::move(condition));
        expect(TokenType::RPAREN);
        
        auto then_block = parse_statement();
        if_stmt->add_child(std::move(then_block));
        
        if (match(TokenType::ELSE)) {
            auto else_block = parse_statement();
            if_stmt->add_child(std::move(else_block));
        }
        
        return if_stmt;
    }
    
    std::unique_ptr<ASTNode> parse_loop_statement() {
        expect(TokenType::LOOP);
        
        auto loop = std::make_unique<ASTNode>(ASTNodeType::LOOP_STMT);
        auto body = parse_statement();
        loop->add_child(std::move(body));
        
        return loop;
    }
    
    std::unique_ptr<ASTNode> parse_return_statement() {
        expect(TokenType::RET);
        
        auto ret = std::make_unique<ASTNode>(ASTNodeType::RETURN_STMT);
        if (current_token.type != TokenType::SEMICOLON) {
            auto expr = parse_expression();
            ret->add_child(std::move(expr));
        }
        
        return ret;
    }
    
    std::unique_ptr<ASTNode> parse_block() {
        expect(TokenType::LBRACE);
        
        auto block = std::make_unique<ASTNode>(ASTNodeType::BLOCK);
        
        while (current_token.type != TokenType::RBRACE) {
            auto stmt = parse_statement();
            block->add_child(std::move(stmt));
        }
        
        expect(TokenType::RBRACE);
        return block;
    }
    
    std::unique_ptr<ASTNode> parse_expression() {
        return parse_equality();
    }
    
    std::unique_ptr<ASTNode> parse_equality() {
        auto left = parse_relational();
        
        while (current_token.type == TokenType::EQUALS || current_token.type == TokenType::NOT_EQUALS) {
            TokenType op = current_token.type;
            advance();
            auto right = parse_relational();
            
            auto binary_op = std::make_unique<ASTNode>(ASTNodeType::BINARY_OP, 
                op == TokenType::EQUALS ? "==" : "!=");
            binary_op->add_child(std::move(left));
            binary_op->add_child(std::move(right));
            left = std::move(binary_op);
        }
        
        return left;
    }
    
    std::unique_ptr<ASTNode> parse_relational() {
        auto left = parse_additive();
        
        while (current_token.type == TokenType::GREATER || 
               current_token.type == TokenType::GREATER_EQUAL ||
               current_token.type == TokenType::LESS ||
               current_token.type == TokenType::LESS_EQUAL) {
            TokenType op = current_token.type;
            advance();
            auto right = parse_additive();
            
            std::string op_str;
            switch (op) {
                case TokenType::GREATER: op_str = ">"; break;
                case TokenType::GREATER_EQUAL: op_str = ">="; break;
                case TokenType::LESS: op_str = "<"; break;
                case TokenType::LESS_EQUAL: op_str = "<="; break;
                default: break;
            }
            
            auto binary_op = std::make_unique<ASTNode>(ASTNodeType::BINARY_OP, op_str);
            binary_op->add_child(std::move(left));
            binary_op->add_child(std::move(right));
            left = std::move(binary_op);
        }
        
        return left;
    }
    
    std::unique_ptr<ASTNode> parse_additive() {
        auto left = parse_multiplicative();
        
        while (current_token.type == TokenType::PLUS || current_token.type == TokenType::MINUS) {
            TokenType op = current_token.type;
            advance();
            auto right = parse_multiplicative();
            
            auto binary_op = std::make_unique<ASTNode>(ASTNodeType::BINARY_OP, 
                op == TokenType::PLUS ? "+" : "-");
            binary_op->add_child(std::move(left));
            binary_op->add_child(std::move(right));
            left = std::move(binary_op);
        }
        
        return left;
    }
    
    std::unique_ptr<ASTNode> parse_multiplicative() {
        auto left = parse_unary();
        
        while (current_token.type == TokenType::MULTIPLY || current_token.type == TokenType::DIVIDE) {
            TokenType op = current_token.type;
            advance();
            auto right = parse_unary();
            
            auto binary_op = std::make_unique<ASTNode>(ASTNodeType::BINARY_OP, 
                op == TokenType::MULTIPLY ? "*" : "/");
            binary_op->add_child(std::move(left));
            binary_op->add_child(std::move(right));
            left = std::move(binary_op);
        }
        
        return left;
    }
    
    std::unique_ptr<ASTNode> parse_unary() {
        if (current_token.type == TokenType::MINUS) {
            advance();
            auto operand = parse_primary();
            auto unary = std::make_unique<ASTNode>(ASTNodeType::UNARY_OP, "-");
            unary->add_child(std::move(operand));
            return unary;
        }
        
        return parse_primary();
    }
    
    std::unique_ptr<ASTNode> parse_primary() {
        switch (current_token.type) {
            case TokenType::NUMBER:
                {
                    auto literal = std::make_unique<ASTNode>(ASTNodeType::LITERAL, current_token.value);
                    advance();
                    return literal;
                }
            case TokenType::STRING:
                {
                    auto literal = std::make_unique<ASTNode>(ASTNodeType::LITERAL, current_token.value);
                    advance();
                    return literal;
                }
            case TokenType::IDENTIFIER:
                {
                    auto identifier = std::make_unique<ASTNode>(ASTNodeType::IDENTIFIER, current_token.value);
                    advance();
                    return identifier;
                }
            case TokenType::LPAREN:
                {
                    advance();
                    auto expr = parse_expression();
                    expect(TokenType::RPAREN);
                    return expr;
                }
            default:
                std::cerr << "Error: Unexpected token in primary expression" << std::endl;
                return nullptr;
        }
    }
};

// === Code Generator Class ===
class CodeGenerator {
private:
    std::string output;
    int label_count;
    int temp_count;
    
    std::string new_label() {
        return "label_" + std::to_string(label_count++);
    }
    
    std::string new_temp() {
        return "temp_" + std::to_string(temp_count++);
    }
    
public:
    CodeGenerator() : label_count(0), temp_count(0) {}
    
    void generate_program(const ASTNode* node) {
        output += "section .text\n";
        output += "global _start\n";
        output += "_start:\n";
        output += "    call main\n";
        output += "    mov rax, 60\n";
        output += "    mov rdi, 0\n";
        output += "    syscall\n\n";
        
        for (const auto& child : node->children) {
            generate_declaration(child.get());
        }
    }
    
    void generate_declaration(const ASTNode* node) {
        switch (node->type) {
            case ASTNodeType::FUNCTION_DEF:
                generate_function(node);
                break;
            case ASTNodeType::MODEL_DEF:
                generate_model(node);
                break;
            default:
                generate_statement(node);
                break;
        }
    }
    
    void generate_function(const ASTNode* node) {
        output += "main:\n";
        output += "    push rbp\n";
        output += "    mov rbp, rsp\n";
        output += "    sub rsp, 1024\n"; // Allocate stack space
        
        if (!node->children.empty()) {
            generate_statement(node->children[0].get());
        }
        
        output += "    mov rax, 0\n";
        output += "    leave\n";
        output += "    ret\n\n";
    }
    
    void generate_model(const ASTNode* node) {
        output += "; Model: " + node->value + "\n";
    }
    
    void generate_statement(const ASTNode* node) {
        switch (node->type) {
            case ASTNodeType::VARIABLE_DECL:
                generate_variable_declaration(node);
                break;
            case ASTNodeType::ASSIGNMENT:
                generate_assignment(node);
                break;
            case ASTNodeType::IF_STMT:
                generate_if_statement(node);
                break;
            case ASTNodeType::LOOP_STMT:
                generate_loop_statement(node);
                break;
            case ASTNodeType::RETURN_STMT:
                generate_return_statement(node);
                break;
            case ASTNodeType::BLOCK:
                generate_block(node);
                break;
            default:
                generate_expression(node);
                break;
        }
    }
    
    void generate_variable_declaration(const ASTNode* node) {
        output += "; Variable: " + node->value + "\n";
        if (!node->children.empty()) {
            generate_expression(node->children[0].get());
        }
    }
    
    void generate_assignment(const ASTNode* node) {
        if (!node->children.empty()) {
            generate_expression(node->children[0].get());
        }
    }
    
    void generate_if_statement(const ASTNode* node) {
        if (node->children.size() >= 2) {
            std::string else_label = new_label();
            std::string end_label = new_label();
            
            generate_expression(node->children[0].get());
            output += "    cmp rax, 0\n";
            output += "    je " + else_label + "\n";
            
            generate_statement(node->children[1].get());
            output += "    jmp " + end_label + "\n";
            
            output += else_label + ":\n";
            if (node->children.size() > 2) {
                generate_statement(node->children[2].get());
            }
            
            output += end_label + ":\n";
        }
    }
    
    void generate_loop_statement(const ASTNode* node) {
        if (!node->children.empty()) {
            std::string loop_label = new_label();
            std::string end_label = new_label();
            
            output += loop_label + ":\n";
            generate_statement(node->children[0].get());
            output += "    jmp " + loop_label + "\n";
            output += end_label + ":\n";
        }
    }
    
    void generate_return_statement(const ASTNode* node) {
        if (!node->children.empty()) {
            generate_expression(node->children[0].get());
        }
        output += "    mov rax, 0\n";
    }
    
    void generate_block(const ASTNode* node) {
        for (const auto& child : node->children) {
            generate_statement(child.get());
        }
    }
    
    void generate_expression(const ASTNode* node) {
        switch (node->type) {
            case ASTNodeType::BINARY_OP:
                generate_binary_operation(node);
                break;
            case ASTNodeType::UNARY_OP:
                generate_unary_operation(node);
                break;
            case ASTNodeType::IDENTIFIER:
                generate_identifier(node);
                break;
            case ASTNodeType::LITERAL:
                generate_literal(node);
                break;
            default:
                break;
        }
    }
    
    void generate_binary_operation(const ASTNode* node) {
        if (node->children.size() >= 2) {
            generate_expression(node->children[0].get());
            output += "    push rax\n";
            generate_expression(node->children[1].get());
            output += "    pop rbx\n";
            
            if (node->value == "+") {
                output += "    add rax, rbx\n";
            } else if (node->value == "-") {
                output += "    sub rax, rbx\n";
            } else if (node->value == "*") {
                output += "    mul rbx\n";
            } else if (node->value == "/") {
                output += "    div rbx\n";
            } else if (node->value == "==") {
                output += "    cmp rax, rbx\n";
                output += "    sete al\n";
                output += "    movzx rax, al\n";
            } else if (node->value == "!=") {
                output += "    cmp rax, rbx\n";
                output += "    setne al\n";
                output += "    movzx rax, al\n";
            }
        }
    }
    
    void generate_unary_operation(const ASTNode* node) {
        if (!node->children.empty()) {
            generate_expression(node->children[0].get());
            if (node->value == "-") {
                output += "    neg rax\n";
            }
        }
    }
    
    void generate_identifier(const ASTNode* node) {
        output += "; Identifier: " + node->value + "\n";
        output += "    mov rax, 0\n"; // Placeholder
    }
    
    void generate_literal(const ASTNode* node) {
        if (std::isdigit(node->value[0])) {
            output += "    mov rax, " + node->value + "\n";
        } else {
            output += "; String literal: " + node->value + "\n";
            output += "    mov rax, 0\n"; // Placeholder
        }
    }
    
    std::string get_output() const {
        return output;
    }
};

// === Bootstrap Compiler Class ===
class BootstrapCompiler {
public:
    static std::string compile(const std::string& source) {
        try {
            Parser parser(source);
            auto ast = parser.parse_program();
            
            CodeGenerator generator;
            generator.generate_program(ast.get());
            
            return generator.get_output();
        } catch (const std::exception& e) {
            return "; Error: " + std::string(e.what()) + "\n";
        }
    }
    
    static void compile_file(const std::string& input_file, const std::string& output_file) {
        std::ifstream file(input_file);
        if (!file.is_open()) {
            std::cerr << "Error: Cannot open input file " << input_file << std::endl;
            return;
        }
        
        std::string source((std::istreambuf_iterator<char>(file)),
                          std::istreambuf_iterator<char>());
        file.close();
        
        std::string assembly = compile(source);
        
        std::ofstream out(output_file);
        if (!out.is_open()) {
            std::cerr << "Error: Cannot open output file " << output_file << std::endl;
            return;
        }
        
        out << assembly;
        out.close();
        
        std::cout << "Compilation successful. Output written to " << output_file << std::endl;
    }
};

// === Main Function ===
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <input_file> [output_file]" << std::endl;
        std::cout << "Example: " << argv[0] << " program.eon program.asm" << std::endl;
        return 1;
    }
    
    std::string input_file = argv[1];
    std::string output_file = (argc > 2) ? argv[2] : "output.asm";
    
    BootstrapCompiler::compile_file(input_file, output_file);
    
    return 0;
}
