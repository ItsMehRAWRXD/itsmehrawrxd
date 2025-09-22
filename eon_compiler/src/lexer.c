// EON Compiler Lexer Implementation
#include "../include/compiler.h"

// Global lexer state
Token current_token;
char *source;
int source_pos;
int source_len;

void lexer_init(char *src) {
    source = src;
    source_pos = 0;
    source_len = strlen(source);
    lexer_next();
}

void lexer_next() {
    skip_whitespace();
    
    if (source_pos >= source_len) {
        current_token = make_token(TOKEN_EOF, "");
        return;
    }
    
    char c = peek();
    
    if (is_digit(c)) {
        current_token = read_number();
    } else if (is_alpha(c)) {
        current_token = read_identifier();
    } else {
        switch (c) {
            case '+':
                advance();
                current_token = make_token(TOKEN_PLUS, "+");
                break;
            case '-':
                advance();
                current_token = make_token(TOKEN_MINUS, "-");
                break;
            case '*':
                advance();
                current_token = make_token(TOKEN_MULTIPLY, "*");
                break;
            case '/':
                advance();
                current_token = make_token(TOKEN_DIVIDE, "/");
                break;
            case '=':
                advance();
                current_token = make_token(TOKEN_ASSIGN, "=");
                break;
            case ';':
                advance();
                current_token = make_token(TOKEN_SEMICOLON, ";");
                break;
            case '(':
                advance();
                current_token = make_token(TOKEN_LPAREN, "(");
                break;
            case ')':
                advance();
                current_token = make_token(TOKEN_RPAREN, ")");
                break;
            case '{':
                advance();
                current_token = make_token(TOKEN_LBRACE, "{");
                break;
            case '}':
                advance();
                current_token = make_token(TOKEN_RBRACE, "}");
                break;
            case '>':
                advance();
                current_token = make_token(TOKEN_GREATER, ">");
                break;
            case ',':
                advance();
                current_token = make_token(TOKEN_COMMA, ",");
                break;
            case ':':
                advance();
                current_token = make_token(TOKEN_COLON, ":");
                break;
            case '&':
                advance();
                current_token = make_token(TOKEN_ADDRESS_OF, "&");
                break;
            default:
                advance();
                current_token = make_token(TOKEN_EOF, "");
                break;
        }
    }
}

Token make_token(TokenType type, char *value) {
    Token token;
    token.type = type;
    token.value = malloc(strlen(value) + 1);
    strcpy(token.value, value);
    token.line = 1; // Simplified line tracking
    token.column = source_pos;
    return token;
}

int is_alpha(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

int is_digit(char c) {
    return c >= '0' && c <= '9';
}

int is_alnum(char c) {
    return is_alpha(c) || is_digit(c);
}

char peek() {
    if (source_pos >= source_len) return '\0';
    return source[source_pos];
}

char advance() {
    if (source_pos >= source_len) return '\0';
    return source[source_pos++];
}

void skip_whitespace() {
    while (source_pos < source_len) {
        char c = peek();
        if (c == ' ' || c == '\t' || c == '\r') {
            advance();
        } else if (c == '\n') {
            advance();
        } else {
            break;
        }
    }
}

Token read_number() {
    int start = source_pos;
    while (is_digit(peek())) {
        advance();
    }
    
    int len = source_pos - start;
    char *value = malloc(len + 1);
    strncpy(value, source + start, len);
    value[len] = '\0';
    
    return make_token(TOKEN_NUMBER, value);
}

Token read_identifier() {
    int start = source_pos;
    while (is_alnum(peek())) {
        advance();
    }
    
    int len = source_pos - start;
    char *value = malloc(len + 1);
    strncpy(value, source + start, len);
    value[len] = '\0';
    
    // Check for keywords
    if (strcmp(value, "if") == 0) {
        return make_token(TOKEN_IF, value);
    } else if (strcmp(value, "else") == 0) {
        return make_token(TOKEN_ELSE, value);
    } else if (strcmp(value, "ret") == 0) {
        return make_token(TOKEN_RET, value);
    } else if (strcmp(value, "let") == 0) {
        return make_token(TOKEN_LET, value);
    } else if (strcmp(value, "def") == 0) {
        return make_token(TOKEN_DEF, value);
    } else if (strcmp(value, "struct") == 0) {
        return make_token(TOKEN_STRUCT, value);
    } else if (strcmp(value, "alloc") == 0) {
        return make_token(TOKEN_ALLOC, value);
    } else if (strcmp(value, "for") == 0) {
        return make_token(TOKEN_FOR, value);
    } else if (strcmp(value, "while") == 0) {
        return make_token(TOKEN_WHILE, value);
    }
    
    return make_token(TOKEN_IDENTIFIER, value);
}
