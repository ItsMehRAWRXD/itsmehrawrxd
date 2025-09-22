#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

// --- Security Globals ---
unsigned long long security_cookie;

// Forward declarations for compiler components
typedef struct Token Token;
typedef struct AstNode AstNode;
typedef struct Symbol Symbol;
typedef struct EonType EonType;
typedef struct Scope Scope;
typedef struct TacEntry TacEntry;
typedef struct TacList TacList;

char *lexer_src;
Token current_token;
int if_count = 0;
int func_count = 0;
int label_count = 0;

// --- COMPREHENSIVE TOKEN DEFINITIONS ---
// Based on the comprehensive token list from rwararw.txt
typedef struct Token {
    enum {
        // Basic tokens
        TOKEN_EOF, TOKEN_IDENTIFIER, TOKEN_NUMBER, TOKEN_STRING, TOKEN_CHAR,
        
        // Keywords
        TOKEN_DEF, TOKEN_MODEL, TOKEN_FUNC, TOKEN_LOOP, TOKEN_IF, TOKEN_ELSE,
        TOKEN_LET, TOKEN_CONST, TOKEN_RET, TOKEN_BREAK, TOKEN_CONTINUE,
        TOKEN_IMPORT, TOKEN_EXPORT, TOKEN_MATCH, TOKEN_CASE, TOKEN_DEFAULT,
        TOKEN_TRY, TOKEN_CATCH, TOKEN_FINALLY, TOKEN_THROW,
        
        // Type keywords
        TOKEN_INT, TOKEN_FLOAT, TOKEN_BOOL, TOKEN_VOID, TOKEN_AUTO,
        
        // Operators
        TOKEN_PLUS, TOKEN_MINUS, TOKEN_MULTIPLY, TOKEN_DIVIDE, TOKEN_MODULO,
        TOKEN_POWER, TOKEN_ASSIGN, TOKEN_PLUS_ASSIGN, TOKEN_MINUS_ASSIGN,
        TOKEN_MULTIPLY_ASSIGN, TOKEN_DIVIDE_ASSIGN, TOKEN_EQUALS, TOKEN_NOT_EQUALS,
        TOKEN_GREATER, TOKEN_GREATER_EQUAL, TOKEN_LESS, TOKEN_LESS_EQUAL,
        TOKEN_LOGICAL_AND, TOKEN_LOGICAL_OR, TOKEN_LOGICAL_NOT,
        TOKEN_BITWISE_AND, TOKEN_BITWISE_OR, TOKEN_BITWISE_XOR, TOKEN_BITWISE_NOT,
        TOKEN_LEFT_SHIFT, TOKEN_RIGHT_SHIFT,
        
        // Punctuation
        TOKEN_LPAREN, TOKEN_RPAREN, TOKEN_LBRACE, TOKEN_RBRACE,
        TOKEN_LBRACKET, TOKEN_RBRACKET, TOKEN_SEMICOLON, TOKEN_COMMA,
        TOKEN_DOT, TOKEN_COLON, TOKEN_DOUBLE_COLON, TOKEN_ARROW, TOKEN_FAT_ARROW,
        TOKEN_QUESTION, TOKEN_AMPERSAND, TOKEN_STAR,
        
        // Special
        TOKEN_NEWLINE, TOKEN_INDENT, TOKEN_DEDENT,
        
        // Memory management
        TOKEN_ALLOC, TOKEN_FREE, TOKEN_SIZEOF,
        
        // Concurrency
        TOKEN_SPAWN, TOKEN_SHARED, TOKEN_MUTEX, TOKEN_LOCK, TOKEN_UNLOCK,
        
        // Legacy tokens for compatibility
        TOKEN_GT, TOKEN_EQ, TOKEN_ADD, TOKEN_SUB, TOKEN_MUL, TOKEN_DIV
    } type;
    char *value;
    int line;
    int column;
} Token;

// --- ENHANCED TYPE SYSTEM ---
typedef enum {
    TYPE_INT, TYPE_FLOAT, TYPE_BOOL, TYPE_VOID, TYPE_POINTER, TYPE_STRUCT, TYPE_FUNCTION
} EonTypeKind;

typedef struct EonType {
    EonTypeKind kind;
    struct EonType *base_type; // For pointers
    char *struct_name; // For structs
    struct EonType **param_types; // For functions
    int param_count;
    struct EonType *return_type; // For functions
    int size; // Size in bytes
} EonType;

// --- ENHANCED SYMBOL TABLE ---
#define MAX_SYMBOLS 256
#define MAX_SCOPES 32

typedef struct Symbol {
    char *name;
    int stack_offset;
    EonType *type;
    int is_function;
    int is_parameter;
    int is_shared; // For concurrency
} Symbol;

typedef struct Scope {
    Symbol *symbols[MAX_SYMBOLS];
    int count;
    struct Scope *parent;
    int level;
} Scope;

// Global symbol table
Scope *current_scope = NULL;
Scope *global_scope = NULL;

// --- ENHANCED AST NODES ---
typedef struct AstNode {
    enum {
        AST_NUMBER, AST_STRING, AST_CHAR, AST_OP, AST_IDENTIFIER, AST_VAR_DECL, 
        AST_ASSIGN, AST_IF, AST_ELSE, AST_RET, AST_BLOCK, AST_FUNCTION_DEFINITION, 
        AST_FUNCTION_CALL, AST_STRUCT_DEFINITION, AST_POINTER_TYPE, AST_DEREFERENCE, 
        AST_ADDRESS_OF, AST_PARAMETER, AST_STRUCT_FIELD, AST_PROGRAM, AST_ALLOC,
        AST_FREE, AST_SIZEOF, AST_FUNCTION_PROTOTYPE, AST_SPAWN, AST_ASSIGN_DEREF,
        AST_WHILE_LOOP, AST_FOR_LOOP, AST_BREAK, AST_CONTINUE, AST_MATCH, AST_CASE,
        AST_TRY, AST_CATCH, AST_FINALLY, AST_THROW, AST_MEMBER_ACCESS, AST_ARRAY_ACCESS,
        AST_IMPORT, AST_EXPORT, AST_MUTEX, AST_LOCK, AST_UNLOCK
    } type;
    int value;
    char *name;
    int op;
    struct AstNode *left;
    struct AstNode *right;
    struct AstNode *cond;
    struct AstNode *body;
    struct AstNode *next;
    struct AstNode *args;
    struct AstNode *params;
    struct AstNode *fields;
    struct AstNode *cases;
    struct AstNode *catch_block;
    struct AstNode *finally_block;
    EonType *type_info;
    int is_shared;
    int line;
    int column;
    
    // Union for different node types
    union {
        struct {
            char *name;
            AstNode *init_expr;
        } var_decl;
        struct {
            char *name;
            AstNode *params;
            AstNode *body;
            EonType *return_type;
        } func_def;
        struct {
            char *name;
            AstNode *args;
        } func_call;
        struct {
            char *name;
            AstNode *fields;
        } struct_def;
        struct {
            AstNode *structure;
            AstNode *member;
        } member_access;
        struct {
            AstNode *array;
            AstNode *index;
        } array_access;
        struct {
            AstNode *init;
            AstNode *cond;
            AstNode *incr;
            AstNode *body;
        } for_loop;
        struct {
            AstNode *cond;
            AstNode *body;
        } while_loop;
        struct {
            AstNode *expr;
            AstNode *cases;
        } match_stmt;
        struct {
            AstNode *pattern;
            AstNode *body;
        } case_stmt;
        struct {
            AstNode *try_block;
            AstNode *catch_block;
            AstNode *finally_block;
        } try_stmt;
    } data;
} AstNode;

// --- INTERMEDIATE REPRESENTATION ---
typedef enum {
    TAC_ASSIGN, TAC_ADD, TAC_SUB, TAC_MUL, TAC_DIV, TAC_MOD, TAC_POWER,
    TAC_EQUALS, TAC_NOT_EQUALS, TAC_GREATER, TAC_GREATER_EQUAL, TAC_LESS, TAC_LESS_EQUAL,
    TAC_LOGICAL_AND, TAC_LOGICAL_OR, TAC_LOGICAL_NOT,
    TAC_BITWISE_AND, TAC_BITWISE_OR, TAC_BITWISE_XOR, TAC_BITWISE_NOT,
    TAC_LEFT_SHIFT, TAC_RIGHT_SHIFT,
    TAC_IF_GOTO, TAC_GOTO, TAC_LABEL, TAC_CALL, TAC_RETURN, TAC_PARAM,
    TAC_LOAD_MEM, TAC_STORE_MEM, TAC_LOAD_ADDR, TAC_ALLOC, TAC_FREE,
    TAC_MEMBER_ACCESS, TAC_ARRAY_ACCESS, TAC_SPAWN, TAC_LOCK, TAC_UNLOCK
} TacOpcode;

typedef struct TacEntry {
    TacOpcode opcode;
    char *arg1;
    char *arg2;
    char *result;
    struct TacEntry *next;
} TacEntry;

typedef struct TacList {
    TacEntry *head;
    TacEntry *tail;
    int count;
} TacList;

// --- ENHANCED LEXER ---
void lexer_init(char *src) {
    lexer_src = src;
    current_token.line = 1;
    current_token.column = 1;
}

Token *lexer_next() {
    while(isspace(*lexer_src)) {
        if (*lexer_src == '\n') {
            current_token.line++;
            current_token.column = 1;
        } else {
            current_token.column++;
        }
        lexer_src++;
    }
    
    if (*lexer_src == '\0') { 
        current_token.type = TOKEN_EOF; 
        return &current_token; 
    }

    char *start = lexer_src;
    
    // Handle identifiers and keywords
    if (isalpha(*start) || *start == '_') {
        while(isalnum(*lexer_src) || *lexer_src == '_') {
            lexer_src++;
            current_token.column++;
        }
        char *word = strndup(start, lexer_src-start);
        
        // Comprehensive keyword recognition
        if (strcmp(word,"def")==0) { current_token.type = TOKEN_DEF; }
        else if (strcmp(word,"model")==0) { current_token.type = TOKEN_MODEL; }
        else if (strcmp(word,"func")==0) { current_token.type = TOKEN_FUNC; }
        else if (strcmp(word,"loop")==0) { current_token.type = TOKEN_LOOP; }
        else if (strcmp(word,"if")==0) { current_token.type = TOKEN_IF; }
        else if (strcmp(word,"else")==0) { current_token.type = TOKEN_ELSE; }
        else if (strcmp(word,"let")==0) { current_token.type = TOKEN_LET; }
        else if (strcmp(word,"const")==0) { current_token.type = TOKEN_CONST; }
        else if (strcmp(word,"ret")==0) { current_token.type = TOKEN_RET; }
        else if (strcmp(word,"break")==0) { current_token.type = TOKEN_BREAK; }
        else if (strcmp(word,"continue")==0) { current_token.type = TOKEN_CONTINUE; }
        else if (strcmp(word,"import")==0) { current_token.type = TOKEN_IMPORT; }
        else if (strcmp(word,"export")==0) { current_token.type = TOKEN_EXPORT; }
        else if (strcmp(word,"match")==0) { current_token.type = TOKEN_MATCH; }
        else if (strcmp(word,"case")==0) { current_token.type = TOKEN_CASE; }
        else if (strcmp(word,"default")==0) { current_token.type = TOKEN_DEFAULT; }
        else if (strcmp(word,"try")==0) { current_token.type = TOKEN_TRY; }
        else if (strcmp(word,"catch")==0) { current_token.type = TOKEN_CATCH; }
        else if (strcmp(word,"finally")==0) { current_token.type = TOKEN_FINALLY; }
        else if (strcmp(word,"throw")==0) { current_token.type = TOKEN_THROW; }
        else if (strcmp(word,"int")==0) { current_token.type = TOKEN_INT; }
        else if (strcmp(word,"float")==0) { current_token.type = TOKEN_FLOAT; }
        else if (strcmp(word,"bool")==0) { current_token.type = TOKEN_BOOL; }
        else if (strcmp(word,"void")==0) { current_token.type = TOKEN_VOID; }
        else if (strcmp(word,"auto")==0) { current_token.type = TOKEN_AUTO; }
        else if (strcmp(word,"alloc")==0) { current_token.type = TOKEN_ALLOC; }
        else if (strcmp(word,"free")==0) { current_token.type = TOKEN_FREE; }
        else if (strcmp(word,"sizeof")==0) { current_token.type = TOKEN_SIZEOF; }
        else if (strcmp(word,"spawn")==0) { current_token.type = TOKEN_SPAWN; }
        else if (strcmp(word,"shared")==0) { current_token.type = TOKEN_SHARED; }
        else if (strcmp(word,"mutex")==0) { current_token.type = TOKEN_MUTEX; }
        else if (strcmp(word,"lock")==0) { current_token.type = TOKEN_LOCK; }
        else if (strcmp(word,"unlock")==0) { current_token.type = TOKEN_UNLOCK; }
        else { 
            current_token.type = TOKEN_IDENTIFIER; 
            current_token.value = word; 
        }
        return &current_token;
    }
    
    // Handle numbers
    if (isdigit(*start)) {
        while(isdigit(*lexer_src) || *lexer_src == '.') {
            lexer_src++;
            current_token.column++;
        }
        current_token.type = TOKEN_NUMBER;
        current_token.value = strndup(start, lexer_src-start);
        return &current_token;
    }
    
    // Handle strings
    if (*start == '"') {
        lexer_src++;
        current_token.column++;
        start = lexer_src;
        while(*lexer_src != '"' && *lexer_src != '\0') {
            lexer_src++;
            current_token.column++;
        }
        if (*lexer_src == '"') {
            lexer_src++;
            current_token.column++;
        }
        current_token.type = TOKEN_STRING;
        current_token.value = strndup(start, lexer_src-start-1);
        return &current_token;
    }
    
    // Handle characters
    if (*start == '\'') {
        lexer_src++;
        current_token.column++;
        if (*lexer_src != '\0') {
            lexer_src++;
            current_token.column++;
        }
        if (*lexer_src == '\'') {
            lexer_src++;
            current_token.column++;
        }
        current_token.type = TOKEN_CHAR;
        current_token.value = strndup(start+1, 1);
        return &current_token;
    }
    
    // Handle operators and punctuation
    switch(*lexer_src) {
        case '+': 
            if (*(lexer_src+1) == '=') { 
                current_token.type = TOKEN_PLUS_ASSIGN; 
                lexer_src++; 
                current_token.column++;
            } else { 
                current_token.type = TOKEN_PLUS; 
            } 
            break;
        case '-': 
            if (*(lexer_src+1) == '>') { 
                current_token.type = TOKEN_ARROW; 
                lexer_src++; 
                current_token.column++;
            } else if (*(lexer_src+1) == '=') { 
                current_token.type = TOKEN_MINUS_ASSIGN; 
                lexer_src++; 
                current_token.column++;
            } else { 
                current_token.type = TOKEN_MINUS; 
            } 
            break;
        case '*': 
            if (*(lexer_src+1) == '=') { 
                current_token.type = TOKEN_MULTIPLY_ASSIGN; 
                lexer_src++; 
                current_token.column++;
            } else { 
                current_token.type = TOKEN_STAR; 
            } 
            break;
        case '/': 
            if (*(lexer_src+1) == '=') { 
                current_token.type = TOKEN_DIVIDE_ASSIGN; 
                lexer_src++; 
                current_token.column++;
            } else { 
                current_token.type = TOKEN_DIVIDE; 
            } 
            break;
        case '%': current_token.type = TOKEN_MODULO; break;
        case '^': current_token.type = TOKEN_POWER; break;
        case '=': 
            if (*(lexer_src+1) == '=') { 
                current_token.type = TOKEN_EQUALS; 
                lexer_src++; 
                current_token.column++;
            } else { 
                current_token.type = TOKEN_ASSIGN; 
            } 
            break;
        case '!': 
            if (*(lexer_src+1) == '=') { 
                current_token.type = TOKEN_NOT_EQUALS; 
                lexer_src++; 
                current_token.column++;
            } else { 
                current_token.type = TOKEN_LOGICAL_NOT; 
            } 
            break;
        case '>': 
            if (*(lexer_src+1) == '=') { 
                current_token.type = TOKEN_GREATER_EQUAL; 
                lexer_src++; 
                current_token.column++;
            } else if (*(lexer_src+1) == '>') { 
                current_token.type = TOKEN_RIGHT_SHIFT; 
                lexer_src++; 
                current_token.column++;
            } else { 
                current_token.type = TOKEN_GREATER; 
            } 
            break;
        case '<': 
            if (*(lexer_src+1) == '=') { 
                current_token.type = TOKEN_LESS_EQUAL; 
                lexer_src++; 
                current_token.column++;
            } else if (*(lexer_src+1) == '<') { 
                current_token.type = TOKEN_LEFT_SHIFT; 
                lexer_src++; 
                current_token.column++;
            } else { 
                current_token.type = TOKEN_LESS; 
            } 
            break;
        case '&': 
            if (*(lexer_src+1) == '&') { 
                current_token.type = TOKEN_LOGICAL_AND; 
                lexer_src++; 
                current_token.column++;
            } else { 
                current_token.type = TOKEN_AMPERSAND; 
            } 
            break;
        case '|': 
            if (*(lexer_src+1) == '|') { 
                current_token.type = TOKEN_LOGICAL_OR; 
                lexer_src++; 
                current_token.column++;
            } else { 
                current_token.type = TOKEN_BITWISE_OR; 
            } 
            break;
        case '~': current_token.type = TOKEN_BITWISE_NOT; break;
        case '(': current_token.type = TOKEN_LPAREN; break;
        case ')': current_token.type = TOKEN_RPAREN; break;
        case '{': current_token.type = TOKEN_LBRACE; break;
        case '}': current_token.type = TOKEN_RBRACE; break;
        case '[': current_token.type = TOKEN_LBRACKET; break;
        case ']': current_token.type = TOKEN_RBRACKET; break;
        case ';': current_token.type = TOKEN_SEMICOLON; break;
        case ',': current_token.type = TOKEN_COMMA; break;
        case '.': current_token.type = TOKEN_DOT; break;
        case ':': 
            if (*(lexer_src+1) == ':') { 
                current_token.type = TOKEN_DOUBLE_COLON; 
                lexer_src++; 
                current_token.column++;
            } else { 
                current_token.type = TOKEN_COLON; 
            } 
            break;
        case '?': current_token.type = TOKEN_QUESTION; break;
        default: 
            printf("Unknown token: '%c' at line %d, column %d\n", *lexer_src, current_token.line, current_token.column); 
            exit(1);
    }
    lexer_src++;
    current_token.column++;
    return &current_token;
}

// --- SYMBOL TABLE FUNCTIONS ---
void symtab_init() {
    global_scope = malloc(sizeof(Scope));
    global_scope->count = 0;
    global_scope->parent = NULL;
    global_scope->level = 0;
    current_scope = global_scope;
}

void symtab_push_scope() {
    Scope *new_scope = malloc(sizeof(Scope));
    new_scope->count = 0;
    new_scope->parent = current_scope;
    new_scope->level = current_scope->level + 1;
    current_scope = new_scope;
}

void symtab_pop_scope() {
    if (current_scope->parent) {
        Scope *parent_scope = current_scope->parent;
        free(current_scope);
        current_scope = parent_scope;
    }
}

Symbol *symtab_add(char *name, EonType *type) {
    if (current_scope->count >= MAX_SYMBOLS) {
        fprintf(stderr, "Error: Symbol table overflow at line %d\n", current_token.line);
        exit(1);
    }
    Symbol *sym = malloc(sizeof(Symbol));
    sym->name = strdup(name);
    sym->type = type;
    sym->stack_offset = 0;
    sym->is_function = 0;
    sym->is_parameter = 0;
    sym->is_shared = 0;
    current_scope->symbols[current_scope->count++] = sym;
    return sym;
}

Symbol *symtab_get(char *name) {
    Scope *scope = current_scope;
    while (scope) {
        for (int i = 0; i < scope->count; i++) {
            if (strcmp(scope->symbols[i]->name, name) == 0) {
                return scope->symbols[i];
            }
        }
        scope = scope->parent;
    }
    return NULL;
}

// --- TYPE SYSTEM FUNCTIONS ---
EonType *new_int_type() {
    EonType *type = malloc(sizeof(EonType));
    type->kind = TYPE_INT;
    type->size = 8;
    return type;
}

EonType *new_float_type() {
    EonType *type = malloc(sizeof(EonType));
    type->kind = TYPE_FLOAT;
    type->size = 8;
    return type;
}

EonType *new_bool_type() {
    EonType *type = malloc(sizeof(EonType));
    type->kind = TYPE_BOOL;
    type->size = 1;
    return type;
}

EonType *new_void_type() {
    EonType *type = malloc(sizeof(EonType));
    type->kind = TYPE_VOID;
    type->size = 0;
    return type;
}

EonType *new_pointer_type(EonType *base_type) {
    EonType *type = malloc(sizeof(EonType));
    type->kind = TYPE_POINTER;
    type->base_type = base_type;
    type->size = 8;
    return type;
}

EonType *new_struct_type(char *name) {
    EonType *type = malloc(sizeof(EonType));
    type->kind = TYPE_STRUCT;
    type->struct_name = strdup(name);
    type->size = 0; // Will be calculated later
    return type;
}

// --- AST NODE CREATION ---
AstNode *new_node(int type) {
    AstNode *node = malloc(sizeof(AstNode));
    node->type = type;
    node->left = NULL;
    node->right = NULL;
    node->next = NULL;
    node->type_info = NULL;
    node->line = current_token.line;
    node->column = current_token.column;
    return node;
}

// --- PARSER FUNCTIONS ---
void advance() { 
    lexer_next(); 
}

void expect(int type) {
    if (current_token.type != type) { 
        printf("Syntax error: expected token type %d, got %d ('%s') at line %d, column %d\n", 
               type, current_token.type, current_token.value ? current_token.value : "NULL", 
               current_token.line, current_token.column); 
        exit(1); 
    }
    advance();
}

// --- COMPREHENSIVE PARSER IMPLEMENTATION ---
AstNode *parse_expression();
AstNode *parse_primary();
AstNode *parse_statement();
AstNode *parse_block();
AstNode *parse_function_definition();
AstNode *parse_struct_definition();
AstNode *parse_top_level_declaration();

// Parse primary expressions (identifiers, numbers, strings, etc.)
AstNode *parse_primary() {
    AstNode *node = NULL;
    
    switch (current_token.type) {
        case TOKEN_NUMBER:
            node = new_node(AST_NUMBER);
            node->value = atoi(current_token.value);
            node->type_info = new_int_type();
            advance();
            break;
            
        case TOKEN_STRING:
            node = new_node(AST_STRING);
            node->name = strdup(current_token.value);
            advance();
            break;
            
        case TOKEN_CHAR:
            node = new_node(AST_CHAR);
            node->value = current_token.value[0];
            advance();
            break;
            
        case TOKEN_IDENTIFIER:
            node = new_node(AST_IDENTIFIER);
            node->name = strdup(current_token.value);
            advance();
            
            // Check for function calls
            if (current_token.type == TOKEN_LPAREN) {
                AstNode *call_node = new_node(AST_FUNCTION_CALL);
                call_node->data.func_call.name = node->name;
                advance(); // consume '('
                
                if (current_token.type != TOKEN_RPAREN) {
                    call_node->data.func_call.args = parse_expression();
                    AstNode *arg = call_node->data.func_call.args;
                    while (current_token.type == TOKEN_COMMA) {
                        advance(); // consume ','
                        arg->next = parse_expression();
                        arg = arg->next;
                    }
                }
                expect(TOKEN_RPAREN);
                free(node);
                return call_node;
            }
            
            // Check for member access
            if (current_token.type == TOKEN_DOT) {
                AstNode *member_node = new_node(AST_MEMBER_ACCESS);
                member_node->data.member_access.structure = node;
                advance(); // consume '.'
                expect(TOKEN_IDENTIFIER);
                member_node->data.member_access.member = new_node(AST_IDENTIFIER);
                member_node->data.member_access.member->name = strdup(current_token.value);
                advance();
                return member_node;
            }
            
            // Check for array access
            if (current_token.type == TOKEN_LBRACKET) {
                AstNode *array_node = new_node(AST_ARRAY_ACCESS);
                array_node->data.array_access.array = node;
                advance(); // consume '['
                array_node->data.array_access.index = parse_expression();
                expect(TOKEN_RBRACKET);
                return array_node;
            }
            break;
            
        case TOKEN_LPAREN:
            advance(); // consume '('
            node = parse_expression();
            expect(TOKEN_RPAREN);
            break;
            
        case TOKEN_AMPERSAND:
            advance(); // consume '&'
            node = new_node(AST_ADDRESS_OF);
            node->left = parse_primary();
            break;
            
        case TOKEN_STAR:
            advance(); // consume '*'
            node = new_node(AST_DEREFERENCE);
            node->left = parse_primary();
            break;
            
        case TOKEN_ALLOC:
            advance(); // consume 'alloc'
            expect(TOKEN_LPAREN);
            node = new_node(AST_ALLOC);
            node->left = parse_expression();
            expect(TOKEN_RPAREN);
            break;
            
        case TOKEN_FREE:
            advance(); // consume 'free'
            expect(TOKEN_LPAREN);
            node = new_node(AST_FREE);
            node->left = parse_expression();
            expect(TOKEN_RPAREN);
            break;
            
        case TOKEN_SIZEOF:
            advance(); // consume 'sizeof'
            expect(TOKEN_LPAREN);
            node = new_node(AST_SIZEOF);
            node->left = parse_expression();
            expect(TOKEN_RPAREN);
            break;
            
        default:
            printf("Unexpected token in primary expression: %d at line %d\n", 
                   current_token.type, current_token.line);
            exit(1);
    }
    
    return node;
}

// Parse expressions with operator precedence
AstNode *parse_expression() {
    return parse_logical_or();
}

AstNode *parse_logical_or() {
    AstNode *node = parse_logical_and();
    
    while (current_token.type == TOKEN_LOGICAL_OR) {
        AstNode *op_node = new_node(AST_OP);
        op_node->op = TOKEN_LOGICAL_OR;
        op_node->left = node;
        advance();
        op_node->right = parse_logical_and();
        node = op_node;
    }
    
    return node;
}

AstNode *parse_logical_and() {
    AstNode *node = parse_equality();
    
    while (current_token.type == TOKEN_LOGICAL_AND) {
        AstNode *op_node = new_node(AST_OP);
        op_node->op = TOKEN_LOGICAL_AND;
        op_node->left = node;
        advance();
        op_node->right = parse_equality();
        node = op_node;
    }
    
    return node;
}

AstNode *parse_equality() {
    AstNode *node = parse_relational();
    
    while (current_token.type == TOKEN_EQUALS || current_token.type == TOKEN_NOT_EQUALS) {
        AstNode *op_node = new_node(AST_OP);
        op_node->op = current_token.type;
        op_node->left = node;
        advance();
        op_node->right = parse_relational();
        node = op_node;
    }
    
    return node;
}

AstNode *parse_relational() {
    AstNode *node = parse_additive();
    
    while (current_token.type == TOKEN_GREATER || current_token.type == TOKEN_GREATER_EQUAL ||
           current_token.type == TOKEN_LESS || current_token.type == TOKEN_LESS_EQUAL) {
        AstNode *op_node = new_node(AST_OP);
        op_node->op = current_token.type;
        op_node->left = node;
        advance();
        op_node->right = parse_additive();
        node = op_node;
    }
    
    return node;
}

AstNode *parse_additive() {
    AstNode *node = parse_multiplicative();
    
    while (current_token.type == TOKEN_PLUS || current_token.type == TOKEN_MINUS) {
        AstNode *op_node = new_node(AST_OP);
        op_node->op = current_token.type;
        op_node->left = node;
        advance();
        op_node->right = parse_multiplicative();
        node = op_node;
    }
    
    return node;
}

AstNode *parse_multiplicative() {
    AstNode *node = parse_unary();
    
    while (current_token.type == TOKEN_STAR || current_token.type == TOKEN_DIVIDE || 
           current_token.type == TOKEN_MODULO) {
        AstNode *op_node = new_node(AST_OP);
        op_node->op = current_token.type;
        op_node->left = node;
        advance();
        op_node->right = parse_unary();
        node = op_node;
    }
    
    return node;
}

AstNode *parse_unary() {
    if (current_token.type == TOKEN_LOGICAL_NOT || current_token.type == TOKEN_MINUS ||
        current_token.type == TOKEN_BITWISE_NOT) {
        AstNode *node = new_node(AST_OP);
        node->op = current_token.type;
        advance();
        node->right = parse_unary();
        return node;
    }
    
    return parse_primary();
}

// Parse statements
AstNode *parse_statement() {
    AstNode *node = NULL;
    
    switch (current_token.type) {
        case TOKEN_LET:
            advance(); // consume 'let'
            node = new_node(AST_VAR_DECL);
            expect(TOKEN_IDENTIFIER);
            node->data.var_decl.name = strdup(current_token.value);
            advance();
            
            if (current_token.type == TOKEN_COLON) {
                advance(); // consume ':'
                // Parse type (simplified)
                node->type_info = new_int_type(); // Default to int
                advance();
            }
            
            if (current_token.type == TOKEN_ASSIGN) {
                advance(); // consume '='
                node->data.var_decl.init_expr = parse_expression();
            }
            expect(TOKEN_SEMICOLON);
            break;
            
        case TOKEN_IF:
            advance(); // consume 'if'
            node = new_node(AST_IF);
            expect(TOKEN_LPAREN);
            node->cond = parse_expression();
            expect(TOKEN_RPAREN);
            node->body = parse_statement();
            
            if (current_token.type == TOKEN_ELSE) {
                advance(); // consume 'else'
                node->right = parse_statement();
            }
            break;
            
        case TOKEN_RET:
            advance(); // consume 'ret'
            node = new_node(AST_RET);
            if (current_token.type != TOKEN_SEMICOLON) {
                node->left = parse_expression();
            }
            expect(TOKEN_SEMICOLON);
            break;
            
        case TOKEN_LBRACE:
            node = parse_block();
            break;
            
        case TOKEN_LOOP:
            advance(); // consume 'loop'
            node = new_node(AST_WHILE_LOOP);
            expect(TOKEN_LPAREN);
            node->cond = parse_expression();
            expect(TOKEN_RPAREN);
            node->body = parse_statement();
            break;
            
        case TOKEN_BREAK:
            advance(); // consume 'break'
            node = new_node(AST_BREAK);
            expect(TOKEN_SEMICOLON);
            break;
            
        case TOKEN_CONTINUE:
            advance(); // consume 'continue'
            node = new_node(AST_CONTINUE);
            expect(TOKEN_SEMICOLON);
            break;
            
        case TOKEN_SPAWN:
            advance(); // consume 'spawn'
            node = new_node(AST_SPAWN);
            node->left = parse_expression();
            expect(TOKEN_SEMICOLON);
            break;
            
        default:
            // Try to parse as expression statement
            node = parse_expression();
            if (current_token.type == TOKEN_SEMICOLON) {
                advance();
            }
            break;
    }
    
    return node;
}

// Parse block statements
AstNode *parse_block() {
    AstNode *node = new_node(AST_BLOCK);
    expect(TOKEN_LBRACE);
    
    AstNode *stmt = NULL;
    AstNode *last_stmt = NULL;
    
    while (current_token.type != TOKEN_RBRACE && current_token.type != TOKEN_EOF) {
        stmt = parse_statement();
        if (last_stmt == NULL) {
            node->body = stmt;
        } else {
            last_stmt->next = stmt;
        }
        last_stmt = stmt;
    }
    
    expect(TOKEN_RBRACE);
    return node;
}

// Parse function definitions
AstNode *parse_function_definition() {
    AstNode *node = new_node(AST_FUNCTION_DEFINITION);
    
    if (current_token.type == TOKEN_DEF) {
        advance(); // consume 'def'
    }
    
    expect(TOKEN_FUNC);
    expect(TOKEN_IDENTIFIER);
    node->data.func_def.name = strdup(current_token.value);
    advance();
    
    expect(TOKEN_LPAREN);
    
    // Parse parameters
    if (current_token.type != TOKEN_RPAREN) {
        AstNode *param = new_node(AST_PARAMETER);
        expect(TOKEN_IDENTIFIER);
        param->name = strdup(current_token.value);
        advance();
        
        if (current_token.type == TOKEN_COLON) {
            advance(); // consume ':'
            param->type_info = new_int_type(); // Default to int
        }
        
        node->data.func_def.params = param;
        AstNode *last_param = param;
        
        while (current_token.type == TOKEN_COMMA) {
            advance(); // consume ','
            param = new_node(AST_PARAMETER);
            expect(TOKEN_IDENTIFIER);
            param->name = strdup(current_token.value);
            advance();
            
            if (current_token.type == TOKEN_COLON) {
                advance(); // consume ':'
                param->type_info = new_int_type(); // Default to int
            }
            
            last_param->next = param;
            last_param = param;
        }
    }
    
    expect(TOKEN_RPAREN);
    
    // Parse return type
    if (current_token.type == TOKEN_ARROW) {
        advance(); // consume '->'
        node->data.func_def.return_type = new_int_type(); // Default to int
    } else {
        node->data.func_def.return_type = new_void_type();
    }
    
    // Parse function body
    node->data.func_def.body = parse_block();
    
    return node;
}

// Parse struct definitions
AstNode *parse_struct_definition() {
    AstNode *node = new_node(AST_STRUCT_DEFINITION);
    
    expect(TOKEN_MODEL);
    expect(TOKEN_IDENTIFIER);
    node->data.struct_def.name = strdup(current_token.value);
    advance();
    
    expect(TOKEN_LBRACE);
    
    // Parse fields
    if (current_token.type != TOKEN_RBRACE) {
        AstNode *field = new_node(AST_STRUCT_FIELD);
        expect(TOKEN_IDENTIFIER);
        field->name = strdup(current_token.value);
        advance();
        
        if (current_token.type == TOKEN_COLON) {
            advance(); // consume ':'
            field->type_info = new_int_type(); // Default to int
        }
        
        node->data.struct_def.fields = field;
        AstNode *last_field = field;
        
        while (current_token.type == TOKEN_COMMA) {
            advance(); // consume ','
            field = new_node(AST_STRUCT_FIELD);
            expect(TOKEN_IDENTIFIER);
            field->name = strdup(current_token.value);
            advance();
            
            if (current_token.type == TOKEN_COLON) {
                advance(); // consume ':'
                field->type_info = new_int_type(); // Default to int
            }
            
            last_field->next = field;
            last_field = field;
        }
    }
    
    expect(TOKEN_RBRACE);
    return node;
}

// Parse top-level declarations
AstNode *parse_top_level_declaration() {
    switch (current_token.type) {
        case TOKEN_DEF:
        case TOKEN_FUNC:
            return parse_function_definition();
        case TOKEN_MODEL:
            return parse_struct_definition();
        default:
            return parse_statement();
    }
}

// Parse entire program
AstNode *parse_program() {
    AstNode *node = new_node(AST_PROGRAM);
    AstNode *decl = NULL;
    AstNode *last_decl = NULL;
    
    while (current_token.type != TOKEN_EOF) {
        decl = parse_top_level_declaration();
        if (node->body == NULL) {
            node->body = decl;
        } else {
            last_decl->next = decl;
        }
        last_decl = decl;
    }
    
    return node;
}

// --- SEMANTIC ANALYSIS ---
void semantic_pass(AstNode *node) {
    if (!node) return;

    switch (node->type) {
        case AST_VAR_DECL: {
            // Check if variable is already declared in current scope
            Symbol *existing = symtab_get(node->data.var_decl.name);
            if (existing && existing->is_function == 0) {
                fprintf(stderr, "Error: Variable '%s' already declared at line %d\n", 
                        node->data.var_decl.name, node->line);
                exit(1);
            }
            
            // Add to symbol table
            EonType *type = node->type_info ? node->type_info : new_int_type();
            Symbol *sym = symtab_add(node->data.var_decl.name, type);
            
            // Check initialization expression
            if (node->data.var_decl.init_expr) {
                semantic_pass(node->data.var_decl.init_expr);
                // Type checking would go here
            }
            break;
        }
        
        case AST_ASSIGN: {
            // Check if variable exists
            Symbol *sym = symtab_get(node->name);
            if (!sym) {
                fprintf(stderr, "Error: Undefined variable '%s' at line %d\n", 
                        node->name, node->line);
                exit(1);
            }
            
            // Check assignment expression
            semantic_pass(node->left);
            // Type checking would go here
            break;
        }
        
        case AST_FUNCTION_CALL: {
            // Check if function exists
            Symbol *func_sym = symtab_get(node->data.func_call.name);
            if (!func_sym || !func_sym->is_function) {
                fprintf(stderr, "Error: Undefined function '%s' at line %d\n", 
                        node->data.func_call.name, node->line);
                exit(1);
            }
            
            // Check arguments
            AstNode *arg = node->data.func_call.args;
            while (arg) {
                semantic_pass(arg);
                arg = arg->next;
            }
            break;
        }
        
        case AST_MEMBER_ACCESS: {
            semantic_pass(node->data.member_access.structure);
            // Check if structure is a struct type and member exists
            break;
        }
        
        case AST_DEREFERENCE: {
            semantic_pass(node->left);
            // Check if left operand is a pointer
            break;
        }
        
        case AST_ADDRESS_OF: {
            semantic_pass(node->left);
            // Check if left operand is addressable
            break;
        }
        
        case AST_IF:
        case AST_WHILE_LOOP:
        case AST_FOR_LOOP: {
            symtab_push_scope();
            semantic_pass(node->cond);
            semantic_pass(node->body);
            symtab_pop_scope();
            break;
        }
        
        case AST_FUNCTION_DEFINITION: {
            // Add function to symbol table
            Symbol *func_sym = symtab_add(node->data.func_def.name, node->data.func_def.return_type);
            func_sym->is_function = 1;
            
            symtab_push_scope();
            
            // Add parameters to symbol table
            AstNode *param = node->data.func_def.params;
            while (param) {
                Symbol *param_sym = symtab_add(param->name, param->type_info);
                param_sym->is_parameter = 1;
                param = param->next;
            }
            
            semantic_pass(node->data.func_def.body);
            symtab_pop_scope();
            break;
        }
        
        case AST_STRUCT_DEFINITION: {
            // Add struct to symbol table
            EonType *struct_type = new_struct_type(node->data.struct_def.name);
            symtab_add(node->data.struct_def.name, struct_type);
            break;
        }
        
        case AST_OP: {
            semantic_pass(node->left);
            semantic_pass(node->right);
            // Type checking for operators would go here
            break;
        }
        
        case AST_IDENTIFIER: {
            Symbol *sym = symtab_get(node->name);
            if (!sym) {
                fprintf(stderr, "Error: Undefined variable '%s' at line %d\n", 
                        node->name, node->line);
                exit(1);
            }
            node->type_info = sym->type;
            break;
        }
        
        case AST_NUMBER:
            node->type_info = new_int_type();
            break;
            
        case AST_STRING:
            // String type would be defined here
            break;
            
        default:
            break;
    }
    
    // Recursively process child nodes
    semantic_pass(node->left);
    semantic_pass(node->right);
    semantic_pass(node->next);
}

// --- INTERMEDIATE REPRESENTATION GENERATION ---
int temp_var_count = 0;
int label_var_count = 0;

char *new_temp_var() {
    char *temp = malloc(16);
    sprintf(temp, "_t%d", temp_var_count++);
    return temp;
}

char *new_label() {
    char *label = malloc(16);
    sprintf(label, "_L%d", label_var_count++);
    return label;
}

TacList *new_tac_list() {
    TacList *list = malloc(sizeof(TacList));
    list->head = NULL;
    list->tail = NULL;
    list->count = 0;
    return list;
}

TacEntry *new_tac_entry(TacOpcode opcode, char *arg1, char *arg2, char *result) {
    TacEntry *entry = malloc(sizeof(TacEntry));
    entry->opcode = opcode;
    entry->arg1 = arg1 ? strdup(arg1) : NULL;
    entry->arg2 = arg2 ? strdup(arg2) : NULL;
    entry->result = result ? strdup(result) : NULL;
    entry->next = NULL;
    return entry;
}

void tac_list_add(TacList *list, TacEntry *entry) {
    if (list->tail == NULL) {
        list->head = entry;
        list->tail = entry;
    } else {
        list->tail->next = entry;
        list->tail = entry;
    }
    list->count++;
}

char *ast_to_ir_expr(AstNode *node, TacList *ir_list);
void ast_to_ir_stmt(AstNode *node, TacList *ir_list);

char *ast_to_ir_expr(AstNode *node, TacList *ir_list) {
    if (!node) return NULL;
    
    char *result = NULL;
    
    switch (node->type) {
        case AST_NUMBER: {
            result = malloc(16);
            sprintf(result, "%d", node->value);
            break;
        }
        
        case AST_IDENTIFIER: {
            result = strdup(node->name);
            break;
        }
        
        case AST_OP: {
            char *left = ast_to_ir_expr(node->left, ir_list);
            char *right = ast_to_ir_expr(node->right, ir_list);
            result = new_temp_var();
            
            TacOpcode opcode;
            switch (node->op) {
                case TOKEN_PLUS: opcode = TAC_ADD; break;
                case TOKEN_MINUS: opcode = TAC_SUB; break;
                case TOKEN_STAR: opcode = TAC_MUL; break;
                case TOKEN_DIVIDE: opcode = TAC_DIV; break;
                case TOKEN_MODULO: opcode = TAC_MOD; break;
                case TOKEN_EQUALS: opcode = TAC_EQUALS; break;
                case TOKEN_NOT_EQUALS: opcode = TAC_NOT_EQUALS; break;
                case TOKEN_GREATER: opcode = TAC_GREATER; break;
                case TOKEN_GREATER_EQUAL: opcode = TAC_GREATER_EQUAL; break;
                case TOKEN_LESS: opcode = TAC_LESS; break;
                case TOKEN_LESS_EQUAL: opcode = TAC_LESS_EQUAL; break;
                case TOKEN_LOGICAL_AND: opcode = TAC_LOGICAL_AND; break;
                case TOKEN_LOGICAL_OR: opcode = TAC_LOGICAL_OR; break;
                default: opcode = TAC_ADD; break;
            }
            
            tac_list_add(ir_list, new_tac_entry(opcode, left, right, result));
            break;
        }
        
        case AST_FUNCTION_CALL: {
            result = new_temp_var();
            
            // Generate parameter passing
            AstNode *arg = node->data.func_call.args;
            while (arg) {
                char *arg_result = ast_to_ir_expr(arg, ir_list);
                tac_list_add(ir_list, new_tac_entry(TAC_PARAM, arg_result, NULL, NULL));
                arg = arg->next;
            }
            
            tac_list_add(ir_list, new_tac_entry(TAC_CALL, node->data.func_call.name, NULL, result));
            break;
        }
        
        case AST_DEREFERENCE: {
            char *ptr = ast_to_ir_expr(node->left, ir_list);
            result = new_temp_var();
            tac_list_add(ir_list, new_tac_entry(TAC_LOAD_MEM, ptr, NULL, result));
            break;
        }
        
        case AST_ADDRESS_OF: {
            result = new_temp_var();
            tac_list_add(ir_list, new_tac_entry(TAC_LOAD_ADDR, node->left->name, NULL, result));
            break;
        }
        
        case AST_ALLOC: {
            char *size = ast_to_ir_expr(node->left, ir_list);
            result = new_temp_var();
            tac_list_add(ir_list, new_tac_entry(TAC_ALLOC, size, NULL, result));
            break;
        }
        
        case AST_SIZEOF: {
            result = new_temp_var();
            tac_list_add(ir_list, new_tac_entry(TAC_LOAD_MEM, "8", NULL, result)); // Simplified
            break;
        }
        
        default:
            result = strdup("0");
            break;
    }
    
    return result;
}

void ast_to_ir_stmt(AstNode *node, TacList *ir_list) {
    if (!node) return;
    
    switch (node->type) {
        case AST_VAR_DECL: {
            if (node->data.var_decl.init_expr) {
                char *init_result = ast_to_ir_expr(node->data.var_decl.init_expr, ir_list);
                tac_list_add(ir_list, new_tac_entry(TAC_ASSIGN, init_result, NULL, node->data.var_decl.name));
            }
            break;
        }
        
        case AST_ASSIGN: {
            char *expr_result = ast_to_ir_expr(node->left, ir_list);
            tac_list_add(ir_list, new_tac_entry(TAC_ASSIGN, expr_result, NULL, node->name));
            break;
        }
        
        case AST_IF: {
            char *cond_result = ast_to_ir_expr(node->cond, ir_list);
            char *else_label = new_label();
            char *end_label = new_label();
            
            tac_list_add(ir_list, new_tac_entry(TAC_IF_GOTO, cond_result, NULL, else_label));
            ast_to_ir_stmt(node->body, ir_list);
            tac_list_add(ir_list, new_tac_entry(TAC_GOTO, end_label, NULL, NULL));
            tac_list_add(ir_list, new_tac_entry(TAC_LABEL, else_label, NULL, NULL));
            
            if (node->right) {
                ast_to_ir_stmt(node->right, ir_list);
            }
            
            tac_list_add(ir_list, new_tac_entry(TAC_LABEL, end_label, NULL, NULL));
            break;
        }
        
        case AST_WHILE_LOOP: {
            char *start_label = new_label();
            char *end_label = new_label();
            
            tac_list_add(ir_list, new_tac_entry(TAC_LABEL, start_label, NULL, NULL));
            char *cond_result = ast_to_ir_expr(node->cond, ir_list);
            tac_list_add(ir_list, new_tac_entry(TAC_IF_GOTO, cond_result, NULL, end_label));
            ast_to_ir_stmt(node->body, ir_list);
            tac_list_add(ir_list, new_tac_entry(TAC_GOTO, start_label, NULL, NULL));
            tac_list_add(ir_list, new_tac_entry(TAC_LABEL, end_label, NULL, NULL));
            break;
        }
        
        case AST_RET: {
            if (node->left) {
                char *ret_result = ast_to_ir_expr(node->left, ir_list);
                tac_list_add(ir_list, new_tac_entry(TAC_RETURN, ret_result, NULL, NULL));
            } else {
                tac_list_add(ir_list, new_tac_entry(TAC_RETURN, NULL, NULL, NULL));
            }
            break;
        }
        
        case AST_BLOCK: {
            AstNode *stmt = node->body;
            while (stmt) {
                ast_to_ir_stmt(stmt, ir_list);
                stmt = stmt->next;
            }
            break;
        }
        
        case AST_FUNCTION_DEFINITION: {
            // Function definition IR generation would go here
            ast_to_ir_stmt(node->data.func_def.body, ir_list);
            break;
        }
        
        default:
            // Try to generate as expression
            ast_to_ir_expr(node, ir_list);
            break;
    }
}

// --- CODE GENERATION ---
void generate_from_ir(FILE *out, TacList *ir_list) {
    fprintf(out, "section .text\n");
    fprintf(out, "global main\n");
    fprintf(out, "extern printf\n");
    fprintf(out, "extern malloc\n");
    fprintf(out, "extern free\n");
    fprintf(out, "main:\n");
    fprintf(out, "    push rbp\n");
    fprintf(out, "    mov rbp, rsp\n");
    fprintf(out, "    sub rsp, 1024\n"); // Allocate stack space
    
    TacEntry *current = ir_list->head;
    while (current) {
        switch (current->opcode) {
            case TAC_ASSIGN:
                if (current->arg1 && isdigit(current->arg1[0])) {
                    fprintf(out, "    mov rax, %s\n", current->arg1);
                } else {
                    fprintf(out, "    mov rax, [rbp-%d]\n", 8); // Simplified offset
                }
                fprintf(out, "    mov [rbp-%d], rax\n", 8); // Simplified offset
                break;
                
            case TAC_ADD:
                fprintf(out, "    mov rax, %s\n", current->arg1);
                fprintf(out, "    mov rbx, %s\n", current->arg2);
                fprintf(out, "    add rax, rbx\n");
                fprintf(out, "    mov [rbp-%d], rax\n", 8);
                break;
                
            case TAC_SUB:
                fprintf(out, "    mov rax, %s\n", current->arg1);
                fprintf(out, "    mov rbx, %s\n", current->arg2);
                fprintf(out, "    sub rax, rbx\n");
                fprintf(out, "    mov [rbp-%d], rax\n", 8);
                break;
                
            case TAC_MUL:
                fprintf(out, "    mov rax, %s\n", current->arg1);
                fprintf(out, "    mov rbx, %s\n", current->arg2);
                fprintf(out, "    imul rax, rbx\n");
                fprintf(out, "    mov [rbp-%d], rax\n", 8);
                break;
                
            case TAC_DIV:
                fprintf(out, "    mov rax, %s\n", current->arg1);
                fprintf(out, "    mov rbx, %s\n", current->arg2);
                fprintf(out, "    xor rdx, rdx\n");
                fprintf(out, "    idiv rbx\n");
                fprintf(out, "    mov [rbp-%d], rax\n", 8);
                break;
                
            case TAC_RETURN:
                if (current->arg1) {
                    fprintf(out, "    mov rax, %s\n", current->arg1);
                }
                fprintf(out, "    leave\n");
                fprintf(out, "    ret\n");
                break;
                
            case TAC_IF_GOTO:
                fprintf(out, "    cmp %s, 0\n", current->arg1);
                fprintf(out, "    je %s\n", current->result);
                break;
                
            case TAC_GOTO:
                fprintf(out, "    jmp %s\n", current->arg1);
                break;
                
            case TAC_LABEL:
                fprintf(out, "%s:\n", current->arg1);
                break;
                
            case TAC_CALL:
                if (strcmp(current->arg1, "print") == 0) {
                    fprintf(out, "    mov rdi, %s\n", current->arg2);
                    fprintf(out, "    call print_int\n");
                } else {
                    fprintf(out, "    call %s\n", current->arg1);
                }
                fprintf(out, "    mov [rbp-%d], rax\n", 8);
                break;
                
            case TAC_ALLOC:
                fprintf(out, "    mov rdi, %s\n", current->arg1);
                fprintf(out, "    call malloc\n");
                fprintf(out, "    mov [rbp-%d], rax\n", 8);
                break;
                
            case TAC_FREE:
                fprintf(out, "    mov rdi, %s\n", current->arg1);
                fprintf(out, "    call free\n");
                break;
        }
        current = current->next;
    }
    
    // Add print function
    fprintf(out, "print_int:\n");
    fprintf(out, "    push rbp\n");
    fprintf(out, "    mov rbp, rsp\n");
    fprintf(out, "    mov rsi, rdi\n");
    fprintf(out, "    mov rdi, print_fmt\n");
    fprintf(out, "    mov rax, 0\n");
    fprintf(out, "    call printf\n");
    fprintf(out, "    leave\n");
    fprintf(out, "    ret\n");
    
    fprintf(out, "section .data\n");
    fprintf(out, "print_fmt: db \"%%d\", 10, 0\n");
}

// --- OPTIMIZATION PASSES ---
int is_numeric(char *str) {
    if (!str) return 0;
    for (int i = 0; str[i] != '\0'; i++) {
        if (!isdigit(str[i]) && (i != 0 || str[i] != '-')) return 0;
    }
    return 1;
}

void optimize_ir(TacList *ir_list) {
    TacEntry *current = ir_list->head;
    while (current) {
        // Constant folding
        if (current->opcode == TAC_ADD && is_numeric(current->arg1) && is_numeric(current->arg2)) {
            int val1 = atoi(current->arg1);
            int val2 = atoi(current->arg2);
            int result = val1 + val2;
            char *res_str = malloc(16);
            sprintf(res_str, "%d", result);
            current->opcode = TAC_ASSIGN;
            current->arg1 = res_str;
            current->arg2 = NULL;
        }
        else if (current->opcode == TAC_SUB && is_numeric(current->arg1) && is_numeric(current->arg2)) {
            int val1 = atoi(current->arg1);
            int val2 = atoi(current->arg2);
            int result = val1 - val2;
            char *res_str = malloc(16);
            sprintf(res_str, "%d", result);
            current->opcode = TAC_ASSIGN;
            current->arg1 = res_str;
            current->arg2 = NULL;
        }
        else if (current->opcode == TAC_MUL && is_numeric(current->arg1) && is_numeric(current->arg2)) {
            int val1 = atoi(current->arg1);
            int val2 = atoi(current->arg2);
            int result = val1 * val2;
            char *res_str = malloc(16);
            sprintf(res_str, "%d", result);
            current->opcode = TAC_ASSIGN;
            current->arg1 = res_str;
            current->arg2 = NULL;
        }
        else if (current->opcode == TAC_DIV && is_numeric(current->arg1) && is_numeric(current->arg2)) {
            int val1 = atoi(current->arg1);
            int val2 = atoi(current->arg2);
            if (val2 != 0) {
                int result = val1 / val2;
                char *res_str = malloc(16);
                sprintf(res_str, "%d", result);
                current->opcode = TAC_ASSIGN;
                current->arg1 = res_str;
                current->arg2 = NULL;
            }
        }
        
        current = current->next;
    }
}

// --- MAIN FUNCTION ---
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <source_file>\n", argv[0]);
        exit(1);
    }
    
    FILE *src_file = fopen(argv[1], "r");
    if (!src_file) {
        perror("Failed to open source file");
        exit(1);
    }
    
    fseek(src_file, 0, SEEK_END);
    long fsize = ftell(src_file);
    fseek(src_file, 0, SEEK_SET);
    
    char *src = malloc(fsize + 1);
    if (!src) {
        perror("Memory allocation failed");
        fclose(src_file);
        exit(1);
    }
    fread(src, 1, fsize, src_file);
    src[fsize] = '\0';
    fclose(src_file);
    
    printf("Enhanced EON Compiler v2.0\n");
    printf("Source file: %s (%ld bytes)\n", argv[1], fsize);
    
    // Initialize compiler components
    lexer_init(src);
    advance(); // Load the first token
    symtab_init();
    
    // Parse the program
    printf("Parsing...\n");
    AstNode *ast = parse_program();
    printf("Parsing completed successfully!\n");
    
    // Perform semantic analysis
    printf("Performing semantic analysis...\n");
    semantic_pass(ast);
    printf("Semantic analysis completed successfully!\n");
    
    // Generate Intermediate Representation
    printf("Generating Intermediate Representation...\n");
    TacList *ir_list = new_tac_list();
    ast_to_ir_stmt(ast, ir_list);
    printf("IR generation completed! Generated %d TAC instructions.\n", ir_list->count);
    
    // Optimize the IR
    printf("Optimizing IR...\n");
    optimize_ir(ir_list);
    printf("Optimization completed!\n");
    
    // Generate assembly code
    printf("Generating assembly code...\n");
    FILE *out_file = fopen("out.asm", "w");
    if (!out_file) {
        perror("Failed to create output file");
        free(src);
        exit(1);
    }
    generate_from_ir(out_file, ir_list);
    fclose(out_file);
    printf("Assembly code written to out.asm\n");
    
    // Cleanup
    free(src);
    
    printf("\nCompilation successful!\n");
    printf("To compile and run:\n");
    printf("  nasm -f elf64 out.asm\n");
    printf("  gcc out.o -o program\n");
    printf("  ./program\n");
    
    return 0;
}
