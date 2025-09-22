#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

// --- Security Globals ---
unsigned long long security_cookie;

// --- Global Compiler State ---
char *lexer_src;
Token current_token;
int if_count = 0;
int func_count = 0;

// --- LEXER (Enhanced) ---
typedef struct Token {
    enum {
        TOKEN_EOF, TOKEN_IDENTIFIER, TOKEN_NUMBER, TOKEN_RET, TOKEN_LET, TOKEN_IF,
        TOKEN_LPAREN, TOKEN_RPAREN, TOKEN_LBRACE, TOKEN_RBRACE, TOKEN_EQ,
        TOKEN_ADD, TOKEN_SUB, TOKEN_MUL, TOKEN_DIV, TOKEN_GT, TOKEN_DEF,
        TOKEN_FUNC, TOKEN_MODEL, TOKEN_STAR, TOKEN_AMPERSAND, TOKEN_ALLOC,
        TOKEN_SIZEOF, TOKEN_COLON, TOKEN_ARROW, TOKEN_COMMA, TOKEN_SPAWN, TOKEN_SHARED,
        TOKEN_INT, TOKEN_PTR, TOKEN_SEMICOLON, TOKEN_LT, TOKEN_LE, TOKEN_GE, TOKEN_NE, TOKEN_EQ_EQ
    } type;
    char *value;
    int line;
    int column;
} Token;

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
    current_token.column = lexer_src - start + 1;
    
    if (isalpha(*start)) {
        while(isalnum(*lexer_src)) lexer_src++;
        char *word = strndup(start, lexer_src-start);
        if (strcmp(word,"def")==0) { current_token.type = TOKEN_DEF; }
        else if (strcmp(word,"func")==0) { current_token.type = TOKEN_FUNC; }
        else if (strcmp(word,"model")==0) { current_token.type = TOKEN_MODEL; }
        else if (strcmp(word,"let")==0) { current_token.type = TOKEN_LET; }
        else if (strcmp(word,"if")==0) { current_token.type = TOKEN_IF; }
        else if (strcmp(word,"ret")==0) { current_token.type = TOKEN_RET; }
        else if (strcmp(word,"alloc")==0) { current_token.type = TOKEN_ALLOC; }
        else if (strcmp(word,"sizeof")==0) { current_token.type = TOKEN_SIZEOF; }
        else if (strcmp(word,"spawn")==0) { current_token.type = TOKEN_SPAWN; }
        else if (strcmp(word,"shared")==0) { current_token.type = TOKEN_SHARED; }
        else if (strcmp(word,"int")==0) { current_token.type = TOKEN_INT; }
        else if (strcmp(word,"ptr")==0) { current_token.type = TOKEN_PTR; }
        else { current_token.type = TOKEN_IDENTIFIER; }
        current_token.value = word;
    }
    else if (isdigit(*start)) {
        while(isdigit(*lexer_src)) lexer_src++;
        current_token.type = TOKEN_NUMBER;
        current_token.value = strndup(start, lexer_src-start);
    }
    else {
        switch(*lexer_src++) {
            case '(': current_token.type = TOKEN_LPAREN; current_token.value = strdup("("); break;
            case ')': current_token.type = TOKEN_RPAREN; current_token.value = strdup(")"); break;
            case '{': current_token.type = TOKEN_LBRACE; current_token.value = strdup("{"); break;
            case '}': current_token.type = TOKEN_RBRACE; current_token.value = strdup("}"); break;
            case '=': 
                if (*lexer_src == '=') {
                    lexer_src++;
                    current_token.type = TOKEN_EQ_EQ;
                    current_token.value = strdup("==");
                } else {
                    current_token.type = TOKEN_EQ;
                    current_token.value = strdup("=");
                }
                break;
            case '+': current_token.type = TOKEN_ADD; current_token.value = strdup("+"); break;
            case '-': 
                if (*lexer_src == '>') {
                    lexer_src++;
                    current_token.type = TOKEN_ARROW;
                    current_token.value = strdup("->");
                } else {
                    current_token.type = TOKEN_SUB;
                    current_token.value = strdup("-");
                }
                break;
            case '*': current_token.type = TOKEN_STAR; current_token.value = strdup("*"); break;
            case '/': current_token.type = TOKEN_DIV; current_token.value = strdup("/"); break;
            case '>': 
                if (*lexer_src == '=') {
                    lexer_src++;
                    current_token.type = TOKEN_GE;
                    current_token.value = strdup(">=");
                } else {
                    current_token.type = TOKEN_GT;
                    current_token.value = strdup(">");
                }
                break;
            case '<': 
                if (*lexer_src == '=') {
                    lexer_src++;
                    current_token.type = TOKEN_LE;
                    current_token.value = strdup("<=");
                } else {
                    current_token.type = TOKEN_LT;
                    current_token.value = strdup("<");
                }
                break;
            case '!': 
                if (*lexer_src == '=') {
                    lexer_src++;
                    current_token.type = TOKEN_NE;
                    current_token.value = strdup("!=");
                } else {
                    printf("Error: Unknown token '!'\n");
                    exit(1);
                }
                break;
            case '&': current_token.type = TOKEN_AMPERSAND; current_token.value = strdup("&"); break;
            case ':': current_token.type = TOKEN_COLON; current_token.value = strdup(":"); break;
            case ',': current_token.type = TOKEN_COMMA; current_token.value = strdup(","); break;
            case ';': current_token.type = TOKEN_SEMICOLON; current_token.value = strdup(";"); break;
            default: printf("Error: Unknown token '%c'\n", *(lexer_src-1)); exit(1);
        }
    }
    return &current_token;
}

// --- AST (Enhanced) ---
typedef struct AstNode {
    enum {
        AST_NUMBER, AST_OP, AST_IDENTIFIER, AST_VAR_DECL, AST_ASSIGN, AST_IF, AST_RET, AST_BLOCK,
        AST_FUNCTION_DEFINITION, AST_FUNCTION_CALL, AST_STRUCT_DEFINITION, AST_POINTER_TYPE,
        AST_DEREFERENCE, AST_ADDRESS_OF, AST_PARAMETER, AST_STRUCT_FIELD, AST_PROGRAM, AST_ALLOC,
        AST_SIZEOF, AST_FUNCTION_PROTOTYPE, AST_SPAWN, AST_ASSIGN_DEREF, AST_TYPE_DECL
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
    struct AstNode *return_type;
    int is_shared;
    int line;
    int column;
} AstNode;

// --- SYMBOL TABLE (Advanced with Scoping) ---
#define MAX_SYMBOLS 128

typedef enum { 
    TYPE_INT, 
    TYPE_PTR, 
    TYPE_FUNC,
    TYPE_STRUCT,
    TYPE_VOID 
} SymbolType;

typedef struct {
    char *name;
    int stack_offset;
    SymbolType type;
    int is_shared;
    int is_parameter;
    int scope_level;
    AstNode *type_node;  // For complex types
    AstNode *function_node; // For function symbols
} Symbol;

typedef struct Scope {
    Symbol symbols[MAX_SYMBOLS];
    int count;
    int stack_size;
    int level;
    struct Scope *parent;
    char *name; // For debugging
} Scope;

Scope *global_scope;
Scope *current_scope;
int scope_level = 0;

// --- Scope Management ---
void init_scopes() {
    global_scope = malloc(sizeof(Scope));
    global_scope->count = 0;
    global_scope->stack_size = 0;
    global_scope->parent = NULL;
    global_scope->level = 0;
    global_scope->name = strdup("global");
    current_scope = global_scope;
    scope_level = 0;
}

void push_scope(char *name) {
    Scope *new_scope = malloc(sizeof(Scope));
    new_scope->count = 0;
    new_scope->stack_size = 0;
    new_scope->parent = current_scope;
    new_scope->level = ++scope_level;
    new_scope->name = name ? strdup(name) : strdup("anonymous");
    current_scope = new_scope;
}

void pop_scope() {
    if (current_scope == global_scope) {
        printf("Warning: Attempted to pop global scope\n");
        return;
    }
    
    Scope *old_scope = current_scope;
    current_scope = current_scope->parent;
    scope_level = current_scope->level;
    
    // Clean up symbols
    for (int i = 0; i < old_scope->count; i++) {
        free(old_scope->symbols[i].name);
    }
    free(old_scope->name);
    free(old_scope);
}

Symbol *find_symbol(char *name) {
    Scope *scope = current_scope;
    while (scope != NULL) {
        for (int i = 0; i < scope->count; i++) {
            if (strcmp(scope->symbols[i].name, name) == 0) {
                return &scope->symbols[i];
            }
        }
        scope = scope->parent;
    }
    return NULL;
}

Symbol *add_symbol(char *name, SymbolType type) {
    if (current_scope->count >= MAX_SYMBOLS) {
        printf("Error: Symbol table overflow in scope '%s'\n", current_scope->name);
        exit(1);
    }
    
    // Check if symbol already exists in current scope
    for (int i = 0; i < current_scope->count; i++) {
        if (strcmp(current_scope->symbols[i].name, name) == 0) {
            printf("Error: Symbol '%s' already declared in scope '%s'\n", name, current_scope->name);
            exit(1);
        }
    }
    
    Symbol *symbol = &current_scope->symbols[current_scope->count++];
    symbol->name = strdup(name);
    symbol->type = type;
    symbol->is_shared = 0;
    symbol->is_parameter = 0;
    symbol->scope_level = current_scope->level;
    symbol->type_node = NULL;
    symbol->function_node = NULL;
    
    // Calculate stack offset
    if (type == TYPE_INT) {
        symbol->stack_offset = current_scope->stack_size;
        current_scope->stack_size += 8; // 64-bit alignment
    } else if (type == TYPE_PTR) {
        symbol->stack_offset = current_scope->stack_size;
        current_scope->stack_size += 8;
    }
    
    return symbol;
}

// --- SEMANTIC ANALYZER ---
void semantic_error(const char *msg, int line, int column) {
    printf("Semantic Error at line %d, column %d: %s\n", line, column, msg);
    exit(1);
}

SymbolType analyze_expression(AstNode *node) {
    if (!node) return TYPE_INT; // Default or error case

    switch (node->type) {
        case AST_NUMBER:
            return TYPE_INT;
            
        case AST_IDENTIFIER: {
            Symbol *sym = find_symbol(node->name);
            if (!sym) {
                semantic_error("Undefined variable", node->line, node->column);
            }
            return sym->type;
        }
        
        case AST_OP: {
            SymbolType left_type = analyze_expression(node->left);
            SymbolType right_type = analyze_expression(node->right);
            
            // Type checking for different operations
            switch (node->op) {
                case TOKEN_ADD:
                case TOKEN_SUB:
                case TOKEN_MUL:
                case TOKEN_DIV:
                    if (left_type != TYPE_INT || right_type != TYPE_INT) {
                        semantic_error("Arithmetic operation on non-integer type", node->line, node->column);
                    }
                    return TYPE_INT;
                    
                case TOKEN_GT:
                case TOKEN_LT:
                case TOKEN_GE:
                case TOKEN_LE:
                case TOKEN_EQ_EQ:
                case TOKEN_NE:
                    if (left_type != right_type) {
                        semantic_error("Comparison between incompatible types", node->line, node->column);
                    }
                    return TYPE_INT; // Boolean result
                    
                default:
                    semantic_error("Invalid operator for semantic analysis", node->line, node->column);
            }
            return TYPE_INT;
        }
        
        case AST_ADDRESS_OF: {
            SymbolType inner_type = analyze_expression(node->left);
            if (inner_type == TYPE_PTR) {
                semantic_error("Cannot take address of pointer", node->line, node->column);
            }
            return TYPE_PTR;
        }
        
        case AST_DEREFERENCE: {
            SymbolType inner_type = analyze_expression(node->left);
            if (inner_type != TYPE_PTR) {
                semantic_error("Dereference on non-pointer type", node->line, node->column);
            }
            return TYPE_INT; // Dereference yields an integer
        }
        
        case AST_FUNCTION_CALL: {
            Symbol *func_sym = find_symbol(node->name);
            if (!func_sym || func_sym->type != TYPE_FUNC) {
                semantic_error("Call to undefined function", node->line, node->column);
            }
            
            // Check argument count and types (simplified)
            AstNode *arg = node->args;
            int arg_count = 0;
            while (arg) {
                analyze_expression(arg);
                arg = arg->next;
                arg_count++;
            }
            
            // Return function's return type (simplified to int for now)
            return TYPE_INT;
        }
        
        case AST_ALLOC: {
            analyze_expression(node->left); // Size expression
            return TYPE_PTR;
        }
        
        case AST_SIZEOF: {
            analyze_expression(node->left);
            return TYPE_INT;
        }
        
        default:
            semantic_error("Invalid expression type for semantic analysis", node->line, node->column);
            return TYPE_INT;
    }
}

void analyze_statement(AstNode *node) {
    if (!node) return;

    switch (node->type) {
        case AST_VAR_DECL: {
            SymbolType expr_type = analyze_expression(node->right);
            Symbol *sym = add_symbol(node->name, expr_type);
            sym->is_shared = node->is_shared;
            break;
        }
        
        case AST_ASSIGN: {
            Symbol *sym = find_symbol(node->name);
            if (!sym) {
                semantic_error("Assignment to undefined variable", node->line, node->column);
            }
            SymbolType expr_type = analyze_expression(node->right);
            if (sym->type != expr_type) {
                semantic_error("Type mismatch in assignment", node->line, node->column);
            }
            break;
        }
        
        case AST_ASSIGN_DEREF: {
            SymbolType left_type = analyze_expression(node->left);
            if (left_type != TYPE_PTR) {
                semantic_error("Assignment to dereference requires pointer type", node->line, node->column);
            }
            SymbolType right_type = analyze_expression(node->right);
            if (right_type != TYPE_INT) {
                semantic_error("Cannot assign non-integer to dereferenced pointer", node->line, node->column);
            }
            break;
        }
        
        case AST_RET: {
            if (node->left) {
                analyze_expression(node->left);
            }
            break;
        }
        
        case AST_IF: {
            SymbolType cond_type = analyze_expression(node->cond);
            if (cond_type != TYPE_INT) {
                semantic_error("If condition must be integer type", node->line, node->column);
            }
            push_scope("if_block");
            analyze_statement(node->body);
            pop_scope();
            break;
        }
        
        case AST_BLOCK: {
            push_scope("block");
            analyze_statement(node->left);
            analyze_statement(node->next);
            pop_scope();
            break;
        }
        
        case AST_FUNCTION_DEFINITION: {
            analyze_function(node);
            break;
        }
        
        case AST_SPAWN: {
            analyze_expression(node->left);
            break;
        }
        
        default:
            // Some statement types might not need semantic analysis
            break;
    }
}

void analyze_function(AstNode *node) {
    if (!node || node->type != AST_FUNCTION_DEFINITION) return;
    
    // Add function to symbol table
    Symbol *func_sym = add_symbol(node->name, TYPE_FUNC);
    func_sym->function_node = node;
    
    // Create new scope for function body
    char scope_name[256];
    snprintf(scope_name, sizeof(scope_name), "func_%s", node->name);
    push_scope(scope_name);
    
    // Add parameters to function scope
    AstNode *param = node->args;
    while (param) {
        if (param->type == AST_PARAMETER) {
            SymbolType param_type = param->return_type ? 
                (param->return_type->type == AST_POINTER_TYPE ? TYPE_PTR : TYPE_INT) : TYPE_INT;
            Symbol *param_sym = add_symbol(param->name, param_type);
            param_sym->is_parameter = 1;
        }
        param = param->next;
    }
    
    // Analyze function body
    analyze_statement(node->body);
    
    // Pop function scope
    pop_scope();
}

void analyze_program(AstNode *ast) {
    if (!ast || ast->type != AST_PROGRAM) {
        semantic_error("Root node must be a program", 0, 0);
        return;
    }
    
    init_scopes();
    
    AstNode *node = ast->body;
    while (node) {
        if (node->type == AST_FUNCTION_DEFINITION) {
            analyze_function(node);
        } else {
            analyze_statement(node);
        }
        node = node->next;
    }
    
    printf("Semantic analysis completed successfully.\n");
    printf("Global scope: %d symbols\n", global_scope->count);
}

// --- PARSER (Simplified for demonstration) ---
void advance() { lexer_next(); }

void expect(int type) {
    if (current_token.type != type) { 
        printf("Syntax error: expected token type %d, got %d ('%s')\n", 
               type, current_token.type, current_token.value); 
        exit(1); 
    }
    advance();
}

AstNode *parse_expression() {
    // Simplified expression parsing
    if (current_token.type == TOKEN_NUMBER) {
        AstNode *node = malloc(sizeof(AstNode));
        node->type = AST_NUMBER;
        node->value = atoi(current_token.value);
        node->line = current_token.line;
        node->column = current_token.column;
        advance();
        return node;
    }
    
    if (current_token.type == TOKEN_IDENTIFIER) {
        AstNode *node = malloc(sizeof(AstNode));
        node->type = AST_IDENTIFIER;
        node->name = strdup(current_token.value);
        node->line = current_token.line;
        node->column = current_token.column;
        advance();
        return node;
    }
    
    return NULL;
}

AstNode *parse_statement() {
    if (current_token.type == TOKEN_LET) {
        advance();
        expect(TOKEN_IDENTIFIER);
        char *name = strdup(current_token.value);
        advance();
        expect(TOKEN_EQ);
        AstNode *expr = parse_expression();
        
        AstNode *node = malloc(sizeof(AstNode));
        node->type = AST_VAR_DECL;
        node->name = name;
        node->right = expr;
        node->line = current_token.line;
        node->column = current_token.column;
        return node;
    }
    
    if (current_token.type == TOKEN_RET) {
        advance();
        AstNode *expr = parse_expression();
        
        AstNode *node = malloc(sizeof(AstNode));
        node->type = AST_RET;
        node->left = expr;
        node->line = current_token.line;
        node->column = current_token.column;
        return node;
    }
    
    return parse_expression();
}

AstNode *parse_program() {
    AstNode *program = malloc(sizeof(AstNode));
    program->type = AST_PROGRAM;
    program->body = NULL;
    program->next = NULL;
    
    AstNode *current = NULL;
    while (current_token.type != TOKEN_EOF) {
        AstNode *stmt = parse_statement();
        if (stmt) {
            if (!program->body) {
                program->body = stmt;
                current = stmt;
            } else {
                current->next = stmt;
                current = stmt;
            }
        }
        
        if (current_token.type == TOKEN_SEMICOLON) {
            advance();
        }
    }
    
    return program;
}

// --- Main Compiler Driver ---
int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <source_file>\n", argv[0]);
        return 1;
    }
    
    // Read source file
    FILE *file = fopen(argv[1], "r");
    if (!file) {
        printf("Error: Cannot open file '%s'\n", argv[1]);
        return 1;
    }
    
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char *source = malloc(length + 1);
    fread(source, 1, length, file);
    source[length] = '\0';
    fclose(file);
    
    // Initialize lexer
    lexer_init(source);
    advance();
    
    // Parse program
    AstNode *ast = parse_program();
    
    // Semantic Analysis
    analyze_program(ast);
    
    printf("Compilation completed successfully.\n");
    
    // Cleanup
    free(source);
    
    return 0;
}
