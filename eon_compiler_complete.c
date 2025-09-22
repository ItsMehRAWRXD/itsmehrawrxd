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

// --- LEXER (Complete) ---
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

// --- AST (Complete) ---
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
    AstNode *type_node;
    AstNode *function_node;
} Symbol;

typedef struct Scope {
    Symbol symbols[MAX_SYMBOLS];
    int count;
    int stack_size;
    int level;
    struct Scope *parent;
    char *name;
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
    
    if (type == TYPE_INT) {
        symbol->stack_offset = current_scope->stack_size;
        current_scope->stack_size += 8;
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
    if (!node) return TYPE_INT;

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
                    return TYPE_INT;
                    
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
            return TYPE_INT;
        }
        
        case AST_FUNCTION_CALL: {
            Symbol *func_sym = find_symbol(node->name);
            if (!func_sym || func_sym->type != TYPE_FUNC) {
                semantic_error("Call to undefined function", node->line, node->column);
            }
            
            AstNode *arg = node->args;
            int arg_count = 0;
            while (arg) {
                analyze_expression(arg);
                arg = arg->next;
                arg_count++;
            }
            
            return TYPE_INT;
        }
        
        case AST_ALLOC: {
            analyze_expression(node->left);
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
            break;
    }
}

void analyze_function(AstNode *node) {
    if (!node || node->type != AST_FUNCTION_DEFINITION) return;
    
    Symbol *func_sym = add_symbol(node->name, TYPE_FUNC);
    func_sym->function_node = node;
    
    char scope_name[256];
    snprintf(scope_name, sizeof(scope_name), "func_%s", node->name);
    push_scope(scope_name);
    
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
    
    analyze_statement(node->body);
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

// --- ASSEMBLY CODE GENERATOR ---
typedef struct {
    FILE *output_file;
    int label_count;
    int current_stack_offset;
    int max_stack_size;
    int in_function;
    char *current_function_name;
} AssemblyGenerator;

AssemblyGenerator *init_assembly_generator(FILE *output_file) {
    AssemblyGenerator *gen = malloc(sizeof(AssemblyGenerator));
    gen->output_file = output_file;
    gen->label_count = 0;
    gen->current_stack_offset = 0;
    gen->max_stack_size = 0;
    gen->in_function = 0;
    gen->current_function_name = NULL;
    return gen;
}

void generate_header(AssemblyGenerator *gen) {
    fprintf(gen->output_file, "; Generated x86-64 assembly for Eon program\n");
    fprintf(gen->output_file, ".section .text\n");
    fprintf(gen->output_file, ".global _start\n");
    fprintf(gen->output_file, ".global main\n\n");
    
    fprintf(gen->output_file, "; System call numbers\n");
    fprintf(gen->output_file, "SYS_EXIT equ 60\n");
    fprintf(gen->output_file, "SYS_WRITE equ 1\n");
    fprintf(gen->output_file, "STDOUT equ 1\n\n");
}

void generate_data_section(AssemblyGenerator *gen) {
    fprintf(gen->output_file, ".section .data\n");
    fprintf(gen->output_file, "; Global variables and string literals\n\n");
}

void generate_bss_section(AssemblyGenerator *gen) {
    fprintf(gen->output_file, ".section .bss\n");
    fprintf(gen->output_file, "; Uninitialized global variables\n\n");
}

char *generate_label(AssemblyGenerator *gen, char *prefix) {
    char *label = malloc(64);
    snprintf(label, 64, "%s_%d", prefix, gen->label_count++);
    return label;
}

void push_register(AssemblyGenerator *gen, char *reg) {
    fprintf(gen->output_file, "    push %s\n", reg);
    gen->current_stack_offset += 8;
    if (gen->current_stack_offset > gen->max_stack_size) {
        gen->max_stack_size = gen->current_stack_offset;
    }
}

void pop_register(AssemblyGenerator *gen, char *reg) {
    fprintf(gen->output_file, "    pop %s\n", reg);
    gen->current_stack_offset -= 8;
}

void generate_function_prologue(AssemblyGenerator *gen, char *func_name) {
    fprintf(gen->output_file, "; Function: %s\n", func_name);
    fprintf(gen->output_file, "%s:\n", func_name);
    fprintf(gen->output_file, "    push rbp\n");
    fprintf(gen->output_file, "    mov rbp, rsp\n");
    fprintf(gen->output_file, "    sub rsp, %d\n", gen->max_stack_size);
    gen->in_function = 1;
    gen->current_function_name = strdup(func_name);
}

void generate_function_epilogue(AssemblyGenerator *gen) {
    fprintf(gen->output_file, "    mov rsp, rbp\n");
    fprintf(gen->output_file, "    pop rbp\n");
    fprintf(gen->output_file, "    ret\n\n");
    gen->in_function = 0;
    if (gen->current_function_name) {
        free(gen->current_function_name);
        gen->current_function_name = NULL;
    }
}

void generate_number(AssemblyGenerator *gen, int value) {
    fprintf(gen->output_file, "    mov rax, %d\n", value);
    push_register(gen, "rax");
}

void generate_identifier(AssemblyGenerator *gen, char *name, int stack_offset) {
    if (stack_offset > 0) {
        fprintf(gen->output_file, "    mov rax, [rbp - %d]\n", stack_offset);
    } else {
        fprintf(gen->output_file, "    mov rax, [%s]\n", name);
    }
    push_register(gen, "rax");
}

void generate_binary_operation(AssemblyGenerator *gen, int op, AstNode *left, AstNode *right) {
    generate_expression(gen, right);
    generate_expression(gen, left);
    
    pop_register(gen, "rax");
    pop_register(gen, "rbx");
    
    switch (op) {
        case TOKEN_ADD:
            fprintf(gen->output_file, "    add rax, rbx\n");
            break;
        case TOKEN_SUB:
            fprintf(gen->output_file, "    sub rax, rbx\n");
            break;
        case TOKEN_MUL:
            fprintf(gen->output_file, "    imul rax, rbx\n");
            break;
        case TOKEN_DIV:
            fprintf(gen->output_file, "    cqo\n");
            fprintf(gen->output_file, "    idiv rbx\n");
            break;
        case TOKEN_GT:
            fprintf(gen->output_file, "    cmp rax, rbx\n");
            fprintf(gen->output_file, "    setg al\n");
            fprintf(gen->output_file, "    movzx rax, al\n");
            break;
        case TOKEN_LT:
            fprintf(gen->output_file, "    cmp rax, rbx\n");
            fprintf(gen->output_file, "    setl al\n");
            fprintf(gen->output_file, "    movzx rax, al\n");
            break;
        case TOKEN_EQ_EQ:
            fprintf(gen->output_file, "    cmp rax, rbx\n");
            fprintf(gen->output_file, "    sete al\n");
            fprintf(gen->output_file, "    movzx rax, al\n");
            break;
        default:
            fprintf(gen->output_file, "    ; Unknown operator\n");
            break;
    }
    
    push_register(gen, "rax");
}

void generate_expression(AssemblyGenerator *gen, AstNode *node) {
    if (!node) return;
    
    switch (node->type) {
        case AST_NUMBER:
            generate_number(gen, node->value);
            break;
            
        case AST_IDENTIFIER: {
            int stack_offset = 8;
            generate_identifier(gen, node->name, stack_offset);
            break;
        }
        
        case AST_OP:
            generate_binary_operation(gen, node->op, node->left, node->right);
            break;
            
        case AST_ADDRESS_OF:
            fprintf(gen->output_file, "    lea rax, [rbp - 8]\n");
            push_register(gen, "rax");
            break;
            
        case AST_DEREFERENCE:
            generate_expression(gen, node);
            pop_register(gen, "rax");
            fprintf(gen->output_file, "    mov rax, [rax]\n");
            push_register(gen, "rax");
            break;
            
        case AST_FUNCTION_CALL:
            fprintf(gen->output_file, "    call %s\n", node->name);
            push_register(gen, "rax");
            break;
            
        case AST_ALLOC:
            generate_expression(gen, node->left);
            pop_register(gen, "rdi");
            fprintf(gen->output_file, "    mov rax, 12\n"); // SYS_BRK
            fprintf(gen->output_file, "    syscall\n");
            push_register(gen, "rax");
            break;
            
        default:
            fprintf(gen->output_file, "    ; Unhandled expression type\n");
            break;
    }
}

void generate_variable_declaration(AssemblyGenerator *gen, AstNode *node) {
    generate_expression(gen, node->right);
    pop_register(gen, "rax");
    fprintf(gen->output_file, "    mov [rbp - 8], rax\n");
}

void generate_assignment(AssemblyGenerator *gen, AstNode *node) {
    generate_expression(gen, node->right);
    pop_register(gen, "rax");
    fprintf(gen->output_file, "    mov [rbp - 8], rax\n");
}

void generate_return(AssemblyGenerator *gen, AstNode *node) {
    if (node->left) {
        generate_expression(gen, node->left);
        pop_register(gen, "rax");
    } else {
        fprintf(gen->output_file, "    mov rax, 0\n");
    }
    generate_function_epilogue(gen);
}

void generate_if_statement(AssemblyGenerator *gen, AstNode *node) {
    char *else_label = generate_label(gen, "else");
    char *end_label = generate_label(gen, "endif");
    
    generate_expression(gen, node->cond);
    pop_register(gen, "rax");
    
    fprintf(gen->output_file, "    cmp rax, 0\n");
    fprintf(gen->output_file, "    je %s\n", else_label);
    
    generate_statement(gen, node->body);
    fprintf(gen->output_file, "    jmp %s\n", end_label);
    
    fprintf(gen->output_file, "%s:\n", else_label);
    if (node->right) {
        generate_statement(gen, node->right);
    }
    
    fprintf(gen->output_file, "%s:\n", end_label);
    
    free(else_label);
    free(end_label);
}

void generate_block(AssemblyGenerator *gen, AstNode *node) {
    if (node->left) {
        generate_statement(gen, node->left);
    }
    if (node->next) {
        generate_statement(gen, node->next);
    }
}

void generate_function_definition(AssemblyGenerator *gen, AstNode *node) {
    generate_function_prologue(gen, node->name);
    generate_statement(gen, node->body);
    generate_function_epilogue(gen);
}

void generate_statement(AssemblyGenerator *gen, AstNode *node) {
    if (!node) return;
    
    switch (node->type) {
        case AST_VAR_DECL:
            generate_variable_declaration(gen, node);
            break;
            
        case AST_ASSIGN:
            generate_assignment(gen, node);
            break;
            
        case AST_RET:
            generate_return(gen, node);
            break;
            
        case AST_IF:
            generate_if_statement(gen, node);
            break;
            
        case AST_BLOCK:
            generate_block(gen, node);
            break;
            
        case AST_FUNCTION_DEFINITION:
            generate_function_definition(gen, node);
            break;
            
        case AST_SPAWN:
            generate_expression(gen, node->left);
            pop_register(gen, "rdi");
            fprintf(gen->output_file, "    ; Thread creation not implemented\n");
            break;
            
        default:
            generate_expression(gen, node);
            break;
    }
}

void generate_program(AssemblyGenerator *gen, AstNode *program) {
    generate_header(gen);
    generate_data_section(gen);
    generate_bss_section(gen);
    
    AstNode *node = program->body;
    while (node) {
        if (node->type == AST_FUNCTION_DEFINITION && 
            node->name && strcmp(node->name, "main") == 0) {
            generate_function_definition(gen, node);
            break;
        }
        node = node->next;
    }
    
    node = program->body;
    while (node) {
        if (node->type == AST_FUNCTION_DEFINITION && 
            (!node->name || strcmp(node->name, "main") != 0)) {
            generate_statement(gen, node);
        }
        node = node->next;
    }
    
    fprintf(gen->output_file, "; Entry point\n");
    fprintf(gen->output_file, "_start:\n");
    fprintf(gen->output_file, "    call main\n");
    fprintf(gen->output_file, "    mov rdi, rax\n");
    fprintf(gen->output_file, "    mov rax, SYS_EXIT\n");
    fprintf(gen->output_file, "    syscall\n");
}

void generate_assembly_code(AstNode *ast, const char *output_filename) {
    FILE *output_file = fopen(output_filename, "w");
    if (!output_file) {
        printf("Error: Cannot open output file '%s'\n", output_filename);
        return;
    }
    
    AssemblyGenerator *gen = init_assembly_generator(output_file);
    
    printf("Generating x86-64 assembly code...\n");
    generate_program(gen, ast);
    
    printf("Assembly code generated successfully: %s\n", output_filename);
    
    free(gen);
    fclose(output_file);
}

// --- PARSER (Simplified) ---
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
        printf("Usage: %s <source_file> [output_file]\n", argv[0]);
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
    printf("Parsing Eon program...\n");
    AstNode *ast = parse_program();
    
    // Semantic Analysis
    printf("Performing semantic analysis...\n");
    analyze_program(ast);
    
    // Code Generation
    char *output_filename = argc > 2 ? argv[2] : "output.s";
    generate_assembly_code(ast, output_filename);
    
    printf("Compilation completed successfully.\n");
    printf("Output: %s\n", output_filename);
    
    // Cleanup
    free(source);
    
    return 0;
}
