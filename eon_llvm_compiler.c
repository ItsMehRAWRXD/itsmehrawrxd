#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

// Forward declarations for compiler components.
typedef struct Token Token;
typedef struct AstNode AstNode;
char *lexer_src;
Token current_token;
int if_count = 0;
int func_count = 0;

// --- LEXER ---
typedef struct Token {
    enum {
        TOKEN_EOF, TOKEN_IDENTIFIER, TOKEN_NUMBER, TOKEN_RET, TOKEN_LET, TOKEN_IF,
        TOKEN_LPAREN, TOKEN_RPAREN, TOKEN_LBRACE, TOKEN_RBRACE, TOKEN_EQ,
        TOKEN_ADD, TOKEN_SUB, TOKEN_MUL, TOKEN_DIV, TOKEN_GT, TOKEN_DEF,
        TOKEN_FUNC, TOKEN_MODEL, TOKEN_STAR, TOKEN_AMPERSAND, TOKEN_ALLOC,
        TOKEN_SIZEOF, TOKEN_COLON, TOKEN_ARROW, TOKEN_COMMA, TOKEN_SPAWN, TOKEN_SHARED
    } type;
    char *value;
} Token;

void lexer_init(char *src) {
    lexer_src = src;
}

Token *lexer_next() {
    while(isspace(*lexer_src)) lexer_src++;
    if (*lexer_src == '\0') { current_token.type = TOKEN_EOF; return &current_token; }

    char *start = lexer_src;
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
        else { current_token.type = TOKEN_IDENTIFIER; current_token.value = word; }
        return &current_token;
    }
    if (isdigit(*start)) {
        while(isdigit(*lexer_src)) lexer_src++;
        current_token.type = TOKEN_NUMBER;
        current_token.value = strndup(start, lexer_src-start);
        return &current_token;
    }
    switch(*lexer_src) {
        case '+': current_token.type = TOKEN_ADD; break;
        case '-': if (*(lexer_src+1) == '>') { current_token.type = TOKEN_ARROW; lexer_src++; } else { current_token.type = TOKEN_SUB; } break;
        case '*': current_token.type = TOKEN_STAR; break;
        case '/': current_token.type = TOKEN_DIV; break;
        case '>': current_token.type = TOKEN_GT; break;
        case '=': current_token.type = TOKEN_EQ; break;
        case '(': current_token.type = TOKEN_LPAREN; break;
        case ')': current_token.type = TOKEN_RPAREN; break;
        case '{': current_token.type = TOKEN_LBRACE; break;
        case '}': current_token.type = TOKEN_RBRACE; break;
        case '&': current_token.type = TOKEN_AMPERSAND; break;
        case ':': current_token.type = TOKEN_COLON; break;
        case ',': current_token.type = TOKEN_COMMA; break;
        default: printf("Unknown token: '%c'\n", *lexer_src); exit(1);
    }
    lexer_src++;
    return &current_token;
}

// --- AST ---
typedef struct AstNode {
    enum {
        AST_NUMBER, AST_OP, AST_IDENTIFIER, AST_VAR_DECL, AST_ASSIGN, AST_IF, AST_RET, AST_BLOCK,
        AST_FUNCTION_DEFINITION, AST_FUNCTION_CALL, AST_STRUCT_DEFINITION, AST_POINTER_TYPE,
        AST_DEREFERENCE, AST_ADDRESS_OF, AST_PARAMETER, AST_STRUCT_FIELD, AST_PROGRAM, AST_ALLOC,
        AST_SIZEOF, AST_FUNCTION_PROTOTYPE, AST_SPAWN, AST_ASSIGN_DEREF
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
    int is_shared;
} AstNode;

// --- SYMBOL TABLE ---
typedef struct { 
    char *name; 
    int stack_offset; 
    int is_shared; 
    int size; 
} Symbol;

#define MAX_SYMBOLS 128
Symbol global_symbols[MAX_SYMBOLS];
int global_symbol_count = 0;
Symbol local_symbols[MAX_SYMBOLS];
int local_symbol_count = 0;

void reset_local_symbols() {
    for (int i = 0; i < local_symbol_count; i++) {
        free(local_symbols[i].name);
    }
    local_symbol_count = 0;
}

int get_symbol_offset(char *name) {
    for (int i = 0; i < local_symbol_count; i++) {
        if (strcmp(local_symbols[i].name, name) == 0) {
            return (i + 1) * 8;
        }
    }
    for (int i = 0; i < global_symbol_count; i++) {
        if (strcmp(global_symbols[i].name, name) == 0) {
            return global_symbols[i].stack_offset;
        }
    }
    if (local_symbol_count < MAX_SYMBOLS) {
        local_symbols[local_symbol_count].name = strdup(name);
        local_symbols[local_symbol_count].stack_offset = (local_symbol_count + 1) * 8;
        return (local_symbol_count++ + 1) * 8;
    }
    printf("Error: Symbol table overflow\n");
    exit(1);
}

// --- PARSER ---
void advance() { lexer_next(); }
void expect(int type) {
    if (current_token.type != type) { 
        printf("Syntax error: expected token type %d, got %d ('%s')\n", type, current_token.type, current_token.value); 
        exit(1); 
    }
    advance();
}

AstNode *new_node(int type, AstNode *left, AstNode *right) {
    AstNode *node = malloc(sizeof(AstNode));
    node->type = type;
    node->left = left;
    node->right = right;
    node->next = NULL;
    node->cond = NULL;
    node->body = NULL;
    node->args = NULL;
    node->is_shared = 0;
    return node;
}

AstNode *parse_expression();
AstNode *parse_type();
AstNode *parse_statement();
AstNode *parse_block();

AstNode *parse_primary() {
    AstNode *node = malloc(sizeof(AstNode));
    if (current_token.type == TOKEN_NUMBER) {
        node->type = AST_NUMBER;
        node->value = atoi(current_token.value);
        advance();
    } else if (current_token.type == TOKEN_IDENTIFIER) {
        char *name = strdup(current_token.value);
        advance();
        if (current_token.type == TOKEN_LPAREN) {
            node->type = AST_FUNCTION_CALL;
            node->name = name;
            advance();
            AstNode *head = NULL, *current = NULL;
            if (current_token.type != TOKEN_RPAREN) {
                AstNode *arg = parse_expression();
                head = arg;
                current = arg;
                while (current_token.type == TOKEN_COMMA) {
                    advance();
                    current->next = parse_expression();
                    current = current->next;
                }
            }
            node->args = head;
            expect(TOKEN_RPAREN);
        } else {
            node->type = AST_IDENTIFIER;
            node->name = name;
        }
    } else if (current_token.type == TOKEN_LPAREN) {
        advance();
        node = parse_expression();
        expect(TOKEN_RPAREN);
    } else if (current_token.type == TOKEN_AMPERSAND) {
        advance();
        node->type = AST_ADDRESS_OF;
        node->left = parse_primary();
    } else if (current_token.type == TOKEN_STAR) {
        advance();
        node->type = AST_DEREFERENCE;
        node->left = parse_primary();
    } else if (current_token.type == TOKEN_ALLOC) {
        node->type = AST_ALLOC;
        advance();
        expect(TOKEN_LPAREN);
        node->left = parse_expression();
        expect(TOKEN_RPAREN);
    } else if (current_token.type == TOKEN_SIZEOF) {
        node->type = AST_SIZEOF;
        advance();
        expect(TOKEN_LPAREN);
        node->left = parse_expression();
        expect(TOKEN_RPAREN);
    } else {
        printf("Syntax error: unexpected token in primary expression: '%s'\n", current_token.value);
        exit(1);
    }
    return node;
}

AstNode *parse_factor() {
    AstNode *left = parse_primary();
    while(current_token.type == TOKEN_MUL || current_token.type == TOKEN_DIV) {
        AstNode *node = new_node(AST_OP, left, NULL);
        node->op = current_token.type;
        advance();
        node->right = parse_primary();
        left = node;
    }
    return left;
}

AstNode *parse_term() {
    AstNode *left = parse_factor();
    while(current_token.type == TOKEN_ADD || current_token.type == TOKEN_SUB) {
        AstNode *node = new_node(AST_OP, left, NULL);
        node->op = current_token.type;
        advance();
        node->right = parse_factor();
        left = node;
    }
    return left;
}

AstNode *parse_expression() {
    AstNode *left = parse_term();
    if (current_token.type == TOKEN_GT) {
        AstNode *node = new_node(AST_OP, left, NULL);
        node->op = current_token.type;
        advance();
        node->right = parse_term();
        left = node;
    }
    return left;
}

AstNode *parse_parameters() {
    AstNode *head = NULL, *current = NULL;
    if (current_token.type != TOKEN_RPAREN) {
        AstNode *param = malloc(sizeof(AstNode));
        param->type = AST_PARAMETER;
        param->name = strdup(current_token.value);
        advance();
        expect(TOKEN_COLON);
        param->left = parse_type();
        head = param;
        current = head;
        while (current_token.type == TOKEN_COMMA) {
            advance();
            AstNode *next_param = malloc(sizeof(AstNode));
            next_param->type = AST_PARAMETER;
            next_param->name = strdup(current_token.value);
            advance();
            expect(TOKEN_COLON);
            next_param->left = parse_type();
            current->next = next_param;
            current = current->next;
        }
    }
    return head;
}

AstNode *parse_type() {
    if (current_token.type == TOKEN_IDENTIFIER) {
        AstNode *type = malloc(sizeof(AstNode));
        type->type = AST_IDENTIFIER;
        type->name = strdup(current_token.value);
        advance();
        return type;
    } else if (current_token.type == TOKEN_STAR) {
        advance();
        AstNode *type = malloc(sizeof(AstNode));
        type->type = AST_POINTER_TYPE;
        type->left = parse_type();
        return type;
    }
    printf("Syntax error: Expected type, got '%s'\n", current_token.value);
    exit(1);
}

AstNode *parse_top_level_statement() {
    if (current_token.type == TOKEN_DEF) {
        advance();
        if (current_token.type == TOKEN_FUNC) {
            advance();
            AstNode *func_node = malloc(sizeof(AstNode));
            func_node->type = AST_FUNCTION_DEFINITION;
            func_node->name = strdup(current_token.value);
            advance();
            expect(TOKEN_LPAREN);
            func_node->args = parse_parameters();
            expect(TOKEN_RPAREN);
            expect(TOKEN_ARROW);
            func_node->left = parse_type();
            expect(TOKEN_LBRACE);
            func_node->body = parse_block();
            expect(TOKEN_RBRACE);
            return func_node;
        } else if (current_token.type == TOKEN_MODEL) {
            advance();
            AstNode *model_node = malloc(sizeof(AstNode));
            model_node->type = AST_STRUCT_DEFINITION;
            model_node->name = strdup(current_token.value);
            advance();
            expect(TOKEN_LBRACE);
            AstNode *head = NULL, *current = NULL;
            while (current_token.type == TOKEN_IDENTIFIER) {
                AstNode *field = malloc(sizeof(AstNode));
                field->type = AST_STRUCT_FIELD;
                field->name = strdup(current_token.value);
                advance();
                expect(TOKEN_COLON);
                field->left = parse_type();
                if (head == NULL) {
                    head = field;
                    current = head;
                } else {
                    current->next = field;
                    current = current->next;
                }
            }
            model_node->body = head;
            expect(TOKEN_RBRACE);
            return model_node;
        }
    }
    return parse_statement();
}

AstNode *parse_statement() {
    AstNode *node = malloc(sizeof(AstNode));
    if (current_token.type == TOKEN_RET) {
        node->type = AST_RET;
        advance();
        node->left = parse_expression();
    } else if (current_token.type == TOKEN_LET) {
        advance();
        int is_shared = 0;
        if (current_token.type == TOKEN_SHARED) {
            is_shared = 1;
            advance();
        }
        node->type = AST_VAR_DECL;
        node->name = strdup(current_token.value);
        node->is_shared = is_shared;
        advance();
        expect(TOKEN_EQ);
        node->right = parse_expression();
    } else if (current_token.type == TOKEN_IDENTIFIER) {
        char *name = strdup(current_token.value);
        advance();
        if (current_token.type == TOKEN_LPAREN) {
            AstNode *call_node = malloc(sizeof(AstNode));
            call_node->type = AST_FUNCTION_CALL;
            call_node->name = name;
            advance();
            AstNode *head = NULL, *current = NULL;
            if (current_token.type != TOKEN_RPAREN) {
                AstNode *arg = parse_expression();
                head = arg;
                current = arg;
                while (current_token.type == TOKEN_COMMA) {
                    advance();
                    current->next = parse_expression();
                    current = current->next;
                }
            }
            call_node->args = head;
            expect(TOKEN_RPAREN);
            return call_node;
        } else if (current_token.type == TOKEN_EQ) {
            node->type = AST_ASSIGN;
            node->name = name;
            advance();
            node->right = parse_expression();
        } else {
            printf("Syntax error: unexpected token after identifier in statement: '%s'\n", current_token.value);
            exit(1);
        }
    } else if (current_token.type == TOKEN_STAR) {
        advance();
        AstNode *deref_node = malloc(sizeof(AstNode));
        deref_node->type = AST_ASSIGN_DEREF;
        deref_node->left = parse_primary();
        expect(TOKEN_EQ);
        deref_node->right = parse_expression();
        return deref_node;
    } else if (current_token.type == TOKEN_IF) {
        node->type = AST_IF;
        advance();
        expect(TOKEN_LPAREN);
        node->cond = parse_expression();
        expect(TOKEN_RPAREN);
        expect(TOKEN_LBRACE);
        node->body = parse_block();
        expect(TOKEN_RBRACE);
    } else if (current_token.type == TOKEN_SPAWN) {
        node->type = AST_SPAWN;
        advance();
        node->left = parse_statement();
    } else {
        printf("Syntax error: unexpected token starting statement: '%s'\n", current_token.value);
        exit(1);
    }
    return node;
}

AstNode *parse_block() {
    AstNode *head = NULL;
    AstNode *current = NULL;

    while(current_token.type != TOKEN_EOF && current_token.type != TOKEN_RBRACE) {
        AstNode *newNode = parse_statement();
        if (head == NULL) {
            head = newNode;
            current = head;
        } else {
            current->next = newNode;
            current = current->next;
        }
    }
    return head;
}

AstNode *parse_program() {
    AstNode *node = new_node(AST_PROGRAM, NULL, NULL);
    AstNode *head = NULL, *current = NULL;
    while(current_token.type != TOKEN_EOF) {
        AstNode *newNode = parse_top_level_statement();
        if (head == NULL) {
            head = newNode;
            current = head;
        } else {
            current->next = newNode;
            current = current->next;
        }
    }
    node->body = head;
    return node;
}

// --- LLVM IR GENERATION ---
void generate_llvm_ir_expression(FILE *out, AstNode *node, int *reg_counter);
void generate_llvm_ir_statement(FILE *out, AstNode *node, int *reg_counter);

void generate_llvm_ir_expression(FILE *out, AstNode *node, int *reg_counter) {
    if (node->type == AST_NUMBER) {
        fprintf(out, "  %%reg_%d = add i64 0, %d\n", (*reg_counter)++, node->value);
    } else if (node->type == AST_IDENTIFIER) {
        fprintf(out, "  %%reg_%d = load i64, i64* %%%s\n", (*reg_counter)++, node->name);
    } else if (node->type == AST_OP) {
        generate_llvm_ir_expression(out, node->left, reg_counter);
        int left_reg = *reg_counter - 1;
        generate_llvm_ir_expression(out, node->right, reg_counter);
        int right_reg = *reg_counter - 1;
        
        switch (node->op) {
            case TOKEN_ADD:
                fprintf(out, "  %%reg_%d = add i64 %%reg_%d, %%reg_%d\n", (*reg_counter)++, left_reg, right_reg);
                break;
            case TOKEN_SUB:
                fprintf(out, "  %%reg_%d = sub i64 %%reg_%d, %%reg_%d\n", (*reg_counter)++, left_reg, right_reg);
                break;
            case TOKEN_MUL:
                fprintf(out, "  %%reg_%d = mul i64 %%reg_%d, %%reg_%d\n", (*reg_counter)++, left_reg, right_reg);
                break;
            case TOKEN_DIV:
                fprintf(out, "  %%reg_%d = sdiv i64 %%reg_%d, %%reg_%d\n", (*reg_counter)++, left_reg, right_reg);
                break;
            case TOKEN_GT:
                fprintf(out, "  %%reg_%d = icmp sgt i64 %%reg_%d, %%reg_%d\n", (*reg_counter)++, left_reg, right_reg);
                fprintf(out, "  %%reg_%d = zext i1 %%reg_%d to i64\n", (*reg_counter)++, (*reg_counter)-1);
                break;
        }
    } else if (node->type == AST_FUNCTION_CALL) {
        // Generate function call
        fprintf(out, "  %%reg_%d = call i64 @%s(", (*reg_counter)++, node->name);
        AstNode *current_arg = node->args;
        int first = 1;
        while (current_arg != NULL) {
            if (!first) fprintf(out, ", ");
            generate_llvm_ir_expression(out, current_arg, reg_counter);
            fprintf(out, "i64 %%reg_%d", (*reg_counter)-1);
            current_arg = current_arg->next;
            first = 0;
        }
        fprintf(out, ")\n");
    } else if (node->type == AST_ALLOC) {
        generate_llvm_ir_expression(out, node->left, reg_counter);
        fprintf(out, "  %%reg_%d = call i64 @malloc(i64 %%reg_%d)\n", (*reg_counter)++, (*reg_counter)-1);
    } else if (node->type == AST_SIZEOF) {
        fprintf(out, "  %%reg_%d = add i64 0, 8\n", (*reg_counter)++);
    } else if (node->type == AST_ADDRESS_OF) {
        fprintf(out, "  %%reg_%d = getelementptr i64, i64* %%%s, i32 0\n", (*reg_counter)++, node->left->name);
    } else if (node->type == AST_DEREFERENCE) {
        generate_llvm_ir_expression(out, node->left, reg_counter);
        fprintf(out, "  %%reg_%d = load i64, i64* %%reg_%d\n", (*reg_counter)++, (*reg_counter)-1);
    }
}

void generate_llvm_ir_statement(FILE *out, AstNode *node, int *reg_counter) {
    if (node->type == AST_VAR_DECL) {
        generate_llvm_ir_expression(out, node->right, reg_counter);
        fprintf(out, "  store i64 %%reg_%d, i64* %%%s\n", (*reg_counter)-1, node->name);
    } else if (node->type == AST_ASSIGN) {
        generate_llvm_ir_expression(out, node->right, reg_counter);
        fprintf(out, "  store i64 %%reg_%d, i64* %%%s\n", (*reg_counter)-1, node->name);
    } else if (node->type == AST_ASSIGN_DEREF) {
        generate_llvm_ir_expression(out, node->left, reg_counter);
        int addr_reg = (*reg_counter) - 1;
        generate_llvm_ir_expression(out, node->right, reg_counter);
        fprintf(out, "  store i64 %%reg_%d, i64* %%reg_%d\n", (*reg_counter)-1, addr_reg);
    } else if (node->type == AST_IF) {
        int label_num = if_count++;
        generate_llvm_ir_expression(out, node->cond, reg_counter);
        fprintf(out, "  %%cond_%d = icmp ne i64 %%reg_%d, 0\n", label_num, (*reg_counter)-1);
        fprintf(out, "  br i1 %%cond_%d, label %%if_true_%d, label %%if_false_%d\n", label_num, label_num, label_num);
        fprintf(out, "\nif_true_%d:\n", label_num);
        AstNode *body_node = node->body;
        while (body_node != NULL) {
            generate_llvm_ir_statement(out, body_node, reg_counter);
            body_node = body_node->next;
        }
        fprintf(out, "  br label %%if_end_%d\n", label_num);
        fprintf(out, "\nif_false_%d:\n", label_num);
        fprintf(out, "  br label %%if_end_%d\n", label_num);
        fprintf(out, "\nif_end_%d:\n", label_num);
    } else if (node->type == AST_RET) {
        generate_llvm_ir_expression(out, node->left, reg_counter);
        fprintf(out, "  ret i64 %%reg_%d\n", (*reg_counter)-1);
    } else if (node->type == AST_FUNCTION_CALL) {
        generate_llvm_ir_expression(out, node, reg_counter);
    } else if (node->type == AST_SPAWN) {
        if (node->left->type != AST_FUNCTION_CALL) {
            printf("Error: 'spawn' must be followed by a function call.\n");
            exit(1);
        }
        AstNode *call_node = node->left;
        fprintf(out, "  %%thread_%d = call i32 @pthread_create(ptr null, ptr null, ptr @%s, ptr null)\n", 
                func_count++, call_node->name);
    }
}

void generate_llvm_ir_function(FILE *out, AstNode *node) {
    reset_local_symbols();
    
    // Function signature
    fprintf(out, "define i64 @%s(", node->name);
    
    // Parameters
    AstNode *current_param = node->args;
    int first = 1;
    while (current_param != NULL) {
        if (!first) fprintf(out, ", ");
        fprintf(out, "i64 %%%s", current_param->name);
        get_symbol_offset(current_param->name);
        current_param = current_param->next;
        first = 0;
    }
    fprintf(out, ") {\n");
    
    // Function body
    int reg_counter = 0;
    AstNode *current = node->body;
    while (current != NULL) {
        generate_llvm_ir_statement(out, current, &reg_counter);
        current = current->next;
    }
    
    fprintf(out, "}\n\n");
}

void generate_llvm_ir(AstNode *ast) {
    // LLVM IR header
    fprintf(stdout, "; LLVM IR for Eon Language\n");
    fprintf(stdout, "target triple = \"x86_64-unknown-linux-gnu\"\n\n");
    
    // External function declarations
    fprintf(stdout, "declare i64 @malloc(i64)\n");
    fprintf(stdout, "declare i32 @pthread_create(ptr, ptr, ptr, ptr)\n");
    fprintf(stdout, "declare i32 @puts(ptr)\n");
    fprintf(stdout, "declare void @exit(i32)\n");
    fprintf(stdout, "declare i64 @time(i64)\n");
    fprintf(stdout, "declare void @srand(i32)\n");
    fprintf(stdout, "declare i32 @rand()\n\n");
    
    // Global variables
    fprintf(stdout, "@security_cookie = global i64 0\n\n");
    
    // Generate functions
    AstNode *current = ast->body;
    while (current != NULL) {
        if (current->type == AST_FUNCTION_DEFINITION) {
            generate_llvm_ir_function(stdout, current);
        }
        current = current->next;
    }
    
    // Main function
    fprintf(stdout, "define i32 @main() {\n");
    fprintf(stdout, "entry:\n");
    fprintf(stdout, "  ; Initialize security cookie\n");
    fprintf(stdout, "  %%time_val = call i64 @time(i64 0)\n");
    fprintf(stdout, "  %%time_trunc = trunc i64 %%time_val to i32\n");
    fprintf(stdout, "  call void @srand(i32 %%time_trunc)\n");
    fprintf(stdout, "  %%rand_val = call i32 @rand()\n");
    fprintf(stdout, "  %%rand_ext = zext i32 %%rand_val to i64\n");
    fprintf(stdout, "  store i64 %%rand_ext, i64* @security_cookie\n");
    
    // Generate main body statements
    current = ast->body;
    int reg_counter = 0;
    while (current != NULL) {
        if (current->type != AST_FUNCTION_DEFINITION) {
            generate_llvm_ir_statement(stdout, current, &reg_counter);
        }
        current = current->next;
    }
    
    fprintf(stdout, "  ret i32 0\n");
    fprintf(stdout, "}\n");
}

// --- Main Compiler Driver ---
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <source_file>\n", argv[0]);
        return 1;
    }

    FILE *in_file = fopen(argv[1], "r");
    if (!in_file) {
        perror("Failed to open source file");
        return 1;
    }

    fseek(in_file, 0, SEEK_END);
    long fsize = ftell(in_file);
    fseek(in_file, 0, SEEK_SET);
    char *source = malloc(fsize + 1);
    if (!source) {
        perror("Memory allocation failed");
        fclose(in_file);
        return 1;
    }
    fread(source, fsize, 1, in_file);
    fclose(in_file);
    source[fsize] = '\0';

    // Phase 1: Lexing and Parsing
    lexer_init(source);
    advance();
    AstNode *ast = parse_program();

    // Phase 2: LLVM IR Generation
    FILE *out_file = fopen("out.ll", "w");
    if (!out_file) {
        perror("Failed to open output file");
        free(source);
        return 1;
    }
    
    // Redirect stdout to file for LLVM IR generation
    int stdout_backup = dup(STDOUT_FILENO);
    dup2(fileno(out_file), STDOUT_FILENO);
    
    generate_llvm_ir(ast);
    
    // Restore stdout
    fflush(stdout);
    dup2(stdout_backup, STDOUT_FILENO);
    close(stdout_backup);
    
    fclose(out_file);
    free(source);
    
    printf("Compilation successful. LLVM IR written to out.ll\n");
    return 0;
}
