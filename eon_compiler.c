#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

// --- Security Globals ---
unsigned long long security_cookie;

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
    int size; // For bounds checking
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

// --- PARSER (Recursive Descent) ---
void advance() { lexer_next(); }
void expect(int type) {
    if (current_token.type != type) { printf("Syntax error: expected token type %d, got %d ('%s')\n", type, current_token.type, current_token.value); exit(1); }
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

// --- CODE GENERATOR (Stack-Based) ---
const char *reg_order[] = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
const char *arg_reg_order[] = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};

void generate_expression(FILE *out, AstNode *node);
void generate_statement(FILE *out, AstNode *node);

void generate_call(FILE *out, AstNode *node) {
    int arg_count = 0;
    AstNode *current_arg = node->args;
    while (current_arg != NULL) {
        generate_expression(out, current_arg);
        fprintf(out, "    pop %s\n", arg_reg_order[arg_count++]);
        current_arg = current_arg->next;
    }
    // CFI Check (Conceptual)
    fprintf(out, "    ; CFI check: Validate function address before call\n");
    fprintf(out, "    call %s\n", node->name);
    fprintf(out, "    push rax\n");
}

void generate_expression(FILE *out, AstNode *node) {
    if (node->type == AST_NUMBER) {
        fprintf(out, "    push QWORD %d\n", node->value);
    } else if (node->type == AST_IDENTIFIER) {
        int offset = get_symbol_offset(node->name);
        fprintf(out, "    push QWORD [rbp-%d]\n", offset);
    } else if (node->type == AST_OP) {
        generate_expression(out, node->left);
        generate_expression(out, node->right);
        fprintf(out, "    pop rbx\n");
        fprintf(out, "    pop rax\n");
        switch (node->op) {
            case TOKEN_ADD:
                fprintf(out, "    add rax, rbx\n");
                break;
            case TOKEN_SUB:
                fprintf(out, "    sub rax, rbx\n");
                break;
            case TOKEN_MUL:
                fprintf(out, "    imul rax, rbx\n");
                break;
            case TOKEN_DIV:
                fprintf(out, "    cdq\n");
                fprintf(out, "    idiv rbx\n");
                break;
            case TOKEN_GT:
                fprintf(out, "    cmp rax, rbx\n");
                fprintf(out, "    setg al\n");
                fprintf(out, "    movzx rax, al\n");
                break;
        }
        fprintf(out, "    push rax\n");
    } else if (node->type == AST_FUNCTION_CALL) {
        generate_call(out, node);
    } else if (node->type == AST_ALLOC) {
        generate_expression(out, node->left);
        fprintf(out, "    pop rdi\n");
        fprintf(out, "    call malloc\n");
        fprintf(out, "    push rax\n");
    } else if (node->type == AST_SIZEOF) {
        generate_expression(out, node->left);
        fprintf(out, "    pop rax\n");
        fprintf(out, "    push QWORD 8\n");
    } else if (node->type == AST_ADDRESS_OF) {
        int offset = get_symbol_offset(node->left->name);
        fprintf(out, "    lea rax, [rbp-%d]\n", offset);
        fprintf(out, "    push rax\n");
    } else if (node->type == AST_DEREFERENCE) {
        // Buffer Bounds Checking (Conceptual)
        fprintf(out, "    ; Check bounds for dereference\n");
        generate_expression(out, node->left);
        fprintf(out, "    pop rax\n");
        fprintf(out, "    push QWORD [rax]\n");
    } else {
        printf("Unknown AST node in generate_expression: %d\n", node->type);
        exit(1);
    }
}

void generate_statement(FILE *out, AstNode *node) {
    if (node->type == AST_VAR_DECL) {
        generate_expression(out, node->right);
        int offset = get_symbol_offset(node->name);
        fprintf(out, "    pop rax\n");
        fprintf(out, "    mov QWORD [rbp-%d], rax\n", offset);
    } else if (node->type == AST_ASSIGN) {
        generate_expression(out, node->right);
        int offset = get_symbol_offset(node->name);
        fprintf(out, "    pop rax\n");
        fprintf(out, "    mov QWORD [rbp-%d], rax\n", offset);
    } else if (node->type == AST_ASSIGN_DEREF) {
        generate_expression(out, node->left);
        generate_expression(out, node->right);
        fprintf(out, "    pop rbx\n");
        fprintf(out, "    pop rax\n");
        fprintf(out, "    mov QWORD [rax], rbx\n");
    } else if (node->type == AST_IF) {
        int label_num = if_count++;
        generate_expression(out, node->cond);
        fprintf(out, "    pop rax\n");
        fprintf(out, "    cmp rax, 0\n");
        fprintf(out, "    je if_false_%d\n", label_num);
        AstNode *body_node = node->body;
        while (body_node != NULL) {
            generate_statement(out, body_node);
            body_node = body_node->next;
        }
        fprintf(out, "if_false_%d:\n", label_num);
    } else if (node->type == AST_RET) {
        generate_expression(out, node->left);
        fprintf(out, "    pop rax\n");
        fprintf(out, "    jmp end_func\n");
    } else if (node->type == AST_FUNCTION_CALL) {
        generate_call(out, node);
    } else if (node->type == AST_SPAWN) {
        if (node->left->type != AST_FUNCTION_CALL) {
            printf("Error: 'spawn' must be followed by a function call.\n");
            exit(1);
        }
        AstNode *call_node = node->left;
        fprintf(out, "    mov rdi, QWORD thread_id\n");
        fprintf(out, "    mov rsi, %s\n", call_node->name);
        fprintf(out, "    mov rdx, QWORD 0\n");
        fprintf(out, "    call pthread_create\n");
    } else {
        printf("Unknown AST node in generate_statement: %d\n", node->type);
        exit(1);
    }
}

void generate_function(FILE *out, AstNode *node) {
    reset_local_symbols();
    fprintf(out, "%s:\n", node->name);
    fprintf(out, "    push rbp\n");
    fprintf(out, "    mov rbp, rsp\n");
    fprintf(out, "    push QWORD [rel security_cookie]\n");

    int param_count = 0;
    AstNode *current_param = node->args;
    while(current_param != NULL) {
        get_symbol_offset(current_param->name);
        fprintf(out, "    mov QWORD [rbp-%d], %s\n", (local_symbol_count) * 8, arg_reg_order[param_count++]);
        current_param = current_param->next;
    }

    fprintf(out, "    sub rsp, %d\n", MAX_SYMBOLS * 8);

    AstNode *current = node->body;
    while(current != NULL) {
        generate_statement(out, current);
        current = current->next;
    }

    fprintf(out, "end_func:\n");
    fprintf(out, "    pop rbx\n");
    fprintf(out, "    cmp rbx, QWORD [rel security_cookie]\n");
    fprintf(out, "    jne stack_smash_detected\n");
    fprintf(out, "    mov rsp, rbp\n");
    fprintf(out, "    pop rbp\n");
    fprintf(out, "    ret\n");
}

void generate_program(FILE *out, AstNode *node) {
    fprintf(out, "    .intel_syntax noprefix\n");
    fprintf(out, "    .section .note.GNU-stack,\"\",@progbits\n");
    fprintf(out, "    .section .rodata\n");
    fprintf(out, "stack_smash_msg: .string \"Stack smashing detected!\\n\"\n");
    fprintf(out, "section .text\n");
    fprintf(out, "    global main\n");
    fprintf(out, "    extern malloc, pthread_create, puts, exit, srand, time, rand\n");
    fprintf(out, "    .data\n");
    fprintf(out, "security_cookie: dq 0\n");

    AstNode *current = node->body;
    while(current != NULL) {
        if (current->type == AST_FUNCTION_DEFINITION) {
            generate_function(out, current);
        }
        current = current->next;
    }

    fprintf(out, "stack_smash_detected:\n");
    fprintf(out, "    mov rdi, offset stack_smash_msg\n");
    fprintf(out, "    call puts\n");
    fprintf(out, "    mov rdi, 1\n");
    fprintf(out, "    call exit\n");

    fprintf(out, "main:\n");
    fprintf(out, "    mov edi, 0\n");
    fprintf(out, "    call time\n");
    fprintf(out, "    mov edi, eax\n");
    fprintf(out, "    call srand\n");
    fprintf(out, "    call rand\n");
    fprintf(out, "    mov [rel security_cookie], rax\n");
    
    fprintf(out, "    push rbp\n");
    fprintf(out, "    mov rbp, rsp\n");
    fprintf(out, "    sub rsp, %d\n", MAX_SYMBOLS * 8);
    fprintf(out, "    push QWORD [rel security_cookie]\n");

    current = node->body;
    while(current != NULL) {
        if (current->type != AST_FUNCTION_DEFINITION) {
            generate_statement(out, current);
        }
        current = current->next;
    }
    
    fprintf(out, "    pop rbx\n");
    fprintf(out, "    cmp rbx, QWORD [rel security_cookie]\n");
    fprintf(out, "    jne stack_smash_detected\n");
    fprintf(out, "    mov rsp, rbp\n");
    fprintf(out, "    pop rbp\n");
    fprintf(out, "    ret\n");
}

// --- Main Compiler Driver ---
int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <source_file>\n", argv[0]);
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

    lexer_init(source);
    advance();

    AstNode *ast = parse_program();

    FILE *out_file = fopen("out.s", "w");
    if (!out_file) {
        perror("Failed to open output file");
        free(source);
        return 1;
    }

    generate_program(out_file, ast);

    fclose(out_file);
    free(source);
    
    printf("Compilation successful. Assembly code written to out.s\n");
    return 0;
}
