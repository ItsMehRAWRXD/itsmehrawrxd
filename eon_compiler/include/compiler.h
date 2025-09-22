// EON Compiler Header File
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Forward declarations
typedef struct Token Token;
typedef struct AstNode AstNode;
typedef struct Symbol Symbol;
typedef struct EonType EonType;

// Token types
typedef enum {
    TOKEN_EOF, TOKEN_NUMBER, TOKEN_IDENTIFIER, TOKEN_PLUS, TOKEN_MINUS,
    TOKEN_MULTIPLY, TOKEN_DIVIDE, TOKEN_ASSIGN, TOKEN_SEMICOLON,
    TOKEN_LPAREN, TOKEN_RPAREN, TOKEN_LBRACE, TOKEN_RBRACE,
    TOKEN_IF, TOKEN_ELSE, TOKEN_RET, TOKEN_LET, TOKEN_DEF, TOKEN_STRUCT,
    TOKEN_POINTER, TOKEN_DEREFERENCE, TOKEN_ADDRESS_OF, TOKEN_ALLOC,
    TOKEN_GREATER, TOKEN_EQUAL, TOKEN_COMMA, TOKEN_COLON
} TokenType;

// Token structure
typedef struct Token {
    TokenType type;
    char *value;
    int line;
    int column;
} Token;

// AST node types
typedef enum {
    AST_NUMBER, AST_OP, AST_IDENTIFIER, AST_VAR_DECL, AST_ASSIGN, AST_IF, AST_RET, AST_BLOCK,
    AST_FUNCTION_DEFINITION, AST_FUNCTION_CALL, AST_STRUCT_DEFINITION, AST_POINTER_TYPE,
    AST_DEREFERENCE, AST_ADDRESS_OF, AST_PARAMETER, AST_STRUCT_FIELD, AST_PROGRAM,
    AST_FOR_LOOP, AST_WHILE_LOOP, AST_ARRAY_ACCESS, AST_ARRAY_DECL
} AstNodeType;

// Type system
typedef struct EonType {
    char *name;
    int size;
    struct EonType *base_type; // For pointers
    struct EonType **fields;   // For structs
    char **field_names;
    int field_count;
} EonType;

// AST node structure
typedef struct AstNode {
    AstNodeType type;
    EonType *type_info;
    union {
        int value;
        char *name;
        int op;
        struct { char *name; AstNode *type; } identifier;
        struct { char *name; AstNode *init_expr; } var_decl;
        struct { AstNode *cond; AstNode *body; AstNode *else_body; } if_stmt;
        struct { AstNode *ret_expr; } ret_stmt;
        struct { AstNode *head; } block;
        struct { char *name; AstNode *params; AstNode *ret_type; AstNode *body; } func_def;
        struct { char *name; AstNode *args; } func_call;
        struct { char *name; AstNode *fields; } struct_def;
        struct { AstNode *expr; } dereference;
        struct { AstNode *expr; } address_of;
        struct { char *name; AstNode *type; } parameter;
        struct { char *name; AstNode *type; } struct_field;
        struct { AstNode *body; } program;
        struct { AstNode *init; AstNode *cond; AstNode *incr; AstNode *body; } for_loop;
        struct { AstNode *cond; AstNode *body; } while_loop;
        struct { AstNode *array; AstNode *index; } array_access;
        struct { char *name; AstNode *type; AstNode *size; } array_decl;
    } data;
    AstNode *left;
    AstNode *right;
    AstNode *next;
} AstNode;

// Symbol table entry
typedef struct Symbol {
    char *name;
    EonType *type;
    int offset; // Stack offset for local variables
    int is_global;
    AstNode *ast_node; // For functions and structs
} Symbol;

// Symbol table
typedef struct SymbolTable {
    Symbol *symbols;
    int count;
    int capacity;
    struct SymbolTable *parent; // For nested scopes
} SymbolTable;

// Global variables
extern Token current_token;
extern char *source;
extern int source_pos;
extern int source_len;
extern SymbolTable *current_scope;
extern EonType *int_type;
extern EonType *void_type;
extern int label_count;

// Lexer functions
void lexer_init(char *src);
void lexer_next();
Token make_token(TokenType type, char *value);
int is_alpha(char c);
int is_digit(char c);
int is_alnum(char c);
char peek();
char advance();
void skip_whitespace();
Token read_number();
Token read_identifier();
Token read_string();

// Parser functions
AstNode *new_node(AstNodeType type);
AstNode *parse_program();
AstNode *parse_top_level_declaration();
AstNode *parse_function_definition();
AstNode *parse_struct_definition();
AstNode *parse_statement();
AstNode *parse_expression();
AstNode *parse_primary();
AstNode *parse_block();
AstNode *parse_parameter_list();
AstNode *parse_argument_list();
void expect(TokenType expected);
void advance_token();

// Symbol table functions
void symtab_init();
void symtab_push_scope();
void symtab_pop_scope();
Symbol *symtab_put(char *name, EonType *type);
Symbol *symtab_get(char *name);
Symbol *symtab_get_local(char *name);

// Type system functions
EonType *new_type(char *name, int size);
EonType *new_pointer_type(EonType *base_type);
EonType *new_struct_type(char *name, AstNode *fields);
void type_check_ast(AstNode *node);
EonType *get_type_from_ast(AstNode *node);

// Code generator functions
void generate_program(FILE *out, AstNode *node);
void generate_statement(FILE *out, AstNode *node);
void generate_expression(FILE *out, AstNode *node);
void generate_function(FILE *out, AstNode *node);
void generate_struct(FILE *out, AstNode *node);
void generate_arithmetic(FILE *out, AstNode *node);
void generate_comparison(FILE *out, AstNode *node);
void generate_assignment(FILE *out, AstNode *node);
void generate_if_statement(FILE *out, AstNode *node);
void generate_for_loop(FILE *out, AstNode *node);
void generate_while_loop(FILE *out, AstNode *node);
void generate_function_call(FILE *out, AstNode *node);
void generate_return(FILE *out, AstNode *node);
void generate_variable_declaration(FILE *out, AstNode *node);
void generate_struct_access(FILE *out, AstNode *node);
void generate_pointer_operations(FILE *out, AstNode *node);
void generate_array_operations(FILE *out, AstNode *node);

// Utility functions
void emit(FILE *out, const char *format, ...);
int get_stack_offset(char *name);
void push_register(FILE *out, const char *reg);
void pop_register(FILE *out, const char *reg);
void load_variable(FILE *out, char *name);
void store_variable(FILE *out, char *name);
void call_function(FILE *out, char *name, int arg_count);
void allocate_stack_space(FILE *out, int bytes);
void deallocate_stack_space(FILE *out, int bytes);
