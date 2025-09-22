// Filename: codegen.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

// Forward declarations for our simplified AST structure from the parser
typedef enum {
    NODE_FUNC,
    NODE_LET,
    NODE_PRINT,
    NODE_BIN_OP,
    NODE_LITERAL
} NodeType;

typedef struct Node {
    NodeType type;
    char* name;
    long value;
    struct Node* left;
    struct Node* right;
} Node;

// Global buffer for storing the generated assembly code
char* assembly_buffer;
size_t buffer_size;
size_t buffer_capacity;

// Helper function to append strings to the assembly buffer
void emit(const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    // Calculate required space
    va_list args_copy;
    va_copy(args_copy, args);
    int required_size = vsnprintf(NULL, 0, format, args_copy);
    va_end(args_copy);

    // Resize buffer if needed
    if (buffer_size + required_size + 1 > buffer_capacity) {
        size_t new_capacity = buffer_capacity * 2;
        if (new_capacity < buffer_size + required_size + 1) {
            new_capacity = buffer_size + required_size + 1;
        }
        assembly_buffer = realloc(assembly_buffer, new_capacity);
        if (assembly_buffer == NULL) {
            fprintf(stderr, "Memory allocation failed.\n");
            exit(1);
        }
        buffer_capacity = new_capacity;
    }

    // Append to buffer
    vsnprintf(assembly_buffer + buffer_size, buffer_capacity - buffer_size, format, args);
    buffer_size += required_size;
    va_end(args);
}

// Map a variable name to its stack offset
// For this simplified example, we'll just use a single stack slot
int get_stack_offset(const char* name) {
    // In a real compiler, this would be a symbol table lookup
    // to find the variable's offset relative to the base pointer.
    return -8; // Simple example: all variables share one stack slot
}

// Function to generate code for a single AST node
void generate_node(Node* node) {
    if (!node) return;

    switch (node->type) {
        case NODE_FUNC:
            emit(".globl %s\n", node->name);
            emit("%s:\n", node->name);
            emit("    pushq   %%rbp\n");
            emit("    movq    %%rsp, %%rbp\n");
            generate_node(node->left); // Generate body
            emit("    movq    $0, %%rax\n");
            emit("    leave\n");
            emit("    ret\n");
            break;

        case NODE_LET:
            generate_node(node->right); // Evaluate the expression
            emit("    movq    %%rax, %d(%%rbp)\n", get_stack_offset(node->name));
            generate_node(node->left); // Continue generating subsequent statements
            break;

        case NODE_PRINT:
            // Assuming the value to print is already in the stack slot
            emit("    movq    %d(%%rbp), %%rdi\n", get_stack_offset(node->left->name));
            emit("    callq   _print_integer\n"); // Assumes a C library function `_print_integer`
            generate_node(node->right); // Continue generating subsequent statements
            break;

        case NODE_BIN_OP:
            if (strcmp(node->name, "+") == 0) {
                generate_node(node->left);
                emit("    pushq   %%rax\n"); // Push left operand onto stack
                generate_node(node->right);
                emit("    popq    %%rcx\n"); // Pop left operand into rcx
                emit("    addq    %%rcx, %%rax\n"); // Add rcx to right operand in rax
            }
            // Other operators would be handled here
            break;

        case NODE_LITERAL:
            emit("    movq    $%ld, %%rax\n", node->value);
            break;
    }
}

// Main function to orchestrate the compilation process
void compile(Node* ast_root) {
    // Initialize buffer
    buffer_capacity = 1024;
    assembly_buffer = malloc(buffer_capacity);
    if (assembly_buffer == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        exit(1);
    }
    buffer_size = 0;

    // Standard assembly header
    emit(".text\n");

    // Start code generation from the root of the AST
    generate_node(ast_root);

    // Save output to file
    FILE* output_file = fopen("output.asm", "w");
    if (output_file) {
        fwrite(assembly_buffer, 1, buffer_size, output_file);
        fclose(output_file);
    }

    free(assembly_buffer);
}

// Example usage
int main() {
    // Create a simple AST for testing
    Node* main_func = malloc(sizeof(Node));
    main_func->type = NODE_FUNC;
    main_func->name = "main";
    main_func->left = NULL; // Function body would go here
    main_func->right = NULL;
    
    compile(main_func);
    
    free(main_func);
    return 0;
}
