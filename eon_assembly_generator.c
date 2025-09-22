#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Include the semantic analyzer structures
typedef enum { TYPE_INT, TYPE_PTR, TYPE_FUNC, TYPE_STRUCT, TYPE_VOID } SymbolType;
typedef struct AstNode AstNode;

// Assembly code generator for Eon compiler
typedef struct {
    FILE *output_file;
    int label_count;
    int string_count;
    int current_stack_offset;
    int max_stack_size;
    int in_function;
    char *current_function_name;
} AssemblyGenerator;

AssemblyGenerator *init_assembly_generator(FILE *output_file) {
    AssemblyGenerator *gen = malloc(sizeof(AssemblyGenerator));
    gen->output_file = output_file;
    gen->label_count = 0;
    gen->string_count = 0;
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
    
    // System call numbers for Linux x86-64
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
        // Local variable
        fprintf(gen->output_file, "    mov rax, [rbp - %d]\n", stack_offset);
    } else {
        // Global variable
        fprintf(gen->output_file, "    mov rax, [%s]\n", name);
    }
    push_register(gen, "rax");
}

void generate_binary_operation(AssemblyGenerator *gen, int op, AstNode *left, AstNode *right) {
    // Generate code for right operand
    generate_expression(gen, right);
    
    // Generate code for left operand
    generate_expression(gen, left);
    
    // Pop operands
    pop_register(gen, "rax"); // left operand
    pop_register(gen, "rbx"); // right operand
    
    // Perform operation
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
            fprintf(gen->output_file, "    cqo\n");  // Sign extend rax into rdx
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

void generate_address_of(AssemblyGenerator *gen, AstNode *node) {
    if (node->type == AST_IDENTIFIER) {
        // For now, assume it's a local variable
        // In a real implementation, we'd look up the symbol table
        fprintf(gen->output_file, "    lea rax, [rbp - 8]\n"); // Placeholder offset
        push_register(gen, "rax");
    }
}

void generate_dereference(AssemblyGenerator *gen, AstNode *node) {
    generate_expression(gen, node);
    pop_register(gen, "rax");
    fprintf(gen->output_file, "    mov rax, [rax]\n");
    push_register(gen, "rax");
}

void generate_function_call(AssemblyGenerator *gen, char *func_name, AstNode *args) {
    // Push arguments (right to left for x86-64 calling convention)
    int arg_count = 0;
    AstNode *arg = args;
    while (arg) {
        generate_expression(gen, arg);
        pop_register(gen, arg_count < 6 ? "rdi" : "rsi"); // Simplified parameter passing
        arg = arg->next;
        arg_count++;
    }
    
    // Align stack if needed
    if (gen->current_stack_offset % 16 != 0) {
        fprintf(gen->output_file, "    sub rsp, 8\n");
    }
    
    fprintf(gen->output_file, "    call %s\n", func_name);
    
    // Restore stack alignment
    if (gen->current_stack_offset % 16 != 0) {
        fprintf(gen->output_file, "    add rsp, 8\n");
    }
    
    push_register(gen, "rax"); // Function return value
}

void generate_expression(AssemblyGenerator *gen, AstNode *node) {
    if (!node) return;
    
    switch (node->type) {
        case AST_NUMBER:
            generate_number(gen, node->value);
            break;
            
        case AST_IDENTIFIER: {
            // Look up symbol in symbol table (simplified)
            int stack_offset = 8; // Placeholder
            generate_identifier(gen, node->name, stack_offset);
            break;
        }
        
        case AST_OP:
            generate_binary_operation(gen, node->op, node->left, node->right);
            break;
            
        case AST_ADDRESS_OF:
            generate_address_of(gen, node->left);
            break;
            
        case AST_DEREFERENCE:
            generate_dereference(gen, node->left);
            break;
            
        case AST_FUNCTION_CALL:
            generate_function_call(gen, node->name, node->args);
            break;
            
        case AST_ALLOC:
            // Memory allocation (simplified)
            generate_expression(gen, node->left);
            pop_register(gen, "rdi");
            fprintf(gen->output_file, "    mov rax, SYS_BRK\n");
            fprintf(gen->output_file, "    syscall\n");
            push_register(gen, "rax");
            break;
            
        default:
            fprintf(gen->output_file, "    ; Unhandled expression type\n");
            break;
    }
}

void generate_variable_declaration(AssemblyGenerator *gen, AstNode *node) {
    // Generate code for initializer expression
    generate_expression(gen, node->right);
    
    // Store in variable (simplified - assumes local variable)
    pop_register(gen, "rax");
    fprintf(gen->output_file, "    mov [rbp - 8], rax\n"); // Placeholder stack offset
}

void generate_assignment(AssemblyGenerator *gen, AstNode *node) {
    // Generate code for right-hand side
    generate_expression(gen, node->right);
    
    // Store in variable
    pop_register(gen, "rax");
    fprintf(gen->output_file, "    mov [rbp - 8], rax\n"); // Placeholder stack offset
}

void generate_return(AssemblyGenerator *gen, AstNode *node) {
    if (node->left) {
        generate_expression(gen, node->left);
        pop_register(gen, "rax");
    } else {
        fprintf(gen->output_file, "    mov rax, 0\n"); // Default return value
    }
    generate_function_epilogue(gen);
}

void generate_if_statement(AssemblyGenerator *gen, AstNode *node) {
    char *else_label = generate_label(gen, "else");
    char *end_label = generate_label(gen, "endif");
    
    // Generate condition
    generate_expression(gen, node->cond);
    pop_register(gen, "rax");
    
    // Test condition
    fprintf(gen->output_file, "    cmp rax, 0\n");
    fprintf(gen->output_file, "    je %s\n", else_label);
    
    // Generate then block
    generate_statement(gen, node->body);
    fprintf(gen->output_file, "    jmp %s\n", end_label);
    
    // Else block
    fprintf(gen->output_file, "%s:\n", else_label);
    if (node->right) { // If there's an else block
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
    
    // Generate function body
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
            // Thread creation (simplified)
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
    
    // Generate main function if it exists
    AstNode *node = program->body;
    while (node) {
        if (node->type == AST_FUNCTION_DEFINITION && 
            node->name && strcmp(node->name, "main") == 0) {
            generate_function_definition(gen, node);
            break;
        }
        node = node->next;
    }
    
    // Generate other functions
    node = program->body;
    while (node) {
        if (node->type == AST_FUNCTION_DEFINITION && 
            (!node->name || strcmp(node->name, "main") != 0)) {
            generate_statement(gen, node);
        }
        node = node->next;
    }
    
    // Generate startup code
    fprintf(gen->output_file, "; Entry point\n");
    fprintf(gen->output_file, "_start:\n");
    fprintf(gen->output_file, "    call main\n");
    fprintf(gen->output_file, "    mov rdi, rax\n"); // Exit code
    fprintf(gen->output_file, "    mov rax, SYS_EXIT\n");
    fprintf(gen->output_file, "    syscall\n");
}

void cleanup_assembly_generator(AssemblyGenerator *gen) {
    if (gen->current_function_name) {
        free(gen->current_function_name);
    }
    free(gen);
}

// Integration function for the main compiler
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
    
    cleanup_assembly_generator(gen);
    fclose(output_file);
}

// Example usage and test
int main() {
    printf("Eon Assembly Code Generator\n");
    printf("This module generates x86-64 assembly from Eon AST\n");
    
    // Example AST node (simplified)
    AstNode *example_program = malloc(sizeof(AstNode));
    example_program->type = AST_PROGRAM;
    example_program->body = NULL;
    
    // Generate assembly for example
    generate_assembly_code(example_program, "output.s");
    
    free(example_program);
    return 0;
}
