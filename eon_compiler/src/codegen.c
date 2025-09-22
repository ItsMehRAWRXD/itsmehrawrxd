// EON Compiler Code Generator Implementation
#include "../include/compiler.h"

int label_count = 0;

void generate_program(FILE *out, AstNode *node) {
    emit(out, ".text");
    emit(out, ".global _start");
    emit(out, "_start:");
    emit(out, "    call main");
    emit(out, "    mov $60, %%rax");
    emit(out, "    mov $0, %%rdi");
    emit(out, "    syscall");
    emit(out, "");
    
    AstNode *decl = node->data.program.body;
    while (decl) {
        generate_statement(out, decl);
        decl = decl->next;
    }
}

void generate_statement(FILE *out, AstNode *node) {
    if (!node) return;
    
    switch (node->type) {
        case AST_FUNCTION_DEFINITION:
            generate_function(out, node);
            break;
        case AST_STRUCT_DEFINITION:
            generate_struct(out, node);
            break;
        case AST_VAR_DECL:
            generate_variable_declaration(out, node);
            break;
        case AST_ASSIGN:
            generate_assignment(out, node);
            break;
        case AST_IF:
            generate_if_statement(out, node);
            break;
        case AST_FOR_LOOP:
            generate_for_loop(out, node);
            break;
        case AST_WHILE_LOOP:
            generate_while_loop(out, node);
            break;
        case AST_RET:
            generate_return(out, node);
            break;
        case AST_BLOCK:
            generate_statement(out, node->data.block.head);
            break;
        default:
            generate_expression(out, node);
            break;
    }
}

void generate_expression(FILE *out, AstNode *node) {
    if (!node) return;
    
    switch (node->type) {
        case AST_NUMBER:
            emit(out, "    push $%d", node->data.value);
            break;
        case AST_IDENTIFIER:
            load_variable(out, node->data.name);
            break;
        case AST_OP:
            if (node->data.op == TOKEN_PLUS || node->data.op == TOKEN_MINUS || 
                node->data.op == TOKEN_MULTIPLY || node->data.op == TOKEN_DIVIDE) {
                generate_arithmetic(out, node);
            } else if (node->data.op == TOKEN_GREATER || node->data.op == TOKEN_EQUAL) {
                generate_comparison(out, node);
            }
            break;
        case AST_FUNCTION_CALL:
            generate_function_call(out, node);
            break;
        case AST_DEREFERENCE:
            generate_pointer_operations(out, node);
            break;
        case AST_ADDRESS_OF:
            generate_pointer_operations(out, node);
            break;
        default:
            break;
    }
}

void generate_function(FILE *out, AstNode *node) {
    emit(out, ".global %s", node->data.func_def.name);
    emit(out, "%s:", node->data.func_def.name);
    emit(out, "    push %%rbp");
    emit(out, "    mov %%rsp, %%rbp");
    
    // Allocate space for local variables
    allocate_stack_space(out, 16); // Simplified
    
    // Generate function body
    generate_statement(out, node->data.func_def.body);
    
    emit(out, "    mov %%rbp, %%rsp");
    emit(out, "    pop %%rbp");
    emit(out, "    ret");
    emit(out, "");
}

void generate_struct(FILE *out, AstNode *node) {
    // Struct definitions don't generate code directly
    // They're used for type checking and memory layout
    emit(out, "// Struct definition: %s", node->data.struct_def.name);
}

void generate_arithmetic(FILE *out, AstNode *node) {
    generate_expression(out, node->left);
    generate_expression(out, node->right);
    
    emit(out, "    pop %%rbx");
    emit(out, "    pop %%rax");
    
    switch (node->data.op) {
        case TOKEN_PLUS:
            emit(out, "    add %%rbx, %%rax");
            break;
        case TOKEN_MINUS:
            emit(out, "    sub %%rbx, %%rax");
            break;
        case TOKEN_MULTIPLY:
            emit(out, "    imul %%rbx, %%rax");
            break;
        case TOKEN_DIVIDE:
            emit(out, "    cqo");
            emit(out, "    idiv %%rbx");
            break;
    }
    
    emit(out, "    push %%rax");
}

void generate_comparison(FILE *out, AstNode *node) {
    generate_expression(out, node->left);
    generate_expression(out, node->right);
    
    emit(out, "    pop %%rbx");
    emit(out, "    pop %%rax");
    emit(out, "    cmp %%rbx, %%rax");
    
    switch (node->data.op) {
        case TOKEN_GREATER:
            emit(out, "    setg %%al");
            break;
        case TOKEN_EQUAL:
            emit(out, "    sete %%al");
            break;
    }
    
    emit(out, "    movzbq %%al, %%rax");
    emit(out, "    push %%rax");
}

void generate_assignment(FILE *out, AstNode *node) {
    generate_expression(out, node->right);
    store_variable(out, node->left->data.name);
}

void generate_if_statement(FILE *out, AstNode *node) {
    int else_label = label_count++;
    int end_label = label_count++;
    
    generate_expression(out, node->data.if_stmt.cond);
    emit(out, "    pop %%rax");
    emit(out, "    cmp $0, %%rax");
    emit(out, "    je _else_%d", else_label);
    
    generate_statement(out, node->data.if_stmt.body);
    emit(out, "    jmp _end_%d", end_label);
    
    emit(out, "_else_%d:", else_label);
    if (node->data.if_stmt.else_body) {
        generate_statement(out, node->data.if_stmt.else_body);
    }
    
    emit(out, "_end_%d:", end_label);
}

void generate_for_loop(FILE *out, AstNode *node) {
    int start_label = label_count++;
    int end_label = label_count++;
    
    generate_statement(out, node->data.for_loop.init);
    emit(out, "_for_start_%d:", start_label);
    generate_expression(out, node->data.for_loop.cond);
    emit(out, "    pop %%rax");
    emit(out, "    cmp $0, %%rax");
    emit(out, "    je _for_end_%d", end_label);
    
    generate_statement(out, node->data.for_loop.body);
    generate_expression(out, node->data.for_loop.incr);
    emit(out, "    jmp _for_start_%d", start_label);
    emit(out, "_for_end_%d:", end_label);
}

void generate_while_loop(FILE *out, AstNode *node) {
    int start_label = label_count++;
    int end_label = label_count++;
    
    emit(out, "_while_start_%d:", start_label);
    generate_expression(out, node->data.while_loop.cond);
    emit(out, "    pop %%rax");
    emit(out, "    cmp $0, %%rax");
    emit(out, "    je _while_end_%d", end_label);
    
    generate_statement(out, node->data.while_loop.body);
    emit(out, "    jmp _while_start_%d", start_label);
    emit(out, "_while_end_%d:", end_label);
}

void generate_function_call(FILE *out, AstNode *node) {
    // Push arguments (simplified - only one argument)
    if (node->data.func_call.args) {
        generate_expression(out, node->data.func_call.args);
    }
    
    emit(out, "    call %s", node->data.func_call.name);
    emit(out, "    push %%rax");
}

void generate_return(FILE *out, AstNode *node) {
    if (node->data.ret_stmt.ret_expr) {
        generate_expression(out, node->data.ret_stmt.ret_expr);
        emit(out, "    pop %%rax");
    } else {
        emit(out, "    mov $0, %%rax");
    }
}

void generate_variable_declaration(FILE *out, AstNode *node) {
    if (node->data.var_decl.init_expr) {
        generate_expression(out, node->data.var_decl.init_expr);
        store_variable(out, node->data.var_decl.name);
    }
}

void generate_pointer_operations(FILE *out, AstNode *node) {
    if (node->type == AST_DEREFERENCE) {
        generate_expression(out, node->data.dereference.expr);
        emit(out, "    pop %%rax");
        emit(out, "    mov (%%rax), %%rax");
        emit(out, "    push %%rax");
    } else if (node->type == AST_ADDRESS_OF) {
        // Address of operation - simplified
        emit(out, "    lea %s(%%rbp), %%rax", node->data.address_of.expr->data.name);
        emit(out, "    push %%rax");
    }
}

void generate_array_operations(FILE *out, AstNode *node) {
    // Array operations - simplified implementation
    generate_expression(out, node->data.array_access.array);
    generate_expression(out, node->data.array_access.index);
    emit(out, "    pop %%rbx");
    emit(out, "    pop %%rax");
    emit(out, "    mov (%%rax, %%rbx, 8), %%rax");
    emit(out, "    push %%rax");
}

// Utility functions
void emit(FILE *out, const char *format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(out, format, args);
    va_end(args);
    fprintf(out, "\n");
}

int get_stack_offset(char *name) {
    Symbol *sym = symtab_get(name);
    if (sym) {
        return sym->offset;
    }
    return -8; // Default offset
}

void push_register(FILE *out, const char *reg) {
    emit(out, "    push %%%s", reg);
}

void pop_register(FILE *out, const char *reg) {
    emit(out, "    pop %%%s", reg);
}

void load_variable(FILE *out, char *name) {
    int offset = get_stack_offset(name);
    emit(out, "    mov %d(%%rbp), %%rax", offset);
    emit(out, "    push %%rax");
}

void store_variable(FILE *out, char *name) {
    int offset = get_stack_offset(name);
    emit(out, "    pop %%rax");
    emit(out, "    mov %%rax, %d(%%rbp)", offset);
}

void call_function(FILE *out, char *name, int arg_count) {
    emit(out, "    call %s", name);
    if (arg_count > 0) {
        emit(out, "    add $%d, %%rsp", arg_count * 8);
    }
}

void allocate_stack_space(FILE *out, int bytes) {
    emit(out, "    sub $%d, %%rsp", bytes);
}

void deallocate_stack_space(FILE *out, int bytes) {
    emit(out, "    add $%d, %%rsp", bytes);
}
