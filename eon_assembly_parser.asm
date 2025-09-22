; eon_assembly_parser.asm
; Recursive-descent parser for Eon language in x86-64 assembly

section .data
    ; AST Node Types
    AST_PROGRAM         equ 0
    AST_FUNCTION_DEF    equ 1
    AST_MODEL_DEF       equ 2
    AST_VAR_DECL        equ 3
    AST_ASSIGNMENT      equ 4
    AST_IF_STMT         equ 5
    AST_LOOP_STMT       equ 6
    AST_RETURN_STMT     equ 7
    AST_BLOCK           equ 8
    AST_BINARY_OP       equ 9
    AST_UNARY_OP        equ 10
    AST_FUNCTION_CALL   equ 11
    AST_IDENTIFIER      equ 12
    AST_LITERAL         equ 13

    ; Parser state
    current_token_type  resq 1
    current_token_value resb 256
    current_token_line  resq 1
    current_token_column resq 1
    
    ; AST management
    ast_node_pool       resb 32768
    ast_pool_position   resq 1
    ast_root            resq 1

section .text
    global parser_init
    global parse_program
    global parse_function_definition
    global parse_model_definition
    global parse_statement
    global parse_expression
    global parse_primary
    global create_ast_node
    global advance_token
    global expect_token
    global match_token

; Initialize parser
parser_init:
    push rbp
    mov rbp, rsp
    
    mov qword [ast_pool_position], ast_node_pool
    mov qword [ast_root], 0
    
    ; Get first token
    call lexer_next_token
    call update_current_token
    
    leave
    ret

; Update current token from lexer
update_current_token:
    push rbp
    mov rbp, rsp
    
    call lexer_get_current_token
    mov [current_token_type], rax
    mov [current_token_line], rcx
    mov [current_token_column], rdx
    
    ; Copy token value
    mov rdi, token_value
    mov rsi, current_token_value
    call copy_string
    
    leave
    ret

; Parse complete program
parse_program:
    push rbp
    mov rbp, rsp
    
    ; Create program node
    mov rdi, AST_PROGRAM
    call create_ast_node
    mov [ast_root], rax
    
    ; Parse top-level declarations
.program_loop:
    mov rbx, [current_token_type]
    cmp rbx, TOKEN_EOF
    je .program_done
    
    ; Parse declaration
    call parse_top_level_declaration
    cmp rax, 0
    je .parse_error
    
    ; Add to program
    mov rbx, [ast_root]
    call add_child_to_node
    
    jmp .program_loop
    
.program_done:
    mov rax, [ast_root]
    leave
    ret
    
.parse_error:
    mov rax, 0
    leave
    ret

; Parse top-level declaration
parse_top_level_declaration:
    push rbp
    mov rbp, rsp
    
    mov rbx, [current_token_type]
    
    cmp rbx, TOKEN_DEF
    je .parse_function
    
    cmp rbx, TOKEN_MODEL
    je .parse_model
    
    ; Try to parse as statement
    call parse_statement
    leave
    ret
    
.parse_function:
    call parse_function_definition
    leave
    ret
    
.parse_model:
    call parse_model_definition
    leave
    ret

; Parse function definition
parse_function_definition:
    push rbp
    mov rbp, rsp
    
    ; Create function node
    mov rdi, AST_FUNCTION_DEF
    call create_ast_node
    push rax
    
    ; Expect 'def'
    mov rdi, TOKEN_DEF
    call expect_token
    
    ; Parse function name
    mov rdi, TOKEN_IDENTIFIER
    call expect_token
    ; Store name in node
    
    ; Expect '('
    mov rdi, TOKEN_LPAREN
    call expect_token
    
    ; Parse parameters (simplified)
    call parse_parameter_list
    
    ; Expect ')'
    mov rdi, TOKEN_RPAREN
    call expect_token
    
    ; Parse return type (optional)
    mov rbx, [current_token_type]
    cmp rbx, TOKEN_ARROW
    jne .parse_body
    
    call advance_token
    mov rdi, TOKEN_IDENTIFIER
    call expect_token
    
.parse_body:
    ; Parse function body
    call parse_block
    
    pop rax
    leave
    ret

; Parse model definition
parse_model_definition:
    push rbp
    mov rbp, rsp
    
    ; Create model node
    mov rdi, AST_MODEL_DEF
    call create_ast_node
    push rax
    
    ; Expect 'model'
    mov rdi, TOKEN_MODEL
    call expect_token
    
    ; Parse model name
    mov rdi, TOKEN_IDENTIFIER
    call expect_token
    
    ; Expect '{'
    mov rdi, TOKEN_LBRACE
    call expect_token
    
    ; Parse fields
    call parse_field_list
    
    ; Expect '}'
    mov rdi, TOKEN_RBRACE
    call expect_token
    
    pop rax
    leave
    ret

; Parse statement
parse_statement:
    push rbp
    mov rbp, rsp
    
    mov rbx, [current_token_type]
    
    cmp rbx, TOKEN_LET
    je .parse_var_decl
    
    cmp rbx, TOKEN_IF
    je .parse_if
    
    cmp rbx, TOKEN_LOOP
    je .parse_loop
    
    cmp rbx, TOKEN_RET
    je .parse_return
    
    cmp rbx, TOKEN_LBRACE
    je .parse_block
    
    ; Try expression statement
    call parse_expression
    leave
    ret
    
.parse_var_decl:
    call parse_variable_declaration
    leave
    ret
    
.parse_if:
    call parse_if_statement
    leave
    ret
    
.parse_loop:
    call parse_loop_statement
    leave
    ret
    
.parse_return:
    call parse_return_statement
    leave
    ret
    
.parse_block:
    call parse_block_statement
    leave
    ret

; Parse expression with precedence
parse_expression:
    call parse_logical_or
    ret

parse_logical_or:
    call parse_logical_and
    ret

parse_logical_and:
    call parse_equality
    ret

parse_equality:
    call parse_relational
    ret

parse_relational:
    call parse_additive
    ret

parse_additive:
    call parse_multiplicative
    ret

parse_multiplicative:
    call parse_unary
    ret

parse_unary:
    push rbp
    mov rbp, rsp
    
    mov rbx, [current_token_type]
    
    cmp rbx, TOKEN_MINUS
    je .unary_minus
    
    cmp rbx, TOKEN_LOGICAL_NOT
    je .unary_not
    
    cmp rbx, TOKEN_BITWISE_NOT
    je .unary_bitwise_not
    
    ; Not a unary operator
    call parse_primary
    leave
    ret
    
.unary_minus:
    call advance_token
    call parse_unary
    ; Create unary node
    leave
    ret
    
.unary_not:
    call advance_token
    call parse_unary
    ; Create unary node
    leave
    ret
    
.unary_bitwise_not:
    call advance_token
    call parse_unary
    ; Create unary node
    leave
    ret

; Parse primary expression
parse_primary:
    push rbp
    mov rbp, rsp
    
    mov rbx, [current_token_type]
    
    cmp rbx, TOKEN_NUMBER
    je .parse_number
    
    cmp rbx, TOKEN_STRING
    je .parse_string
    
    cmp rbx, TOKEN_IDENTIFIER
    je .parse_identifier
    
    cmp rbx, TOKEN_LPAREN
    je .parse_grouped
    
    ; Error
    mov rax, 0
    leave
    ret
    
.parse_number:
    call advance_token
    ; Create literal node
    mov rax, 1
    leave
    ret
    
.parse_string:
    call advance_token
    ; Create literal node
    mov rax, 1
    leave
    ret
    
.parse_identifier:
    call advance_token
    ; Check for function call
    mov rbx, [current_token_type]
    cmp rbx, TOKEN_LPAREN
    je .parse_function_call
    
    ; Create identifier node
    mov rax, 1
    leave
    ret
    
.parse_function_call:
    call advance_token
    ; Parse arguments
    call parse_argument_list
    mov rdi, TOKEN_RPAREN
    call expect_token
    ; Create function call node
    mov rax, 1
    leave
    ret
    
.parse_grouped:
    call advance_token
    call parse_expression
    mov rdi, TOKEN_RPAREN
    call expect_token
    leave
    ret

; Create AST node
create_ast_node:
    push rbp
    mov rbp, rsp
    
    mov rax, [ast_pool_position]
    add qword [ast_pool_position], 64  ; Node size
    
    ; Initialize node
    mov [rax], rdi  ; node type
    mov qword [rax + 8], 0   ; left child
    mov qword [rax + 16], 0  ; right child
    mov qword [rax + 24], 0  ; next sibling
    mov qword [rax + 32], 0  ; data pointer
    mov qword [rax + 40], 0  ; value
    mov qword [rax + 48], 0  ; line
    mov qword [rax + 56], 0  ; column
    
    leave
    ret

; Advance to next token
advance_token:
    push rbp
    mov rbp, rsp
    
    call lexer_next_token
    call update_current_token
    
    leave
    ret

; Expect specific token
expect_token:
    push rbp
    mov rbp, rsp
    
    mov rbx, [current_token_type]
    cmp rbx, rdi
    je .token_matched
    
    ; Error - unexpected token
    mov rax, 0
    leave
    ret
    
.token_matched:
    call advance_token
    mov rax, 1
    leave
    ret

; Match token (optional)
match_token:
    push rbp
    mov rbp, rsp
    
    mov rbx, [current_token_type]
    cmp rbx, rdi
    jne .no_match
    
    call advance_token
    mov rax, 1
    leave
    ret
    
.no_match:
    mov rax, 0
    leave
    ret

; Add child to node
add_child_to_node:
    push rbp
    mov rbp, rsp
    
    ; Find last child
    mov rcx, [rbx + 8]  ; left child
    cmp rcx, 0
    je .add_as_first_child
    
    ; Find last sibling
.find_last_sibling:
    mov rdx, [rcx + 24]  ; next sibling
    cmp rdx, 0
    je .add_sibling
    mov rcx, rdx
    jmp .find_last_sibling
    
.add_sibling:
    mov [rcx + 24], rax
    jmp .done
    
.add_as_first_child:
    mov [rbx + 8], rax
    
.done:
    leave
    ret

; Parse parameter list
parse_parameter_list:
    push rbp
    mov rbp, rsp
    
    ; Simplified - just skip parameters for now
    mov rbx, [current_token_type]
    cmp rbx, TOKEN_RPAREN
    je .done
    
    call advance_token
    jmp parse_parameter_list
    
.done:
    leave
    ret

; Parse field list
parse_field_list:
    push rbp
    mov rbp, rsp
    
    ; Simplified - just skip fields for now
    mov rbx, [current_token_type]
    cmp rbx, TOKEN_RBRACE
    je .done
    
    call advance_token
    jmp parse_field_list
    
.done:
    leave
    ret

; Parse variable declaration
parse_variable_declaration:
    push rbp
    mov rbp, rsp
    
    ; Create var decl node
    mov rdi, AST_VAR_DECL
    call create_ast_node
    
    ; Expect 'let'
    mov rdi, TOKEN_LET
    call expect_token
    
    ; Parse variable name
    mov rdi, TOKEN_IDENTIFIER
    call expect_token
    
    ; Parse type (optional)
    mov rbx, [current_token_type]
    cmp rbx, TOKEN_COLON
    jne .parse_initializer
    
    call advance_token
    mov rdi, TOKEN_IDENTIFIER
    call expect_token
    
.parse_initializer:
    ; Parse initializer (optional)
    mov rbx, [current_token_type]
    cmp rbx, TOKEN_ASSIGN
    jne .done
    
    call advance_token
    call parse_expression
    
.done:
    leave
    ret

; Parse if statement
parse_if_statement:
    push rbp
    mov rbp, rsp
    
    ; Create if node
    mov rdi, AST_IF_STMT
    call create_ast_node
    
    ; Expect 'if'
    mov rdi, TOKEN_IF
    call expect_token
    
    ; Expect '('
    mov rdi, TOKEN_LPAREN
    call expect_token
    
    ; Parse condition
    call parse_expression
    
    ; Expect ')'
    mov rdi, TOKEN_RPAREN
    call expect_token
    
    ; Parse then block
    call parse_statement
    
    ; Parse else block (optional)
    mov rbx, [current_token_type]
    cmp rbx, TOKEN_ELSE
    jne .done
    
    call advance_token
    call parse_statement
    
.done:
    leave
    ret

; Parse loop statement
parse_loop_statement:
    push rbp
    mov rbp, rsp
    
    ; Create loop node
    mov rdi, AST_LOOP_STMT
    call create_ast_node
    
    ; Expect 'loop'
    mov rdi, TOKEN_LOOP
    call expect_token
    
    ; Parse loop body
    call parse_statement
    
    leave
    ret

; Parse return statement
parse_return_statement:
    push rbp
    mov rbp, rsp
    
    ; Create return node
    mov rdi, AST_RETURN_STMT
    call create_ast_node
    
    ; Expect 'ret'
    mov rdi, TOKEN_RET
    call expect_token
    
    ; Parse return value (optional)
    mov rbx, [current_token_type]
    cmp rbx, TOKEN_SEMICOLON
    je .done
    
    call parse_expression
    
.done:
    leave
    ret

; Parse block statement
parse_block_statement:
    push rbp
    mov rbp, rsp
    
    ; Create block node
    mov rdi, AST_BLOCK
    call create_ast_node
    
    ; Expect '{'
    mov rdi, TOKEN_LBRACE
    call expect_token
    
    ; Parse statements
.block_loop:
    mov rbx, [current_token_type]
    cmp rbx, TOKEN_RBRACE
    je .block_done
    
    call parse_statement
    call add_child_to_node
    
    jmp .block_loop
    
.block_done:
    ; Expect '}'
    mov rdi, TOKEN_RBRACE
    call expect_token
    
    leave
    ret

; Parse argument list
parse_argument_list:
    push rbp
    mov rbp, rsp
    
    ; Simplified - just skip arguments for now
    mov rbx, [current_token_type]
    cmp rbx, TOKEN_RPAREN
    je .done
    
    call advance_token
    jmp parse_argument_list
    
.done:
    leave
    ret

; Copy string utility
copy_string:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    mov rbx, rdi
    mov rcx, rsi
    
.loop:
    mov al, [rbx]
    mov [rcx], al
    cmp al, 0
    je .done
    inc rbx
    inc rcx
    jmp .loop
    
.done:
    pop rcx
    pop rbx
    leave
    ret
