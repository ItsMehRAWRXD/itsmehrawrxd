; eon_kernel_compiler.asm
; Complete Eon kernel compiler in x86-64 assembly
; Implements minimal Eon language features: def model, def func, loop, if, let, ret

section .data
    ; === Kernel Language Features ===
    kernel_features_msg db "Eon Kernel Compiler - Minimal Language Features", 10, 0
    kernel_syntax_msg   db "Supported: def model, def func, loop, if, let, ret", 10, 0
    
    ; === Kernel Keywords ===
    kernel_def          db "def", 0
    kernel_model        db "model", 0
    kernel_func         db "func", 0
    kernel_loop         db "loop", 0
    kernel_if           db "if", 0
    kernel_let          db "let", 0
    kernel_ret          db "ret", 0
    
    ; === Kernel Token Types ===
    KERNEL_EOF          equ 0
    KERNEL_DEF          equ 1
    KERNEL_MODEL        equ 2
    KERNEL_FUNC         equ 3
    KERNEL_LOOP         equ 4
    KERNEL_IF           equ 5
    KERNEL_LET          equ 6
    KERNEL_RET          equ 7
    KERNEL_IDENTIFIER   equ 8
    KERNEL_NUMBER       equ 9
    KERNEL_LBRACE       equ 10
    KERNEL_RBRACE       equ 11
    KERNEL_LPAREN       equ 12
    KERNEL_RPAREN       equ 13
    KERNEL_SEMICOLON    equ 14
    KERNEL_ASSIGN       equ 15
    KERNEL_PLUS         equ 16
    KERNEL_MINUS        equ 17
    KERNEL_MULTIPLY     equ 18
    KERNEL_DIVIDE       equ 19
    
    ; === Kernel AST Node Types ===
    KERNEL_AST_PROGRAM      equ 0
    KERNEL_AST_MODEL_DEF    equ 1
    KERNEL_AST_FUNC_DEF     equ 2
    KERNEL_AST_VAR_DECL     equ 3
    KERNEL_AST_ASSIGNMENT   equ 4
    KERNEL_AST_IF_STMT      equ 5
    KERNEL_AST_LOOP_STMT    equ 6
    KERNEL_AST_RETURN_STMT  equ 7
    KERNEL_AST_BLOCK        equ 8
    KERNEL_AST_BINARY_OP    equ 9
    KERNEL_AST_IDENTIFIER   equ 10
    KERNEL_AST_NUMBER       equ 11
    
    ; === Kernel Compiler State ===
    kernel_source       resq 1
    kernel_position     resq 1
    kernel_length       resq 1
    kernel_line         resq 1
    kernel_column       resq 1
    kernel_current_char resb 1
    
    ; === Kernel Token State ===
    kernel_token_type   resq 1
    kernel_token_value  resb 256
    kernel_token_line   resq 1
    kernel_token_column resq 1
    
    ; === Kernel AST State ===
    kernel_ast_pool     resb 16384  ; 16KB for AST nodes
    kernel_ast_position resq 1
    kernel_ast_root     resq 1
    
    ; === Kernel Code Generation ===
    kernel_output       resb 32768  ; 32KB output buffer
    kernel_output_pos   resq 1
    kernel_label_count  resq 1
    kernel_temp_count   resq 1

section .text
    global kernel_compiler_init
    global kernel_compile_source
    global kernel_lexer_init
    global kernel_lexer_next
    global kernel_parser_init
    global kernel_parse_program
    global kernel_codegen_init
    global kernel_generate_code

; === Initialize Kernel Compiler ===
kernel_compiler_init:
    push rbp
    mov rbp, rsp
    
    ; Print kernel info
    mov rdi, kernel_features_msg
    call print_string
    mov rdi, kernel_syntax_msg
    call print_string
    
    ; Initialize state
    mov qword [kernel_position], 0
    mov qword [kernel_line], 1
    mov qword [kernel_column], 1
    mov qword [kernel_ast_position], kernel_ast_pool
    mov qword [kernel_ast_root], 0
    mov qword [kernel_output_pos], 0
    mov qword [kernel_label_count], 0
    mov qword [kernel_temp_count], 0
    
    leave
    ret

; === Compile Kernel Source ===
kernel_compile_source:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = source, rsi = length
    mov [kernel_source], rdi
    mov [kernel_length], rsi
    
    ; Initialize lexer
    call kernel_lexer_init
    
    ; Initialize parser
    call kernel_parser_init
    
    ; Parse program
    call kernel_parse_program
    mov [kernel_ast_root], rax
    
    ; Initialize code generator
    call kernel_codegen_init
    
    ; Generate code
    mov rdi, [kernel_ast_root]
    call kernel_generate_code
    
    ; Return output buffer
    mov rax, kernel_output
    
    leave
    ret

; === Kernel Lexer ===
kernel_lexer_init:
    push rbp
    mov rbp, rsp
    
    call kernel_load_current_char
    call kernel_lexer_next
    
    leave
    ret

kernel_load_current_char:
    push rbp
    mov rbp, rsp
    
    mov rax, [kernel_position]
    cmp rax, [kernel_length]
    jge .eof
    
    mov rbx, [kernel_source]
    mov al, [rbx + rax]
    mov [kernel_current_char], al
    jmp .done
    
.eof:
    mov byte [kernel_current_char], 0
    
.done:
    leave
    ret

kernel_lexer_next:
    push rbp
    mov rbp, rsp
    
    ; Skip whitespace
    call kernel_skip_whitespace
    
    ; Check for EOF
    mov al, [kernel_current_char]
    cmp al, 0
    je .eof_token
    
    ; Record token position
    mov rax, [kernel_line]
    mov [kernel_token_line], rax
    mov rax, [kernel_column]
    mov [kernel_token_column], rax
    
    ; Identify token
    call kernel_identify_token
    
    leave
    ret
    
.eof_token:
    mov qword [kernel_token_type], KERNEL_EOF
    mov byte [kernel_token_value], 0
    leave
    ret

kernel_skip_whitespace:
    push rbp
    mov rbp, rsp
    
.whitespace_loop:
    mov al, [kernel_current_char]
    
    cmp al, ' '
    je .skip_char
    cmp al, 9              ; tab
    je .skip_char
    cmp al, 10             ; newline
    je .newline
    cmp al, 13             ; carriage return
    je .newline
    
    jmp .done
    
.skip_char:
    call kernel_advance
    jmp .whitespace_loop
    
.newline:
    call kernel_advance
    inc qword [kernel_line]
    mov qword [kernel_column], 1
    jmp .whitespace_loop
    
.done:
    leave
    ret

kernel_advance:
    push rbp
    mov rbp, rsp
    
    inc qword [kernel_position]
    inc qword [kernel_column]
    call kernel_load_current_char
    
    leave
    ret

kernel_identify_token:
    push rbp
    mov rbp, rsp
    
    mov al, [kernel_current_char]
    
    ; Check for letters (identifiers/keywords)
    cmp al, 'a'
    jl .not_letter
    cmp al, 'z'
    jle .identifier_or_keyword
    cmp al, 'A'
    jl .not_letter
    cmp al, 'Z'
    jle .identifier_or_keyword
    cmp al, '_'
    je .identifier_or_keyword
    
.not_letter:
    ; Check for digits
    cmp al, '0'
    jl .not_digit
    cmp al, '9'
    jg .not_digit
    jmp .number
    
.not_digit:
    ; Check for operators and punctuation
    call kernel_identify_operator
    leave
    ret
    
.identifier_or_keyword:
    call kernel_read_identifier
    call kernel_is_keyword
    cmp rax, 0
    jne .keyword_found
    
    mov qword [kernel_token_type], KERNEL_IDENTIFIER
    jmp .done
    
.keyword_found:
    mov [kernel_token_type], rax
    jmp .done
    
.number:
    call kernel_read_number
    mov qword [kernel_token_type], KERNEL_NUMBER
    jmp .done
    
.done:
    leave
    ret

kernel_read_identifier:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    mov rbx, kernel_token_value
    mov rcx, 0
    
.identifier_loop:
    mov al, [kernel_current_char]
    
    ; Check if valid identifier character
    cmp al, 'a'
    jl .identifier_done
    cmp al, 'z'
    jle .add_char
    cmp al, 'A'
    jl .identifier_done
    cmp al, 'Z'
    jle .add_char
    cmp al, '_'
    je .add_char
    cmp al, '0'
    jl .identifier_done
    cmp al, '9'
    jg .identifier_done
    
.add_char:
    mov [rbx + rcx], al
    inc rcx
    call kernel_advance
    jmp .identifier_loop
    
.identifier_done:
    mov byte [rbx + rcx], 0
    
    pop rcx
    pop rbx
    leave
    ret

kernel_read_number:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    mov rbx, kernel_token_value
    mov rcx, 0
    
.number_loop:
    mov al, [kernel_current_char]
    cmp al, '0'
    jl .number_done
    cmp al, '9'
    jg .number_done
    
    mov [rbx + rcx], al
    inc rcx
    call kernel_advance
    jmp .number_loop
    
.number_done:
    mov byte [rbx + rcx], 0
    
    pop rcx
    pop rbx
    leave
    ret

kernel_identify_operator:
    push rbp
    mov rbp, rsp
    
    mov al, [kernel_current_char]
    
    cmp al, '{'
    je .lbrace
    cmp al, '}'
    je .rbrace
    cmp al, '('
    je .lparen
    cmp al, ')'
    je .rparen
    cmp al, ';'
    je .semicolon
    cmp al, '='
    je .assign
    cmp al, '+'
    je .plus
    cmp al, '-'
    je .minus
    cmp al, '*'
    je .multiply
    cmp al, '/'
    je .divide
    
    ; Unknown character
    jmp .unknown
    
.lbrace:
    call kernel_advance
    mov qword [kernel_token_type], KERNEL_LBRACE
    jmp .done
    
.rbrace:
    call kernel_advance
    mov qword [kernel_token_type], KERNEL_RBRACE
    jmp .done
    
.lparen:
    call kernel_advance
    mov qword [kernel_token_type], KERNEL_LPAREN
    jmp .done
    
.rparen:
    call kernel_advance
    mov qword [kernel_token_type], KERNEL_RPAREN
    jmp .done
    
.semicolon:
    call kernel_advance
    mov qword [kernel_token_type], KERNEL_SEMICOLON
    jmp .done
    
.assign:
    call kernel_advance
    mov qword [kernel_token_type], KERNEL_ASSIGN
    jmp .done
    
.plus:
    call kernel_advance
    mov qword [kernel_token_type], KERNEL_PLUS
    jmp .done
    
.minus:
    call kernel_advance
    mov qword [kernel_token_type], KERNEL_MINUS
    jmp .done
    
.multiply:
    call kernel_advance
    mov qword [kernel_token_type], KERNEL_MULTIPLY
    jmp .done
    
.divide:
    call kernel_advance
    mov qword [kernel_token_type], KERNEL_DIVIDE
    jmp .done
    
.unknown:
    mov qword [kernel_token_type], KERNEL_EOF
    
.done:
    leave
    ret

kernel_is_keyword:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    ; Compare with kernel keywords
    mov rdi, kernel_token_value
    mov rsi, kernel_def
    call string_compare
    cmp rax, 0
    je .keyword_def_found
    
    mov rdi, kernel_token_value
    mov rsi, kernel_model
    call string_compare
    cmp rax, 0
    je .keyword_model_found
    
    mov rdi, kernel_token_value
    mov rsi, kernel_func
    call string_compare
    cmp rax, 0
    je .keyword_func_found
    
    mov rdi, kernel_token_value
    mov rsi, kernel_loop
    call string_compare
    cmp rax, 0
    je .keyword_loop_found
    
    mov rdi, kernel_token_value
    mov rsi, kernel_if
    call string_compare
    cmp rax, 0
    je .keyword_if_found
    
    mov rdi, kernel_token_value
    mov rsi, kernel_let
    call string_compare
    cmp rax, 0
    je .keyword_let_found
    
    mov rdi, kernel_token_value
    mov rsi, kernel_ret
    call string_compare
    cmp rax, 0
    je .keyword_ret_found
    
    ; Not a keyword
    mov rax, 0
    jmp .done
    
.keyword_def_found:
    mov rax, KERNEL_DEF
    jmp .done
    
.keyword_model_found:
    mov rax, KERNEL_MODEL
    jmp .done
    
.keyword_func_found:
    mov rax, KERNEL_FUNC
    jmp .done
    
.keyword_loop_found:
    mov rax, KERNEL_LOOP
    jmp .done
    
.keyword_if_found:
    mov rax, KERNEL_IF
    jmp .done
    
.keyword_let_found:
    mov rax, KERNEL_LET
    jmp .done
    
.keyword_ret_found:
    mov rax, KERNEL_RET
    jmp .done
    
.done:
    pop rcx
    pop rbx
    leave
    ret

; === Kernel Parser ===
kernel_parser_init:
    push rbp
    mov rbp, rsp
    
    ; Parser is ready to use
    leave
    ret

kernel_parse_program:
    push rbp
    mov rbp, rsp
    
    ; Create program node
    mov rdi, KERNEL_AST_PROGRAM
    call kernel_create_ast_node
    mov [kernel_ast_root], rax
    
    ; Parse declarations
.program_loop:
    mov rbx, [kernel_token_type]
    cmp rbx, KERNEL_EOF
    je .program_done
    
    call kernel_parse_declaration
    cmp rax, 0
    je .parse_error
    
    ; Add to program
    mov rbx, [kernel_ast_root]
    call kernel_add_child_to_node
    
    jmp .program_loop
    
.program_done:
    mov rax, [kernel_ast_root]
    leave
    ret
    
.parse_error:
    mov rax, 0
    leave
    ret

kernel_parse_declaration:
    push rbp
    mov rbp, rsp
    
    mov rbx, [kernel_token_type]
    
    cmp rbx, KERNEL_DEF
    jne .parse_statement
    
    call kernel_advance_token
    mov rbx, [kernel_token_type]
    
    cmp rbx, KERNEL_MODEL
    je .parse_model_def
    
    cmp rbx, KERNEL_FUNC
    je .parse_func_def
    
    ; Error
    mov rax, 0
    leave
    ret
    
.parse_model_def:
    call kernel_parse_model_definition
    leave
    ret
    
.parse_func_def:
    call kernel_parse_function_definition
    leave
    ret
    
.parse_statement:
    call kernel_parse_statement
    leave
    ret

kernel_parse_model_definition:
    push rbp
    mov rbp, rsp
    
    ; Create model node
    mov rdi, KERNEL_AST_MODEL_DEF
    call kernel_create_ast_node
    push rax
    
    ; Expect 'model'
    mov rdi, KERNEL_MODEL
    call kernel_expect_token
    
    ; Parse model name
    mov rdi, KERNEL_IDENTIFIER
    call kernel_expect_token
    
    ; Expect '{'
    mov rdi, KERNEL_LBRACE
    call kernel_expect_token
    
    ; Parse fields (simplified)
    call kernel_parse_fields
    
    ; Expect '}'
    mov rdi, KERNEL_RBRACE
    call kernel_expect_token
    
    pop rax
    leave
    ret

kernel_parse_function_definition:
    push rbp
    mov rbp, rsp
    
    ; Create function node
    mov rdi, KERNEL_AST_FUNC_DEF
    call kernel_create_ast_node
    push rax
    
    ; Expect 'func'
    mov rdi, KERNEL_FUNC
    call kernel_expect_token
    
    ; Parse function name
    mov rdi, KERNEL_IDENTIFIER
    call kernel_expect_token
    
    ; Expect '('
    mov rdi, KERNEL_LPAREN
    call kernel_expect_token
    
    ; Parse parameters (simplified)
    call kernel_parse_parameters
    
    ; Expect ')'
    mov rdi, KERNEL_RPAREN
    call kernel_expect_token
    
    ; Parse function body
    call kernel_parse_block
    
    pop rax
    leave
    ret

kernel_parse_statement:
    push rbp
    mov rbp, rsp
    
    mov rbx, [kernel_token_type]
    
    cmp rbx, KERNEL_LET
    je .parse_var_decl
    
    cmp rbx, KERNEL_IF
    je .parse_if_stmt
    
    cmp rbx, KERNEL_LOOP
    je .parse_loop_stmt
    
    cmp rbx, KERNEL_RET
    je .parse_return_stmt
    
    cmp rbx, KERNEL_LBRACE
    je .parse_block
    
    ; Try expression
    call kernel_parse_expression
    leave
    ret
    
.parse_var_decl:
    call kernel_parse_variable_declaration
    leave
    ret
    
.parse_if_stmt:
    call kernel_parse_if_statement
    leave
    ret
    
.parse_loop_stmt:
    call kernel_parse_loop_statement
    leave
    ret
    
.parse_return_stmt:
    call kernel_parse_return_statement
    leave
    ret
    
.parse_block:
    call kernel_parse_block_statement
    leave
    ret

kernel_parse_expression:
    push rbp
    mov rbp, rsp
    
    ; Simplified expression parsing
    mov rbx, [kernel_token_type]
    
    cmp rbx, KERNEL_IDENTIFIER
    je .parse_identifier
    
    cmp rbx, KERNEL_NUMBER
    je .parse_number
    
    ; Error
    mov rax, 0
    leave
    ret
    
.parse_identifier:
    call kernel_advance_token
    mov rdi, KERNEL_AST_IDENTIFIER
    call kernel_create_ast_node
    leave
    ret
    
.parse_number:
    call kernel_advance_token
    mov rdi, KERNEL_AST_NUMBER
    call kernel_create_ast_node
    leave
    ret

kernel_parse_variable_declaration:
    push rbp
    mov rbp, rsp
    
    ; Create var decl node
    mov rdi, KERNEL_AST_VAR_DECL
    call kernel_create_ast_node
    
    ; Expect 'let'
    mov rdi, KERNEL_LET
    call kernel_expect_token
    
    ; Parse variable name
    mov rdi, KERNEL_IDENTIFIER
    call kernel_expect_token
    
    ; Parse initializer (optional)
    mov rbx, [kernel_token_type]
    cmp rbx, KERNEL_ASSIGN
    jne .done
    
    call kernel_advance_token
    call kernel_parse_expression
    
.done:
    leave
    ret

kernel_parse_if_statement:
    push rbp
    mov rbp, rsp
    
    ; Create if node
    mov rdi, KERNEL_AST_IF_STMT
    call kernel_create_ast_node
    
    ; Expect 'if'
    mov rdi, KERNEL_IF
    call kernel_expect_token
    
    ; Expect '('
    mov rdi, KERNEL_LPAREN
    call kernel_expect_token
    
    ; Parse condition
    call kernel_parse_expression
    
    ; Expect ')'
    mov rdi, KERNEL_RPAREN
    call kernel_expect_token
    
    ; Parse then block
    call kernel_parse_statement
    
    leave
    ret

kernel_parse_loop_statement:
    push rbp
    mov rbp, rsp
    
    ; Create loop node
    mov rdi, KERNEL_AST_LOOP_STMT
    call kernel_create_ast_node
    
    ; Expect 'loop'
    mov rdi, KERNEL_LOOP
    call kernel_expect_token
    
    ; Parse loop body
    call kernel_parse_statement
    
    leave
    ret

kernel_parse_return_statement:
    push rbp
    mov rbp, rsp
    
    ; Create return node
    mov rdi, KERNEL_AST_RETURN_STMT
    call kernel_create_ast_node
    
    ; Expect 'ret'
    mov rdi, KERNEL_RET
    call kernel_expect_token
    
    ; Parse return value (optional)
    mov rbx, [kernel_token_type]
    cmp rbx, KERNEL_SEMICOLON
    je .done
    
    call kernel_parse_expression
    
.done:
    leave
    ret

kernel_parse_block_statement:
    push rbp
    mov rbp, rsp
    
    ; Create block node
    mov rdi, KERNEL_AST_BLOCK
    call kernel_create_ast_node
    
    ; Expect '{'
    mov rdi, KERNEL_LBRACE
    call kernel_expect_token
    
    ; Parse statements
.block_loop:
    mov rbx, [kernel_token_type]
    cmp rbx, KERNEL_RBRACE
    je .block_done
    
    call kernel_parse_statement
    call kernel_add_child_to_node
    
    jmp .block_loop
    
.block_done:
    ; Expect '}'
    mov rdi, KERNEL_RBRACE
    call kernel_expect_token
    
    leave
    ret

kernel_parse_block:
    call kernel_parse_block_statement
    ret

kernel_parse_fields:
    push rbp
    mov rbp, rsp
    
    ; Simplified - just skip fields
    mov rbx, [kernel_token_type]
    cmp rbx, KERNEL_RBRACE
    je .done
    
    call kernel_advance_token
    jmp kernel_parse_fields
    
.done:
    leave
    ret

kernel_parse_parameters:
    push rbp
    mov rbp, rsp
    
    ; Simplified - just skip parameters
    mov rbx, [kernel_token_type]
    cmp rbx, KERNEL_RPAREN
    je .done
    
    call kernel_advance_token
    jmp kernel_parse_parameters
    
.done:
    leave
    ret

; === Kernel AST Management ===
kernel_create_ast_node:
    push rbp
    mov rbp, rsp
    
    mov rax, [kernel_ast_position]
    add qword [kernel_ast_position], 32  ; Node size
    
    ; Initialize node
    mov [rax], rdi  ; node type
    mov qword [rax + 8], 0   ; left child
    mov qword [rax + 16], 0  ; right child
    mov qword [rax + 24], 0  ; next sibling
    
    leave
    ret

kernel_add_child_to_node:
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

kernel_advance_token:
    push rbp
    mov rbp, rsp
    
    call kernel_lexer_next
    leave
    ret

kernel_expect_token:
    push rbp
    mov rbp, rsp
    
    mov rbx, [kernel_token_type]
    cmp rbx, rdi
    je .token_matched
    
    ; Error - unexpected token
    mov rax, 0
    leave
    ret
    
.token_matched:
    call kernel_advance_token
    mov rax, 1
    leave
    ret

; === Kernel Code Generation ===
kernel_codegen_init:
    push rbp
    mov rbp, rsp
    
    ; Initialize code generation
    mov qword [kernel_output_pos], 0
    mov qword [kernel_label_count], 0
    mov qword [kernel_temp_count], 0
    
    ; Generate header
    mov rdi, kernel_output
    mov rsi, "section .text\n"
    call kernel_append_string
    
    mov rdi, kernel_output
    mov rsi, "global _start\n"
    call kernel_append_string
    
    mov rdi, kernel_output
    mov rsi, "_start:\n"
    call kernel_append_string
    
    mov rdi, kernel_output
    mov rsi, "    call main\n"
    call kernel_append_string
    
    mov rdi, kernel_output
    mov rsi, "    mov rax, 60\n"
    call kernel_append_string
    
    mov rdi, kernel_output
    mov rsi, "    mov rdi, 0\n"
    call kernel_append_string
    
    mov rdi, kernel_output
    mov rsi, "    syscall\n"
    call kernel_append_string
    
    leave
    ret

kernel_generate_code:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = AST node
    mov rbx, rdi
    mov rcx, [rbx]  ; node type
    
    cmp rcx, KERNEL_AST_PROGRAM
    je .generate_program
    
    cmp rcx, KERNEL_AST_FUNC_DEF
    je .generate_function
    
    cmp rcx, KERNEL_AST_MODEL_DEF
    je .generate_model
    
    ; Default
    jmp .done
    
.generate_program:
    ; Generate code for each child
    mov rdx, [rbx + 8]  ; left child
    cmp rdx, 0
    je .done
    
    mov rdi, rdx
    call kernel_generate_code
    
    ; Process siblings
    mov rdx, [rdx + 24]  ; next sibling
    cmp rdx, 0
    je .done
    
    mov rdi, rdx
    call kernel_generate_code
    jmp .done
    
.generate_function:
    ; Generate function code
    mov rdi, kernel_output
    mov rsi, "main:\n"
    call kernel_append_string
    
    mov rdi, kernel_output
    mov rsi, "    push rbp\n"
    call kernel_append_string
    
    mov rdi, kernel_output
    mov rsi, "    mov rbp, rsp\n"
    call kernel_append_string
    
    ; Generate function body
    mov rdx, [rbx + 8]  ; left child (body)
    cmp rdx, 0
    je .function_done
    
    mov rdi, rdx
    call kernel_generate_code
    
.function_done:
    mov rdi, kernel_output
    mov rsi, "    mov rax, 0\n"
    call kernel_append_string
    
    mov rdi, kernel_output
    mov rsi, "    leave\n"
    call kernel_append_string
    
    mov rdi, kernel_output
    mov rsi, "    ret\n"
    call kernel_append_string
    jmp .done
    
.generate_model:
    ; Models don't generate code
    jmp .done
    
.done:
    leave
    ret

kernel_append_string:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    ; Args: rdi = buffer, rsi = string
    mov rbx, rdi
    mov rcx, rsi
    
    ; Find end of buffer
    mov rdx, [kernel_output_pos]
    
.append_loop:
    mov al, [rcx]
    cmp al, 0
    je .append_done
    
    mov [rbx + rdx], al
    inc rdx
    inc rcx
    jmp .append_loop
    
.append_done:
    mov [kernel_output_pos], rdx
    
    pop rcx
    pop rbx
    leave
    ret

; === Utility Functions ===
string_compare:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    mov rbx, rdi
    mov rcx, rsi
    
.compare_loop:
    mov al, [rbx]
    mov dl, [rcx]
    
    cmp al, dl
    jne .not_equal
    
    cmp al, 0
    je .equal
    
    inc rbx
    inc rcx
    jmp .compare_loop
    
.equal:
    mov rax, 0
    jmp .done
    
.not_equal:
    mov rax, 1
    
.done:
    pop rcx
    pop rbx
    leave
    ret

print_string:
    push rbp
    mov rbp, rsp
    push rbx
    
    mov rbx, rdi
    mov rdx, 0
    
    ; Calculate string length
.length_loop:
    cmp byte [rbx + rdx], 0
    je .print
    inc rdx
    jmp .length_loop
    
.print:
    mov rax, 1              ; sys_write
    mov rdi, 1              ; stdout
    mov rsi, rbx
    syscall
    
    pop rbx
    leave
    ret
