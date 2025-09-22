; reverser_compiler.asm
; Reverser compiler with right-to-left processing
; Implements backwards language processing for unique syntax

section .data
    ; === Reverser Language Features ===
    reverser_info_msg   db "Reverser Compiler - Right-to-Left Processing", 10, 0
    reverser_syntax_msg db "Syntax: ;ret ;let ;if ;loop ;func ;def", 10, 0
    
    ; === Reverser Keywords (stored in reverse) ===
    reverser_def        db "fed", 0      ; def
    reverser_func       db "cnuf", 0     ; func
    reverser_loop       db "pool", 0     ; loop
    reverser_if         db "fi", 0       ; if
    reverser_let        db "tel", 0      ; let
    reverser_ret        db "ter", 0      ; ret
    reverser_model      db "ledom", 0    ; model
    
    ; === Reverser Token Types ===
    REVERSER_EOF        equ 0
    REVERSER_DEF        equ 1
    REVERSER_FUNC       equ 2
    REVERSER_LOOP       equ 3
    REVERSER_IF         equ 4
    REVERSER_LET        equ 5
    REVERSER_RET        equ 6
    REVERSER_MODEL      equ 7
    REVERSER_IDENTIFIER equ 8
    REVERSER_NUMBER     equ 9
    REVERSER_LBRACE     equ 10
    REVERSER_RBRACE     equ 11
    REVERSER_LPAREN     equ 12
    REVERSER_RPAREN     equ 13
    REVERSER_SEMICOLON  equ 14
    REVERSER_ASSIGN     equ 15
    REVERSER_PLUS       equ 16
    REVERSER_MINUS      equ 17
    REVERSER_MULTIPLY   equ 18
    REVERSER_DIVIDE     equ 19
    
    ; === Reverser AST Node Types ===
    REVERSER_AST_PROGRAM    equ 0
    REVERSER_AST_DEF        equ 1
    REVERSER_AST_FUNC       equ 2
    REVERSER_AST_MODEL      equ 3
    REVERSER_AST_LET        equ 4
    REVERSER_AST_IF         equ 5
    REVERSER_AST_LOOP       equ 6
    REVERSER_AST_RET        equ 7
    REVERSER_AST_BLOCK      equ 8
    REVERSER_AST_EXPRESSION equ 9
    REVERSER_AST_IDENTIFIER equ 10
    REVERSER_AST_NUMBER     equ 11
    
    ; === Reverser Compiler State ===
    reverser_source     resq 1
    reverser_position   resq 1
    reverser_length     resq 1
    reverser_line       resq 1
    reverser_column     resq 1
    reverser_current_char resb 1
    
    ; === Reverser Token State ===
    reverser_token_type resq 1
    reverser_token_value resb 256
    reverser_token_line resq 1
    reverser_token_column resq 1
    
    ; === Reverser AST State ===
    reverser_ast_pool   resb 16384  ; 16KB for AST nodes
    reverser_ast_position resq 1
    reverser_ast_root   resq 1
    
    ; === Reverser Code Generation ===
    reverser_output     resb 32768  ; 32KB output buffer
    reverser_output_pos resq 1
    reverser_label_count resq 1
    reverser_temp_count resq 1
    
    ; === Reverser Stack for Right-to-Left Processing ===
    reverser_stack      resq 256    ; Stack for processing
    reverser_stack_top  resq 1

section .text
    global reverser_compiler_init
    global reverser_compile_source
    global reverser_lexer_init
    global reverser_lexer_next
    global reverser_parser_init
    global reverser_parse_program
    global reverser_codegen_init
    global reverser_generate_code
    global reverser_reverse_string
    global reverser_push_stack
    global reverser_pop_stack
    global reverser_process_right_to_left

; === Initialize Reverser Compiler ===
reverser_compiler_init:
    push rbp
    mov rbp, rsp
    
    ; Print reverser info
    mov rdi, reverser_info_msg
    call print_string
    mov rdi, reverser_syntax_msg
    call print_string
    
    ; Initialize state
    mov qword [reverser_position], 0
    mov qword [reverser_line], 1
    mov qword [reverser_column], 1
    mov qword [reverser_ast_position], reverser_ast_pool
    mov qword [reverser_ast_root], 0
    mov qword [reverser_output_pos], 0
    mov qword [reverser_label_count], 0
    mov qword [reverser_temp_count], 0
    mov qword [reverser_stack_top], 0
    
    leave
    ret

; === Compile Reverser Source ===
reverser_compile_source:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = source, rsi = length
    mov [reverser_source], rdi
    mov [reverser_length], rsi
    
    ; Initialize lexer
    call reverser_lexer_init
    
    ; Initialize parser
    call reverser_parser_init
    
    ; Parse program
    call reverser_parse_program
    mov [reverser_ast_root], rax
    
    ; Initialize code generator
    call reverser_codegen_init
    
    ; Generate code
    mov rdi, [reverser_ast_root]
    call reverser_generate_code
    
    ; Return output buffer
    mov rax, reverser_output
    
    leave
    ret

; === Reverser Lexer ===
reverser_lexer_init:
    push rbp
    mov rbp, rsp
    
    call reverser_load_current_char
    call reverser_lexer_next
    
    leave
    ret

reverser_load_current_char:
    push rbp
    mov rbp, rsp
    
    mov rax, [reverser_position]
    cmp rax, [reverser_length]
    jge .eof
    
    mov rbx, [reverser_source]
    mov al, [rbx + rax]
    mov [reverser_current_char], al
    jmp .done
    
.eof:
    mov byte [reverser_current_char], 0
    
.done:
    leave
    ret

reverser_lexer_next:
    push rbp
    mov rbp, rsp
    
    ; Skip whitespace
    call reverser_skip_whitespace
    
    ; Check for EOF
    mov al, [reverser_current_char]
    cmp al, 0
    je .eof_token
    
    ; Record token position
    mov rax, [reverser_line]
    mov [reverser_token_line], rax
    mov rax, [reverser_column]
    mov [reverser_token_column], rax
    
    ; Identify token
    call reverser_identify_token
    
    leave
    ret
    
.eof_token:
    mov qword [reverser_token_type], REVERSER_EOF
    mov byte [reverser_token_value], 0
    leave
    ret

reverser_skip_whitespace:
    push rbp
    mov rbp, rsp
    
.whitespace_loop:
    mov al, [reverser_current_char]
    
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
    call reverser_advance
    jmp .whitespace_loop
    
.newline:
    call reverser_advance
    inc qword [reverser_line]
    mov qword [reverser_column], 1
    jmp .whitespace_loop
    
.done:
    leave
    ret

reverser_advance:
    push rbp
    mov rbp, rsp
    
    inc qword [reverser_position]
    inc qword [reverser_column]
    call reverser_load_current_char
    
    leave
    ret

reverser_identify_token:
    push rbp
    mov rbp, rsp
    
    mov al, [reverser_current_char]
    
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
    call reverser_identify_operator
    leave
    ret
    
.identifier_or_keyword:
    call reverser_read_identifier
    call reverser_is_keyword
    cmp rax, 0
    jne .keyword_found
    
    mov qword [reverser_token_type], REVERSER_IDENTIFIER
    jmp .done
    
.keyword_found:
    mov [reverser_token_type], rax
    jmp .done
    
.number:
    call reverser_read_number
    mov qword [reverser_token_type], REVERSER_NUMBER
    jmp .done
    
.done:
    leave
    ret

reverser_read_identifier:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    mov rbx, reverser_token_value
    mov rcx, 0
    
.identifier_loop:
    mov al, [reverser_current_char]
    
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
    call reverser_advance
    jmp .identifier_loop
    
.identifier_done:
    mov byte [rbx + rcx], 0
    
    pop rcx
    pop rbx
    leave
    ret

reverser_read_number:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    mov rbx, reverser_token_value
    mov rcx, 0
    
.number_loop:
    mov al, [reverser_current_char]
    cmp al, '0'
    jl .number_done
    cmp al, '9'
    jg .number_done
    
    mov [rbx + rcx], al
    inc rcx
    call reverser_advance
    jmp .number_loop
    
.number_done:
    mov byte [rbx + rcx], 0
    
    pop rcx
    pop rbx
    leave
    ret

reverser_identify_operator:
    push rbp
    mov rbp, rsp
    
    mov al, [reverser_current_char]
    
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
    call reverser_advance
    mov qword [reverser_token_type], REVERSER_LBRACE
    jmp .done
    
.rbrace:
    call reverser_advance
    mov qword [reverser_token_type], REVERSER_RBRACE
    jmp .done
    
.lparen:
    call reverser_advance
    mov qword [reverser_token_type], REVERSER_LPAREN
    jmp .done
    
.rparen:
    call reverser_advance
    mov qword [reverser_token_type], REVERSER_RPAREN
    jmp .done
    
.semicolon:
    call reverser_advance
    mov qword [reverser_token_type], REVERSER_SEMICOLON
    jmp .done
    
.assign:
    call reverser_advance
    mov qword [reverser_token_type], REVERSER_ASSIGN
    jmp .done
    
.plus:
    call reverser_advance
    mov qword [reverser_token_type], REVERSER_PLUS
    jmp .done
    
.minus:
    call reverser_advance
    mov qword [reverser_token_type], REVERSER_MINUS
    jmp .done
    
.multiply:
    call reverser_advance
    mov qword [reverser_token_type], REVERSER_MULTIPLY
    jmp .done
    
.divide:
    call reverser_advance
    mov qword [reverser_token_type], REVERSER_DIVIDE
    jmp .done
    
.unknown:
    mov qword [reverser_token_type], REVERSER_EOF
    
.done:
    leave
    ret

reverser_is_keyword:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    ; Compare with reverser keywords
    mov rdi, reverser_token_value
    mov rsi, reverser_def
    call string_compare
    cmp rax, 0
    je .keyword_def_found
    
    mov rdi, reverser_token_value
    mov rsi, reverser_func
    call string_compare
    cmp rax, 0
    je .keyword_func_found
    
    mov rdi, reverser_token_value
    mov rsi, reverser_loop
    call string_compare
    cmp rax, 0
    je .keyword_loop_found
    
    mov rdi, reverser_token_value
    mov rsi, reverser_if
    call string_compare
    cmp rax, 0
    je .keyword_if_found
    
    mov rdi, reverser_token_value
    mov rsi, reverser_let
    call string_compare
    cmp rax, 0
    je .keyword_let_found
    
    mov rdi, reverser_token_value
    mov rsi, reverser_ret
    call string_compare
    cmp rax, 0
    je .keyword_ret_found
    
    mov rdi, reverser_token_value
    mov rsi, reverser_model
    call string_compare
    cmp rax, 0
    je .keyword_model_found
    
    ; Not a keyword
    mov rax, 0
    jmp .done
    
.keyword_def_found:
    mov rax, REVERSER_DEF
    jmp .done
    
.keyword_func_found:
    mov rax, REVERSER_FUNC
    jmp .done
    
.keyword_loop_found:
    mov rax, REVERSER_LOOP
    jmp .done
    
.keyword_if_found:
    mov rax, REVERSER_IF
    jmp .done
    
.keyword_let_found:
    mov rax, REVERSER_LET
    jmp .done
    
.keyword_ret_found:
    mov rax, REVERSER_RET
    jmp .done
    
.keyword_model_found:
    mov rax, REVERSER_MODEL
    jmp .done
    
.done:
    pop rcx
    pop rbx
    leave
    ret

; === Reverser Parser ===
reverser_parser_init:
    push rbp
    mov rbp, rsp
    
    ; Parser is ready to use
    leave
    ret

reverser_parse_program:
    push rbp
    mov rbp, rsp
    
    ; Create program node
    mov rdi, REVERSER_AST_PROGRAM
    call reverser_create_ast_node
    mov [reverser_ast_root], rax
    
    ; Parse declarations (right-to-left)
    call reverser_process_right_to_left
    
    leave
    ret

reverser_process_right_to_left:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    ; Process tokens in reverse order
    mov rbx, [reverser_token_type]
    cmp rbx, REVERSER_EOF
    je .process_done
    
    ; Push current token onto stack
    mov rdi, rbx
    call reverser_push_stack
    
    ; Get next token
    call reverser_lexer_next
    
    ; Recursively process
    call reverser_process_right_to_left
    
    ; Pop from stack and process
    call reverser_pop_stack
    mov rcx, rax
    
    ; Process the token
    call reverser_parse_token
    cmp rax, 0
    je .process_error
    
    ; Add to program
    mov rbx, [reverser_ast_root]
    call reverser_add_child_to_node
    
    jmp .process_done
    
.process_error:
    mov rax, 0
    jmp .done
    
.process_done:
    mov rax, 1
    
.done:
    pop rcx
    pop rbx
    leave
    ret

reverser_parse_token:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = token type
    mov rbx, rdi
    
    cmp rbx, REVERSER_DEF
    je .parse_def
    
    cmp rbx, REVERSER_FUNC
    je .parse_func
    
    cmp rbx, REVERSER_MODEL
    je .parse_model
    
    cmp rbx, REVERSER_LET
    je .parse_let
    
    cmp rbx, REVERSER_IF
    je .parse_if
    
    cmp rbx, REVERSER_LOOP
    je .parse_loop
    
    cmp rbx, REVERSER_RET
    je .parse_ret
    
    ; Default: create expression node
    mov rdi, REVERSER_AST_EXPRESSION
    call reverser_create_ast_node
    leave
    ret
    
.parse_def:
    mov rdi, REVERSER_AST_DEF
    call reverser_create_ast_node
    leave
    ret
    
.parse_func:
    mov rdi, REVERSER_AST_FUNC
    call reverser_create_ast_node
    leave
    ret
    
.parse_model:
    mov rdi, REVERSER_AST_MODEL
    call reverser_create_ast_node
    leave
    ret
    
.parse_let:
    mov rdi, REVERSER_AST_LET
    call reverser_create_ast_node
    leave
    ret
    
.parse_if:
    mov rdi, REVERSER_AST_IF
    call reverser_create_ast_node
    leave
    ret
    
.parse_loop:
    mov rdi, REVERSER_AST_LOOP
    call reverser_create_ast_node
    leave
    ret
    
.parse_ret:
    mov rdi, REVERSER_AST_RET
    call reverser_create_ast_node
    leave
    ret

; === Reverser AST Management ===
reverser_create_ast_node:
    push rbp
    mov rbp, rsp
    
    mov rax, [reverser_ast_position]
    add qword [reverser_ast_position], 32  ; Node size
    
    ; Initialize node
    mov [rax], rdi  ; node type
    mov qword [rax + 8], 0   ; left child
    mov qword [rax + 16], 0  ; right child
    mov qword [rax + 24], 0  ; next sibling
    
    leave
    ret

reverser_add_child_to_node:
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

; === Reverser Stack Operations ===
reverser_push_stack:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = value to push
    mov rbx, [reverser_stack_top]
    mov [reverser_stack + rbx * 8], rdi
    inc qword [reverser_stack_top]
    
    leave
    ret

reverser_pop_stack:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = popped value
    dec qword [reverser_stack_top]
    mov rbx, [reverser_stack_top]
    mov rax, [reverser_stack + rbx * 8]
    
    leave
    ret

; === Reverser Code Generation ===
reverser_codegen_init:
    push rbp
    mov rbp, rsp
    
    ; Initialize code generation
    mov qword [reverser_output_pos], 0
    mov qword [reverser_label_count], 0
    mov qword [reverser_temp_count], 0
    
    ; Generate header
    mov rdi, reverser_output
    mov rsi, "section .text\n"
    call reverser_append_string
    
    mov rdi, reverser_output
    mov rsi, "global _start\n"
    call reverser_append_string
    
    mov rdi, reverser_output
    mov rsi, "_start:\n"
    call reverser_append_string
    
    mov rdi, reverser_output
    mov rsi, "    call main\n"
    call reverser_append_string
    
    mov rdi, reverser_output
    mov rsi, "    mov rax, 60\n"
    call reverser_append_string
    
    mov rdi, reverser_output
    mov rsi, "    mov rdi, 0\n"
    call reverser_append_string
    
    mov rdi, reverser_output
    mov rsi, "    syscall\n"
    call reverser_append_string
    
    leave
    ret

reverser_generate_code:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = AST node
    mov rbx, rdi
    mov rcx, [rbx]  ; node type
    
    cmp rcx, REVERSER_AST_PROGRAM
    je .generate_program
    
    cmp rcx, REVERSER_AST_DEF
    je .generate_def
    
    cmp rcx, REVERSER_AST_FUNC
    je .generate_func
    
    cmp rcx, REVERSER_AST_MODEL
    je .generate_model
    
    cmp rcx, REVERSER_AST_LET
    je .generate_let
    
    cmp rcx, REVERSER_AST_IF
    je .generate_if
    
    cmp rcx, REVERSER_AST_LOOP
    je .generate_loop
    
    cmp rcx, REVERSER_AST_RET
    je .generate_ret
    
    ; Default
    jmp .done
    
.generate_program:
    ; Generate code for each child
    mov rdx, [rbx + 8]  ; left child
    cmp rdx, 0
    je .done
    
    mov rdi, rdx
    call reverser_generate_code
    
    ; Process siblings
    mov rdx, [rdx + 24]  ; next sibling
    cmp rdx, 0
    je .done
    
    mov rdi, rdx
    call reverser_generate_code
    jmp .done
    
.generate_def:
    ; Generate definition code
    mov rdi, reverser_output
    mov rsi, "; def statement\n"
    call reverser_append_string
    jmp .done
    
.generate_func:
    ; Generate function code
    mov rdi, reverser_output
    mov rsi, "main:\n"
    call reverser_append_string
    
    mov rdi, reverser_output
    mov rsi, "    push rbp\n"
    call reverser_append_string
    
    mov rdi, reverser_output
    mov rsi, "    mov rbp, rsp\n"
    call reverser_append_string
    
    mov rdi, reverser_output
    mov rsi, "    mov rax, 0\n"
    call reverser_append_string
    
    mov rdi, reverser_output
    mov rsi, "    leave\n"
    call reverser_append_string
    
    mov rdi, reverser_output
    mov rsi, "    ret\n"
    call reverser_append_string
    jmp .done
    
.generate_model:
    ; Generate model code
    mov rdi, reverser_output
    mov rsi, "; model definition\n"
    call reverser_append_string
    jmp .done
    
.generate_let:
    ; Generate let code
    mov rdi, reverser_output
    mov rsi, "; let statement\n"
    call reverser_append_string
    jmp .done
    
.generate_if:
    ; Generate if code
    mov rdi, reverser_output
    mov rsi, "; if statement\n"
    call reverser_append_string
    jmp .done
    
.generate_loop:
    ; Generate loop code
    mov rdi, reverser_output
    mov rsi, "; loop statement\n"
    call reverser_append_string
    jmp .done
    
.generate_ret:
    ; Generate return code
    mov rdi, reverser_output
    mov rsi, "; return statement\n"
    call reverser_append_string
    jmp .done
    
.done:
    leave
    ret

reverser_append_string:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    ; Args: rdi = buffer, rsi = string
    mov rbx, rdi
    mov rcx, rsi
    
    ; Find end of buffer
    mov rdx, [reverser_output_pos]
    
.append_loop:
    mov al, [rcx]
    cmp al, 0
    je .append_done
    
    mov [rbx + rdx], al
    inc rdx
    inc rcx
    jmp .append_loop
    
.append_done:
    mov [reverser_output_pos], rdx
    
    pop rcx
    pop rbx
    leave
    ret

; === Utility Functions ===
reverser_reverse_string:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    push rdx
    
    ; Args: rdi = string to reverse
    mov rbx, rdi
    mov rcx, 0
    
    ; Find string length
.length_loop:
    cmp byte [rbx + rcx], 0
    je .reverse_loop
    inc rcx
    jmp .length_loop
    
.reverse_loop:
    cmp rcx, 0
    je .reverse_done
    
    dec rcx
    mov al, [rbx + rcx]
    mov dl, [rbx + rdx]
    mov [rbx + rcx], dl
    mov [rbx + rdx], al
    inc rdx
    jmp .reverse_loop
    
.reverse_done:
    pop rdx
    pop rcx
    pop rbx
    leave
    ret

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
