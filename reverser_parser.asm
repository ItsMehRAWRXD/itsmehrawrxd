; reverser_parser.asm
; Recursive descent parser for Reverser language
; Builds AST by processing source backwards

%include "reverser_lexer.asm"
%include "reverser_ast.asm"

section .data
    ; Parser error messages
    error_unexpected_token db "Unexpected token: ", 0
    error_expected_token db "Expected token: ", 0
    error_syntax_error db "Syntax error", 0
    error_missing_brace db "Missing closing brace", 0
    error_missing_paren db "Missing closing parenthesis", 0

section .bss
    ; Parser state
    parser_root        resq 1      ; Root of AST
    parser_current     resq 1      ; Current node being built
    parser_stack       resq 64     ; Parser stack for nested constructs
    parser_stack_top   resq 1      ; Top of parser stack

section .text
    global parser_init
    global parser_parse
    global parser_parse_program
    global parser_parse_function
    global parser_parse_model
    global parser_parse_statement
    global parser_parse_expression
    global parser_parse_block
    global parser_expect_token
    global parser_peek_token
    global parser_advance_token
    global parser_error

; Initialize parser
; Input: rdi = source pointer, rsi = source length
parser_init:
    push rbx
    
    ; Initialize lexer
    call lexer_init
    
    ; Initialize parser state
    mov qword [parser_root], 0
    mov qword [parser_current], 0
    mov qword [parser_stack_top], 0
    
    ; Initialize AST
    call ast_free_tree
    
    pop rbx
    ret

; Main parse function
; Output: rax = root AST node
parser_parse:
    push rbx
    push rcx
    push rdx
    
    ; Parse the program
    call parser_parse_program
    mov [parser_root], rax
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Parse a program (top-level)
; Output: rax = program AST node
parser_parse_program:
    push rbx
    push rcx
    push rdx
    
    ; Create program node
    mov rdi, AST_PROGRAM
    call ast_create_node
    mov rbx, rax  ; Save program node
    
    ; Parse declarations until EOF
.parse_loop:
    call lexer_peek_token
    cmp rax, TOKEN_EOF
    je .done
    
    ; Parse function or model declaration
    cmp rax, TOKEN_CNUF
    je .parse_function
    cmp rax, TOKEN_LEDOM
    je .parse_model
    
    ; Unexpected token
    call parser_error
    jmp .error

.parse_function:
    call parser_parse_function
    mov rdi, rbx
    mov rsi, rax
    call ast_add_child
    jmp .parse_loop

.parse_model:
    call parser_parse_model
    mov rdi, rbx
    mov rsi, rax
    call ast_add_child
    jmp .parse_loop

.done:
    mov rax, rbx
    jmp .return

.error:
    mov rax, 0

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Parse a function declaration
; Output: rax = function AST node
parser_parse_function:
    push rbx
    push rcx
    push rdx
    
    ; Create function node
    mov rdi, AST_FUNCTION
    call ast_create_node
    mov rbx, rax  ; Save function node
    
    ; Expect 'cnuf' keyword
    call parser_expect_token
    cmp rax, TOKEN_CNUF
    jne .error
    
    ; Parse function name
    call parser_advance_token
    call parser_parse_identifier
    mov rdi, rbx
    mov rsi, rax
    call ast_add_child
    
    ; Expect '('
    call parser_expect_token
    cmp rax, TOKEN_LPAREN
    jne .error
    
    ; Parse parameters
    call parser_parse_parameters
    mov rdi, rbx
    mov rsi, rax
    call ast_add_child
    
    ; Expect ')'
    call parser_expect_token
    cmp rax, TOKEN_RPAREN
    jne .error
    
    ; Parse return type if present
    call parser_peek_token
    cmp rax, TOKEN_ARROW
    jne .parse_body
    
    call parser_advance_token  ; Skip '->'
    call parser_parse_type
    mov rdi, rbx
    mov rsi, rax
    call ast_add_child

.parse_body:
    ; Parse function body
    call parser_parse_block
    mov rdi, rbx
    mov rsi, rax
    call ast_add_child
    
    mov rax, rbx
    jmp .return

.error:
    mov rax, 0

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Parse a model declaration
; Output: rax = model AST node
parser_parse_model:
    push rbx
    push rcx
    push rdx
    
    ; Create model node
    mov rdi, AST_MODEL
    call ast_create_node
    mov rbx, rax  ; Save model node
    
    ; Expect 'ledom' keyword
    call parser_expect_token
    cmp rax, TOKEN_LEDOM
    jne .error
    
    ; Parse model name
    call parser_advance_token
    call parser_parse_identifier
    mov rdi, rbx
    mov rsi, rax
    call ast_add_child
    
    ; Expect '{'
    call parser_expect_token
    cmp rax, TOKEN_LBRACE
    jne .error
    
    ; Parse fields
    call parser_parse_fields
    mov rdi, rbx
    mov rsi, rax
    call ast_add_child
    
    ; Expect '}'
    call parser_expect_token
    cmp rax, TOKEN_RBRACE
    jne .error
    
    mov rax, rbx
    jmp .return

.error:
    mov rax, 0

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Parse a block of statements
; Output: rax = block AST node
parser_parse_block:
    push rbx
    push rcx
    push rdx
    
    ; Create block node
    mov rdi, AST_BLOCK
    call ast_create_node
    mov rbx, rax  ; Save block node
    
    ; Expect '{'
    call parser_expect_token
    cmp rax, TOKEN_LBRACE
    jne .error
    
    ; Parse statements until '}'
.parse_loop:
    call parser_peek_token
    cmp rax, TOKEN_RBRACE
    je .done
    cmp rax, TOKEN_EOF
    je .error
    
    ; Parse statement
    call parser_parse_statement
    mov rdi, rbx
    mov rsi, rax
    call ast_add_child
    
    jmp .parse_loop

.done:
    call parser_advance_token  ; Skip '}'
    mov rax, rbx
    jmp .return

.error:
    mov rax, 0

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Parse a statement
; Output: rax = statement AST node
parser_parse_statement:
    push rbx
    push rcx
    push rdx
    
    call parser_peek_token
    mov rbx, rax  ; Save token type
    
    ; Determine statement type
    cmp rbx, TOKEN_TEL
    je .parse_assignment
    cmp rbx, TOKEN_TER
    je .parse_return
    cmp rbx, TOKEN_FI
    je .parse_if
    cmp rbx, TOKEN_POOL
    je .parse_loop
    cmp rbx, TOKEN_ROF
    je .parse_for
    cmp rbx, TOKEN_ELIHW
    je .parse_while
    
    ; Expression statement
    call parser_parse_expression
    jmp .return

.parse_assignment:
    call parser_parse_assignment
    jmp .return

.parse_return:
    call parser_parse_return
    jmp .return

.parse_if:
    call parser_parse_if
    jmp .return

.parse_loop:
    call parser_parse_loop
    jmp .return

.parse_for:
    call parser_parse_for
    jmp .return

.parse_while:
    call parser_parse_while
    jmp .return

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Parse an expression
; Output: rax = expression AST node
parser_parse_expression:
    push rbx
    push rcx
    push rdx
    
    ; Parse primary expression
    call parser_parse_primary
    mov rbx, rax  ; Save primary expression
    
    ; Parse binary operators
    call parser_parse_binary_ops
    mov rax, rbx
    jmp .return

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Parse primary expression
; Output: rax = primary expression AST node
parser_parse_primary:
    push rbx
    push rcx
    push rdx
    
    call parser_peek_token
    mov rbx, rax  ; Save token type
    
    ; Determine primary type
    cmp rbx, TOKEN_IDENTIFIER
    je .parse_identifier
    cmp rbx, TOKEN_LITERAL_INT
    je .parse_literal
    cmp rbx, TOKEN_LITERAL_STRING
    je .parse_literal
    cmp rbx, TOKEN_LITERAL_REAL
    je .parse_literal
    cmp rbx, TOKEN_EURT
    je .parse_literal
    cmp rbx, TOKEN_ESLAF
    je .parse_literal
    cmp rbx, TOKEN_LPAREN
    je .parse_paren_expr
    
    ; Error
    call parser_error
    mov rax, 0
    jmp .return

.parse_identifier:
    call parser_parse_identifier
    jmp .return

.parse_literal:
    call parser_parse_literal
    jmp .return

.parse_paren_expr:
    call parser_advance_token  ; Skip '('
    call parser_parse_expression
    call parser_expect_token
    cmp rax, TOKEN_RPAREN
    jne .error
    jmp .return

.error:
    mov rax, 0

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Parse identifier
; Output: rax = identifier AST node
parser_parse_identifier:
    push rbx
    push rcx
    push rdx
    
    ; Create identifier node
    mov rdi, AST_IDENTIFIER
    call ast_create_node
    mov rbx, rax
    
    ; Get token value
    call lexer_get_next_token
    mov rdi, rbx
    mov rsi, rdx  ; Token value
    mov rdx, rcx  ; Token length
    call ast_set_value
    
    mov rax, rbx
    jmp .return

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Parse literal
; Output: rax = literal AST node
parser_parse_literal:
    push rbx
    push rcx
    push rdx
    
    ; Create literal node
    mov rdi, AST_LITERAL
    call ast_create_node
    mov rbx, rax
    
    ; Get token value
    call lexer_get_next_token
    mov rdi, rbx
    mov rsi, rdx  ; Token value
    mov rdx, rcx  ; Token length
    call ast_set_value
    
    mov rax, rbx
    jmp .return

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Parse binary operators
; Input: rdi = left expression
; Output: rax = expression AST node
parser_parse_binary_ops:
    push rbx
    push rcx
    push rdx
    
    mov rbx, rdi  ; Save left expression
    
.parse_loop:
    call parser_peek_token
    mov rcx, rax  ; Save token type
    
    ; Check if it's a binary operator
    cmp rcx, TOKEN_PLUS
    je .parse_binary
    cmp rcx, TOKEN_MINUS
    je .parse_binary
    cmp rcx, TOKEN_MULTIPLY
    je .parse_binary
    cmp rcx, TOKEN_DIVIDE
    je .parse_binary
    cmp rcx, TOKEN_EQ
    je .parse_binary
    cmp rcx, TOKEN_GT
    je .parse_binary
    cmp rcx, TOKEN_LT
    je .parse_binary
    cmp rcx, TOKEN_GE
    je .parse_binary
    cmp rcx, TOKEN_LE
    je .parse_binary
    cmp rcx, TOKEN_NE
    je .parse_binary
    cmp rcx, TOKEN_EQEQ
    je .parse_binary
    
    ; Not a binary operator, return left expression
    mov rax, rbx
    jmp .return

.parse_binary:
    ; Create binary operation node
    mov rdi, AST_BINARY_OP
    call ast_create_node
    mov rdx, rax  ; Save binary node
    
    ; Set operator
    mov rdi, rdx
    mov rsi, rcx
    call ast_set_type
    
    ; Add left expression
    mov rdi, rdx
    mov rsi, rbx
    call ast_add_child
    
    ; Parse right expression
    call parser_advance_token
    call parser_parse_primary
    mov rdi, rdx
    mov rsi, rax
    call ast_add_child
    
    ; Continue with this as left expression
    mov rbx, rdx
    jmp .parse_loop

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Expect a specific token
; Input: rdi = expected token type
; Output: rax = success (1) or failure (0)
parser_expect_token:
    push rbx
    push rcx
    
    call lexer_peek_token
    mov rbx, rax  ; Get current token
    mov rcx, rdi  ; Get expected token
    
    cmp rbx, rcx
    je .success
    
    ; Token mismatch
    call parser_error
    mov rax, 0
    jmp .return

.success:
    mov rax, 1

.return:
    pop rcx
    pop rbx
    ret

; Peek at next token
; Output: rax = token type
parser_peek_token:
    call lexer_peek_token
    ret

; Advance to next token
parser_advance_token:
    call lexer_get_next_token
    ret

; Handle parser error
parser_error:
    push rbx
    push rcx
    push rdx
    
    ; Set error message
    mov rdi, error_syntax_error
    mov rsi, 13
    call ast_create_string
    mov [error_message], rax
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Additional parsing functions (simplified implementations)
parser_parse_parameters:
    ; Simplified parameter parsing
    mov rdi, AST_BLOCK
    call ast_create_node
    ret

parser_parse_fields:
    ; Simplified field parsing
    mov rdi, AST_BLOCK
    call ast_create_node
    ret

parser_parse_type:
    ; Simplified type parsing
    call parser_parse_identifier
    ret

parser_parse_assignment:
    ; Simplified assignment parsing
    mov rdi, AST_ASSIGNMENT
    call ast_create_node
    ret

parser_parse_return:
    ; Simplified return parsing
    mov rdi, AST_RETURN
    call ast_create_node
    ret

parser_parse_if:
    ; Simplified if parsing
    mov rdi, AST_IF
    call ast_create_node
    ret

parser_parse_loop:
    ; Simplified loop parsing
    mov rdi, AST_LOOP
    call ast_create_node
    ret

parser_parse_for:
    ; Simplified for parsing
    mov rdi, AST_FOR
    call ast_create_node
    ret

parser_parse_while:
    ; Simplified while parsing
    mov rdi, AST_WHILE
    call ast_create_node
    ret
