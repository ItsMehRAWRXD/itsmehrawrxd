; eon_assembly_lexer.asm
; Complete lexer implementation in x86-64 assembly for the Eon language
; Handles all Eon language tokens and keywords

section .data
    ; === Eon Keywords ===
    keyword_def         db "def", 0
    keyword_model       db "model", 0
    keyword_func        db "func", 0
    keyword_loop        db "loop", 0
    keyword_if          db "if", 0
    keyword_else        db "else", 0
    keyword_let         db "let", 0
    keyword_const       db "const", 0
    keyword_ret         db "ret", 0
    keyword_break       db "break", 0
    keyword_continue    db "continue", 0
    keyword_import      db "import", 0
    keyword_export      db "export", 0
    keyword_match       db "match", 0
    keyword_case        db "case", 0
    keyword_default     db "default", 0
    keyword_try         db "try", 0
    keyword_catch       db "catch", 0
    keyword_finally     db "finally", 0
    keyword_throw       db "throw", 0
    keyword_int         db "int", 0
    keyword_float       db "float", 0
    keyword_bool        db "bool", 0
    keyword_void        db "void", 0
    keyword_auto        db "auto", 0
    keyword_alloc       db "alloc", 0
    keyword_free        db "free", 0
    keyword_sizeof      db "sizeof", 0
    keyword_spawn       db "spawn", 0
    keyword_shared      db "shared", 0
    keyword_mutex       db "mutex", 0
    keyword_lock        db "lock", 0
    keyword_unlock      db "unlock", 0
    
    ; === Token Types ===
    TOKEN_EOF           equ 0
    TOKEN_IDENTIFIER    equ 1
    TOKEN_NUMBER        equ 2
    TOKEN_STRING        equ 3
    TOKEN_CHAR          equ 4
    TOKEN_DEF           equ 5
    TOKEN_MODEL         equ 6
    TOKEN_FUNC          equ 7
    TOKEN_LOOP          equ 8
    TOKEN_IF            equ 9
    TOKEN_ELSE          equ 10
    TOKEN_LET           equ 11
    TOKEN_CONST         equ 12
    TOKEN_RET           equ 13
    TOKEN_BREAK         equ 14
    TOKEN_CONTINUE      equ 15
    TOKEN_IMPORT        equ 16
    TOKEN_EXPORT        equ 17
    TOKEN_MATCH         equ 18
    TOKEN_CASE          equ 19
    TOKEN_DEFAULT       equ 20
    TOKEN_TRY           equ 21
    TOKEN_CATCH         equ 22
    TOKEN_FINALLY       equ 23
    TOKEN_THROW         equ 24
    TOKEN_INT           equ 25
    TOKEN_FLOAT         equ 26
    TOKEN_BOOL          equ 27
    TOKEN_VOID          equ 28
    TOKEN_AUTO          equ 29
    TOKEN_ALLOC         equ 30
    TOKEN_FREE          equ 31
    TOKEN_SIZEOF        equ 32
    TOKEN_SPAWN         equ 33
    TOKEN_SHARED        equ 34
    TOKEN_MUTEX         equ 35
    TOKEN_LOCK          equ 36
    TOKEN_UNLOCK        equ 37
    TOKEN_PLUS          equ 38
    TOKEN_MINUS         equ 39
    TOKEN_MULTIPLY      equ 40
    TOKEN_DIVIDE        equ 41
    TOKEN_MODULO        equ 42
    TOKEN_POWER         equ 43
    TOKEN_ASSIGN        equ 44
    TOKEN_PLUS_ASSIGN   equ 45
    TOKEN_MINUS_ASSIGN  equ 46
    TOKEN_MULTIPLY_ASSIGN equ 47
    TOKEN_DIVIDE_ASSIGN equ 48
    TOKEN_EQUALS        equ 49
    TOKEN_NOT_EQUALS    equ 50
    TOKEN_GREATER       equ 51
    TOKEN_GREATER_EQUAL equ 52
    TOKEN_LESS          equ 53
    TOKEN_LESS_EQUAL    equ 54
    TOKEN_LOGICAL_AND   equ 55
    TOKEN_LOGICAL_OR    equ 56
    TOKEN_LOGICAL_NOT   equ 57
    TOKEN_BITWISE_AND   equ 58
    TOKEN_BITWISE_OR    equ 59
    TOKEN_BITWISE_XOR   equ 60
    TOKEN_BITWISE_NOT   equ 61
    TOKEN_LEFT_SHIFT    equ 62
    TOKEN_RIGHT_SHIFT   equ 63
    TOKEN_LPAREN        equ 64
    TOKEN_RPAREN        equ 65
    TOKEN_LBRACE        equ 66
    TOKEN_RBRACE        equ 67
    TOKEN_LBRACKET      equ 68
    TOKEN_RBRACKET      equ 69
    TOKEN_SEMICOLON     equ 70
    TOKEN_COMMA         equ 71
    TOKEN_DOT           equ 72
    TOKEN_COLON         equ 73
    TOKEN_DOUBLE_COLON  equ 74
    TOKEN_ARROW         equ 75
    TOKEN_FAT_ARROW     equ 76
    TOKEN_QUESTION      equ 77
    TOKEN_AMPERSAND     equ 78
    TOKEN_STAR          equ 79
    TOKEN_NEWLINE       equ 80
    TOKEN_INDENT        equ 81
    TOKEN_DEDENT        equ 82
    
    ; === Lexer State ===
    lexer_source        resq 1       ; Pointer to source code
    lexer_position      resq 1       ; Current position in source
    lexer_length        resq 1       ; Length of source code
    lexer_line          resq 1       ; Current line number
    lexer_column        resq 1       ; Current column number
    lexer_start         resq 1       ; Start of current token
    
    ; === Token Buffer ===
    token_value         resb 256     ; Token value buffer
    token_type          resq 1       ; Token type
    token_line          resq 1       ; Token line number
    token_column        resq 1       ; Token column number
    
    ; === Character Classification ===
    whitespace_chars    db " \t\r", 0
    digit_chars         db "0123456789", 0
    alpha_chars         db "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_", 0
    alnum_chars         db "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789", 0

section .text
    global lexer_init_with_source
    global lexer_next_token
    global lexer_get_current_token
    global lexer_peek_token
    global lexer_skip_whitespace
    global lexer_is_whitespace
    global lexer_is_digit
    global lexer_is_alpha
    global lexer_is_alnum
    global lexer_match_keyword

; === Initialize Lexer with Source ===
lexer_init_with_source:
    push rbp
    mov rbp, rsp
    
    ; Store source information
    mov [lexer_source], rdi
    mov [lexer_length], rsi
    mov qword [lexer_position], 0
    mov qword [lexer_line], 1
    mov qword [lexer_column], 1
    mov qword [lexer_start], 0
    
    leave
    ret

; === Get Next Token ===
lexer_next_token:
    push rbp
    mov rbp, rsp
    
    ; Skip whitespace
    call lexer_skip_whitespace
    
    ; Check for end of file
    mov rax, [lexer_position]
    cmp rax, [lexer_length]
    jge .eof_token
    
    ; Get current character
    mov rdi, [lexer_source]
    add rdi, [lexer_position]
    mov al, [rdi]
    
    ; Store token start position
    mov rax, [lexer_position]
    mov [lexer_start], rax
    mov rax, [lexer_line]
    mov [token_line], rax
    mov rax, [lexer_column]
    mov [token_column], rax
    
    ; Classify character and tokenize
    cmp al, '"'
    je .string_token
    
    cmp al, '''
    je .char_token
    
    cmp al, '0'
    jl .check_alpha
    cmp al, '9'
    jle .number_token
    
.check_alpha:
    call lexer_is_alpha
    cmp rax, 1
    je .identifier_or_keyword
    
    ; Check for operators and punctuation
    cmp al, '+'
    je .plus_token
    
    cmp al, '-'
    je .minus_token
    
    cmp al, '*'
    je .multiply_token
    
    cmp al, '/'
    je .divide_token
    
    cmp al, '%'
    je .modulo_token
    
    cmp al, '^'
    je .power_token
    
    cmp al, '='
    je .assign_token
    
    cmp al, '!'
    je .not_token
    
    cmp al, '>'
    je .greater_token
    
    cmp al, '<'
    je .less_token
    
    cmp al, '&'
    je .ampersand_token
    
    cmp al, '|'
    je .pipe_token
    
    cmp al, '~'
    je .bitwise_not_token
    
    cmp al, '('
    je .lparen_token
    
    cmp al, ')'
    je .rparen_token
    
    cmp al, '{'
    je .lbrace_token
    
    cmp al, '}'
    je .rbrace_token
    
    cmp al, '['
    je .lbracket_token
    
    cmp al, ']'
    je .rbracket_token
    
    cmp al, ';'
    je .semicolon_token
    
    cmp al, ','
    je .comma_token
    
    cmp al, '.'
    je .dot_token
    
    cmp al, ':'
    je .colon_token
    
    cmp al, '?'
    je .question_token
    
    cmp al, '\n'
    je .newline_token
    
    ; Unknown character
    jmp .error_token
    
.string_token:
    call lexer_scan_string
    jmp .done
    
.char_token:
    call lexer_scan_char
    jmp .done
    
.number_token:
    call lexer_scan_number
    jmp .done
    
.identifier_or_keyword:
    call lexer_scan_identifier
    call lexer_match_keyword
    jmp .done
    
.plus_token:
    call lexer_scan_plus
    jmp .done
    
.minus_token:
    call lexer_scan_minus
    jmp .done
    
.multiply_token:
    call lexer_scan_multiply
    jmp .done
    
.divide_token:
    call lexer_scan_divide
    jmp .done
    
.modulo_token:
    mov qword [token_type], TOKEN_MODULO
    call lexer_advance
    jmp .done
    
.power_token:
    mov qword [token_type], TOKEN_POWER
    call lexer_advance
    jmp .done
    
.assign_token:
    call lexer_scan_assign
    jmp .done
    
.not_token:
    call lexer_scan_not
    jmp .done
    
.greater_token:
    call lexer_scan_greater
    jmp .done
    
.less_token:
    call lexer_scan_less
    jmp .done
    
.ampersand_token:
    call lexer_scan_ampersand
    jmp .done
    
.pipe_token:
    call lexer_scan_pipe
    jmp .done
    
.bitwise_not_token:
    mov qword [token_type], TOKEN_BITWISE_NOT
    call lexer_advance
    jmp .done
    
.lparen_token:
    mov qword [token_type], TOKEN_LPAREN
    call lexer_advance
    jmp .done
    
.rparen_token:
    mov qword [token_type], TOKEN_RPAREN
    call lexer_advance
    jmp .done
    
.lbrace_token:
    mov qword [token_type], TOKEN_LBRACE
    call lexer_advance
    jmp .done
    
.rbrace_token:
    mov qword [token_type], TOKEN_RBRACE
    call lexer_advance
    jmp .done
    
.lbracket_token:
    mov qword [token_type], TOKEN_LBRACKET
    call lexer_advance
    jmp .done
    
.rbracket_token:
    mov qword [token_type], TOKEN_RBRACKET
    call lexer_advance
    jmp .done
    
.semicolon_token:
    mov qword [token_type], TOKEN_SEMICOLON
    call lexer_advance
    jmp .done
    
.comma_token:
    mov qword [token_type], TOKEN_COMMA
    call lexer_advance
    jmp .done
    
.dot_token:
    mov qword [token_type], TOKEN_DOT
    call lexer_advance
    jmp .done
    
.colon_token:
    call lexer_scan_colon
    jmp .done
    
.question_token:
    mov qword [token_type], TOKEN_QUESTION
    call lexer_advance
    jmp .done
    
.newline_token:
    mov qword [token_type], TOKEN_NEWLINE
    call lexer_advance
    jmp .done
    
.eof_token:
    mov qword [token_type], TOKEN_EOF
    jmp .done
    
.error_token:
    mov qword [token_type], -1  ; Error token
    jmp .done
    
.done:
    leave
    ret

; === Scan String Literal ===
lexer_scan_string:
    push rbp
    mov rbp, rsp
    
    mov qword [token_type], TOKEN_STRING
    call lexer_advance  ; Skip opening quote
    
    ; Copy string content
    mov rdi, token_value
    mov rsi, [lexer_source]
    add rsi, [lexer_position]
    mov rcx, 0
    
.string_loop:
    mov al, [rsi]
    cmp al, '"'
    je .string_end
    cmp al, '\'
    je .escape_char
    cmp al, 0
    je .string_error
    
    mov [rdi], al
    inc rdi
    inc rsi
    inc rcx
    inc qword [lexer_position]
    inc qword [lexer_column]
    jmp .string_loop
    
.escape_char:
    inc rsi
    inc qword [lexer_position]
    inc qword [lexer_column]
    mov al, [rsi]
    cmp al, 'n'
    je .escape_newline
    cmp al, 't'
    je .escape_tab
    cmp al, 'r'
    je .escape_carriage
    cmp al, '\\'
    je .escape_backslash
    cmp al, '"'
    je .escape_quote
    
    ; Unknown escape sequence
    jmp .string_error
    
.escape_newline:
    mov byte [rdi], 10
    jmp .escape_done
    
.escape_tab:
    mov byte [rdi], 9
    jmp .escape_done
    
.escape_carriage:
    mov byte [rdi], 13
    jmp .escape_done
    
.escape_backslash:
    mov byte [rdi], '\'
    jmp .escape_done
    
.escape_quote:
    mov byte [rdi], '"'
    jmp .escape_done
    
.escape_done:
    inc rdi
    inc rsi
    inc rcx
    inc qword [lexer_position]
    inc qword [lexer_column]
    jmp .string_loop
    
.string_end:
    mov byte [rdi], 0
    call lexer_advance  ; Skip closing quote
    leave
    ret
    
.string_error:
    mov qword [token_type], -1  ; Error
    leave
    ret

; === Scan Character Literal ===
lexer_scan_char:
    push rbp
    mov rbp, rsp
    
    mov qword [token_type], TOKEN_CHAR
    call lexer_advance  ; Skip opening quote
    
    ; Get character
    mov rdi, [lexer_source]
    add rdi, [lexer_position]
    mov al, [rdi]
    
    cmp al, '\'
    je .char_escape
    
    mov [token_value], al
    call lexer_advance
    jmp .char_end
    
.char_escape:
    call lexer_advance
    mov rdi, [lexer_source]
    add rdi, [lexer_position]
    mov al, [rdi]
    
    cmp al, 'n'
    je .char_newline
    cmp al, 't'
    je .char_tab
    cmp al, 'r'
    je .char_carriage
    cmp al, '\\'
    je .char_backslash
    cmp al, '''
    je .char_quote
    
    ; Unknown escape sequence
    jmp .char_error
    
.char_newline:
    mov byte [token_value], 10
    jmp .char_escape_done
    
.char_tab:
    mov byte [token_value], 9
    jmp .char_escape_done
    
.char_carriage:
    mov byte [token_value], 13
    jmp .char_escape_done
    
.char_backslash:
    mov byte [token_value], '\'
    jmp .char_escape_done
    
.char_quote:
    mov byte [token_value], '''
    jmp .char_escape_done
    
.char_escape_done:
    call lexer_advance
    jmp .char_end
    
.char_end:
    ; Check for closing quote
    mov rdi, [lexer_source]
    add rdi, [lexer_position]
    mov al, [rdi]
    cmp al, '''
    jne .char_error
    
    call lexer_advance  ; Skip closing quote
    leave
    ret
    
.char_error:
    mov qword [token_type], -1  ; Error
    leave
    ret

; === Scan Number ===
lexer_scan_number:
    push rbp
    mov rbp, rsp
    
    mov qword [token_type], TOKEN_NUMBER
    
    ; Copy number to token value
    mov rdi, token_value
    mov rsi, [lexer_source]
    add rsi, [lexer_position]
    mov rcx, 0
    
.number_loop:
    mov al, [rsi]
    call lexer_is_digit
    cmp rax, 1
    jne .check_dot
    
    mov [rdi], al
    inc rdi
    inc rsi
    inc rcx
    inc qword [lexer_position]
    inc qword [lexer_column]
    jmp .number_loop
    
.check_dot:
    cmp al, '.'
    jne .number_end
    
    ; Check if next character is a digit
    mov rbx, rsi
    inc rbx
    mov bl, [rbx]
    push rbx
    mov rdi, rbx
    call lexer_is_digit
    pop rbx
    cmp rax, 1
    jne .number_end
    
    ; It's a float
    mov [rdi], al
    inc rdi
    inc rsi
    inc rcx
    inc qword [lexer_position]
    inc qword [lexer_column]
    jmp .number_loop
    
.number_end:
    mov byte [rdi], 0
    leave
    ret

; === Scan Identifier ===
lexer_scan_identifier:
    push rbp
    mov rbp, rsp
    
    mov qword [token_type], TOKEN_IDENTIFIER
    
    ; Copy identifier to token value
    mov rdi, token_value
    mov rsi, [lexer_source]
    add rsi, [lexer_position]
    mov rcx, 0
    
.identifier_loop:
    mov al, [rsi]
    call lexer_is_alnum
    cmp rax, 1
    jne .identifier_end
    
    mov [rdi], al
    inc rdi
    inc rsi
    inc rcx
    inc qword [lexer_position]
    inc qword [lexer_column]
    jmp .identifier_loop
    
.identifier_end:
    mov byte [rdi], 0
    leave
    ret

; === Scan Plus Operator ===
lexer_scan_plus:
    push rbp
    mov rbp, rsp
    
    call lexer_advance
    
    ; Check for +=
    mov rdi, [lexer_source]
    add rdi, [lexer_position]
    mov al, [rdi]
    cmp al, '='
    jne .plus_done
    
    mov qword [token_type], TOKEN_PLUS_ASSIGN
    call lexer_advance
    jmp .plus_end
    
.plus_done:
    mov qword [token_type], TOKEN_PLUS
    
.plus_end:
    leave
    ret

; === Scan Minus Operator ===
lexer_scan_minus:
    push rbp
    mov rbp, rsp
    
    call lexer_advance
    
    ; Check for -= or ->
    mov rdi, [lexer_source]
    add rdi, [lexer_position]
    mov al, [rdi]
    cmp al, '='
    je .minus_assign
    cmp al, '>'
    je .arrow
    
    mov qword [token_type], TOKEN_MINUS
    jmp .minus_end
    
.minus_assign:
    mov qword [token_type], TOKEN_MINUS_ASSIGN
    call lexer_advance
    jmp .minus_end
    
.arrow:
    mov qword [token_type], TOKEN_ARROW
    call lexer_advance
    jmp .minus_end
    
.minus_end:
    leave
    ret

; === Scan Multiply Operator ===
lexer_scan_multiply:
    push rbp
    mov rbp, rsp
    
    call lexer_advance
    
    ; Check for *=
    mov rdi, [lexer_source]
    add rdi, [lexer_position]
    mov al, [rdi]
    cmp al, '='
    jne .multiply_done
    
    mov qword [token_type], TOKEN_MULTIPLY_ASSIGN
    call lexer_advance
    jmp .multiply_end
    
.multiply_done:
    mov qword [token_type], TOKEN_STAR
    
.multiply_end:
    leave
    ret

; === Scan Divide Operator ===
lexer_scan_divide:
    push rbp
    mov rbp, rsp
    
    call lexer_advance
    
    ; Check for /= or //
    mov rdi, [lexer_source]
    add rdi, [lexer_position]
    mov al, [rdi]
    cmp al, '='
    je .divide_assign
    cmp al, '/'
    je .comment
    
    mov qword [token_type], TOKEN_DIVIDE
    jmp .divide_end
    
.divide_assign:
    mov qword [token_type], TOKEN_DIVIDE_ASSIGN
    call lexer_advance
    jmp .divide_end
    
.comment:
    ; Skip single-line comment
    call lexer_skip_comment
    call lexer_next_token  ; Get next token
    jmp .divide_end
    
.divide_end:
    leave
    ret

; === Scan Assign Operator ===
lexer_scan_assign:
    push rbp
    mov rbp, rsp
    
    call lexer_advance
    
    ; Check for ==
    mov rdi, [lexer_source]
    add rdi, [lexer_position]
    mov al, [rdi]
    cmp al, '='
    jne .assign_done
    
    mov qword [token_type], TOKEN_EQUALS
    call lexer_advance
    jmp .assign_end
    
.assign_done:
    mov qword [token_type], TOKEN_ASSIGN
    
.assign_end:
    leave
    ret

; === Scan Not Operator ===
lexer_scan_not:
    push rbp
    mov rbp, rsp
    
    call lexer_advance
    
    ; Check for !=
    mov rdi, [lexer_source]
    add rdi, [lexer_position]
    mov al, [rdi]
    cmp al, '='
    jne .not_done
    
    mov qword [token_type], TOKEN_NOT_EQUALS
    call lexer_advance
    jmp .not_end
    
.not_done:
    mov qword [token_type], TOKEN_LOGICAL_NOT
    
.not_end:
    leave
    ret

; === Scan Greater Operator ===
lexer_scan_greater:
    push rbp
    mov rbp, rsp
    
    call lexer_advance
    
    ; Check for >= or >>
    mov rdi, [lexer_source]
    add rdi, [lexer_position]
    mov al, [rdi]
    cmp al, '='
    je .greater_equal
    cmp al, '>'
    je .right_shift
    
    mov qword [token_type], TOKEN_GREATER
    jmp .greater_end
    
.greater_equal:
    mov qword [token_type], TOKEN_GREATER_EQUAL
    call lexer_advance
    jmp .greater_end
    
.right_shift:
    mov qword [token_type], TOKEN_RIGHT_SHIFT
    call lexer_advance
    jmp .greater_end
    
.greater_end:
    leave
    ret

; === Scan Less Operator ===
lexer_scan_less:
    push rbp
    mov rbp, rsp
    
    call lexer_advance
    
    ; Check for <= or <<
    mov rdi, [lexer_source]
    add rdi, [lexer_position]
    mov al, [rdi]
    cmp al, '='
    je .less_equal
    cmp al, '<'
    je .left_shift
    
    mov qword [token_type], TOKEN_LESS
    jmp .less_end
    
.less_equal:
    mov qword [token_type], TOKEN_LESS_EQUAL
    call lexer_advance
    jmp .less_end
    
.left_shift:
    mov qword [token_type], TOKEN_LEFT_SHIFT
    call lexer_advance
    jmp .less_end
    
.less_end:
    leave
    ret

; === Scan Ampersand Operator ===
lexer_scan_ampersand:
    push rbp
    mov rbp, rsp
    
    call lexer_advance
    
    ; Check for &&
    mov rdi, [lexer_source]
    add rdi, [lexer_position]
    mov al, [rdi]
    cmp al, '&'
    jne .ampersand_done
    
    mov qword [token_type], TOKEN_LOGICAL_AND
    call lexer_advance
    jmp .ampersand_end
    
.ampersand_done:
    mov qword [token_type], TOKEN_AMPERSAND
    
.ampersand_end:
    leave
    ret

; === Scan Pipe Operator ===
lexer_scan_pipe:
    push rbp
    mov rbp, rsp
    
    call lexer_advance
    
    ; Check for ||
    mov rdi, [lexer_source]
    add rdi, [lexer_position]
    mov al, [rdi]
    cmp al, '|'
    jne .pipe_done
    
    mov qword [token_type], TOKEN_LOGICAL_OR
    call lexer_advance
    jmp .pipe_end
    
.pipe_done:
    mov qword [token_type], TOKEN_BITWISE_OR
    
.pipe_end:
    leave
    ret

; === Scan Colon Operator ===
lexer_scan_colon:
    push rbp
    mov rbp, rsp
    
    call lexer_advance
    
    ; Check for ::
    mov rdi, [lexer_source]
    add rdi, [lexer_position]
    mov al, [rdi]
    cmp al, ':'
    jne .colon_done
    
    mov qword [token_type], TOKEN_DOUBLE_COLON
    call lexer_advance
    jmp .colon_end
    
.colon_done:
    mov qword [token_type], TOKEN_COLON
    
.colon_end:
    leave
    ret

; === Utility Functions ===

; Skip whitespace
lexer_skip_whitespace:
    push rbp
    mov rbp, rsp
    
.whitespace_loop:
    mov rax, [lexer_position]
    cmp rax, [lexer_length]
    jge .whitespace_done
    
    mov rdi, [lexer_source]
    add rdi, [lexer_position]
    mov al, [rdi]
    
    call lexer_is_whitespace
    cmp rax, 1
    jne .whitespace_done
    
    cmp al, '\n'
    jne .not_newline
    
    inc qword [lexer_line]
    mov qword [lexer_column], 1
    jmp .advance
    
.not_newline:
    inc qword [lexer_column]
    
.advance:
    inc qword [lexer_position]
    jmp .whitespace_loop
    
.whitespace_done:
    leave
    ret

; Skip comment
lexer_skip_comment:
    push rbp
    mov rbp, rsp
    
.comment_loop:
    mov rax, [lexer_position]
    cmp rax, [lexer_length]
    jge .comment_done
    
    mov rdi, [lexer_source]
    add rdi, [lexer_position]
    mov al, [rdi]
    
    cmp al, '\n'
    je .comment_done
    
    inc qword [lexer_position]
    inc qword [lexer_column]
    jmp .comment_loop
    
.comment_done:
    leave
    ret

; Advance position
lexer_advance:
    inc qword [lexer_position]
    inc qword [lexer_column]
    ret

; Check if character is whitespace
lexer_is_whitespace:
    push rbp
    mov rbp, rsp
    
    cmp dil, ' '
    je .is_whitespace
    cmp dil, '\t'
    je .is_whitespace
    cmp dil, '\r'
    je .is_whitespace
    cmp dil, '\n'
    je .is_whitespace
    
    mov rax, 0
    jmp .whitespace_done
    
.is_whitespace:
    mov rax, 1
    
.whitespace_done:
    leave
    ret

; Check if character is digit
lexer_is_digit:
    push rbp
    mov rbp, rsp
    
    cmp dil, '0'
    jl .not_digit
    cmp dil, '9'
    jg .not_digit
    
    mov rax, 1
    jmp .digit_done
    
.not_digit:
    mov rax, 0
    
.digit_done:
    leave
    ret

; Check if character is alpha
lexer_is_alpha:
    push rbp
    mov rbp, rsp
    
    cmp dil, 'a'
    jl .check_upper
    cmp dil, 'z'
    jle .is_alpha
    
.check_upper:
    cmp dil, 'A'
    jl .check_underscore
    cmp dil, 'Z'
    jle .is_alpha
    
.check_underscore:
    cmp dil, '_'
    je .is_alpha
    
    mov rax, 0
    jmp .alpha_done
    
.is_alpha:
    mov rax, 1
    
.alpha_done:
    leave
    ret

; Check if character is alphanumeric
lexer_is_alnum:
    push rbp
    mov rbp, rsp
    
    call lexer_is_alpha
    cmp rax, 1
    je .is_alnum
    
    call lexer_is_digit
    cmp rax, 1
    je .is_alnum
    
    mov rax, 0
    jmp .alnum_done
    
.is_alnum:
    mov rax, 1
    
.alnum_done:
    leave
    ret

; Match keyword
lexer_match_keyword:
    push rbp
    mov rbp, rsp
    
    ; Compare token value with keywords
    mov rdi, token_value
    mov rsi, keyword_def
    call string_compare
    cmp rax, 0
    je .match_def
    
    mov rdi, token_value
    mov rsi, keyword_model
    call string_compare
    cmp rax, 0
    je .match_model
    
    mov rdi, token_value
    mov rsi, keyword_func
    call string_compare
    cmp rax, 0
    je .match_func
    
    mov rdi, token_value
    mov rsi, keyword_loop
    call string_compare
    cmp rax, 0
    je .match_loop
    
    mov rdi, token_value
    mov rsi, keyword_if
    call string_compare
    cmp rax, 0
    je .match_if
    
    mov rdi, token_value
    mov rsi, keyword_else
    call string_compare
    cmp rax, 0
    je .match_else
    
    mov rdi, token_value
    mov rsi, keyword_let
    call string_compare
    cmp rax, 0
    je .match_let
    
    mov rdi, token_value
    mov rsi, keyword_const
    call string_compare
    cmp rax, 0
    je .match_const
    
    mov rdi, token_value
    mov rsi, keyword_ret
    call string_compare
    cmp rax, 0
    je .match_ret
    
    mov rdi, token_value
    mov rsi, keyword_break
    call string_compare
    cmp rax, 0
    je .match_break
    
    mov rdi, token_value
    mov rsi, keyword_continue
    call string_compare
    cmp rax, 0
    je .match_continue
    
    mov rdi, token_value
    mov rsi, keyword_import
    call string_compare
    cmp rax, 0
    je .match_import
    
    mov rdi, token_value
    mov rsi, keyword_export
    call string_compare
    cmp rax, 0
    je .match_export
    
    mov rdi, token_value
    mov rsi, keyword_match
    call string_compare
    cmp rax, 0
    je .match_match
    
    mov rdi, token_value
    mov rsi, keyword_case
    call string_compare
    cmp rax, 0
    je .match_case
    
    mov rdi, token_value
    mov rsi, keyword_default
    call string_compare
    cmp rax, 0
    je .match_default
    
    mov rdi, token_value
    mov rsi, keyword_try
    call string_compare
    cmp rax, 0
    je .match_try
    
    mov rdi, token_value
    mov rsi, keyword_catch
    call string_compare
    cmp rax, 0
    je .match_catch
    
    mov rdi, token_value
    mov rsi, keyword_finally
    call string_compare
    cmp rax, 0
    je .match_finally
    
    mov rdi, token_value
    mov rsi, keyword_throw
    call string_compare
    cmp rax, 0
    je .match_throw
    
    mov rdi, token_value
    mov rsi, keyword_int
    call string_compare
    cmp rax, 0
    je .match_int
    
    mov rdi, token_value
    mov rsi, keyword_float
    call string_compare
    cmp rax, 0
    je .match_float
    
    mov rdi, token_value
    mov rsi, keyword_bool
    call string_compare
    cmp rax, 0
    je .match_bool
    
    mov rdi, token_value
    mov rsi, keyword_void
    call string_compare
    cmp rax, 0
    je .match_void
    
    mov rdi, token_value
    mov rsi, keyword_auto
    call string_compare
    cmp rax, 0
    je .match_auto
    
    mov rdi, token_value
    mov rsi, keyword_alloc
    call string_compare
    cmp rax, 0
    je .match_alloc
    
    mov rdi, token_value
    mov rsi, keyword_free
    call string_compare
    cmp rax, 0
    je .match_free
    
    mov rdi, token_value
    mov rsi, keyword_sizeof
    call string_compare
    cmp rax, 0
    je .match_sizeof
    
    mov rdi, token_value
    mov rsi, keyword_spawn
    call string_compare
    cmp rax, 0
    je .match_spawn
    
    mov rdi, token_value
    mov rsi, keyword_shared
    call string_compare
    cmp rax, 0
    je .match_shared
    
    mov rdi, token_value
    mov rsi, keyword_mutex
    call string_compare
    cmp rax, 0
    je .match_mutex
    
    mov rdi, token_value
    mov rsi, keyword_lock
    call string_compare
    cmp rax, 0
    je .match_lock
    
    mov rdi, token_value
    mov rsi, keyword_unlock
    call string_compare
    cmp rax, 0
    je .match_unlock
    
    ; No keyword match, keep as identifier
    jmp .keyword_done
    
.match_def:
    mov qword [token_type], TOKEN_DEF
    jmp .keyword_done
    
.match_model:
    mov qword [token_type], TOKEN_MODEL
    jmp .keyword_done
    
.match_func:
    mov qword [token_type], TOKEN_FUNC
    jmp .keyword_done
    
.match_loop:
    mov qword [token_type], TOKEN_LOOP
    jmp .keyword_done
    
.match_if:
    mov qword [token_type], TOKEN_IF
    jmp .keyword_done
    
.match_else:
    mov qword [token_type], TOKEN_ELSE
    jmp .keyword_done
    
.match_let:
    mov qword [token_type], TOKEN_LET
    jmp .keyword_done
    
.match_const:
    mov qword [token_type], TOKEN_CONST
    jmp .keyword_done
    
.match_ret:
    mov qword [token_type], TOKEN_RET
    jmp .keyword_done
    
.match_break:
    mov qword [token_type], TOKEN_BREAK
    jmp .keyword_done
    
.match_continue:
    mov qword [token_type], TOKEN_CONTINUE
    jmp .keyword_done
    
.match_import:
    mov qword [token_type], TOKEN_IMPORT
    jmp .keyword_done
    
.match_export:
    mov qword [token_type], TOKEN_EXPORT
    jmp .keyword_done
    
.match_match:
    mov qword [token_type], TOKEN_MATCH
    jmp .keyword_done
    
.match_case:
    mov qword [token_type], TOKEN_CASE
    jmp .keyword_done
    
.match_default:
    mov qword [token_type], TOKEN_DEFAULT
    jmp .keyword_done
    
.match_try:
    mov qword [token_type], TOKEN_TRY
    jmp .keyword_done
    
.match_catch:
    mov qword [token_type], TOKEN_CATCH
    jmp .keyword_done
    
.match_finally:
    mov qword [token_type], TOKEN_FINALLY
    jmp .keyword_done
    
.match_throw:
    mov qword [token_type], TOKEN_THROW
    jmp .keyword_done
    
.match_int:
    mov qword [token_type], TOKEN_INT
    jmp .keyword_done
    
.match_float:
    mov qword [token_type], TOKEN_FLOAT
    jmp .keyword_done
    
.match_bool:
    mov qword [token_type], TOKEN_BOOL
    jmp .keyword_done
    
.match_void:
    mov qword [token_type], TOKEN_VOID
    jmp .keyword_done
    
.match_auto:
    mov qword [token_type], TOKEN_AUTO
    jmp .keyword_done
    
.match_alloc:
    mov qword [token_type], TOKEN_ALLOC
    jmp .keyword_done
    
.match_free:
    mov qword [token_type], TOKEN_FREE
    jmp .keyword_done
    
.match_sizeof:
    mov qword [token_type], TOKEN_SIZEOF
    jmp .keyword_done
    
.match_spawn:
    mov qword [token_type], TOKEN_SPAWN
    jmp .keyword_done
    
.match_shared:
    mov qword [token_type], TOKEN_SHARED
    jmp .keyword_done
    
.match_mutex:
    mov qword [token_type], TOKEN_MUTEX
    jmp .keyword_done
    
.match_lock:
    mov qword [token_type], TOKEN_LOCK
    jmp .keyword_done
    
.match_unlock:
    mov qword [token_type], TOKEN_UNLOCK
    jmp .keyword_done
    
.keyword_done:
    leave
    ret

; === String Comparison ===
string_compare:
    push rbp
    mov rbp, rsp
    push rbx
    
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
    jmp .compare_done
    
.not_equal:
    mov rax, 1
    
.compare_done:
    pop rbx
    leave
    ret

; === Get Current Token ===
lexer_get_current_token:
    mov rax, [token_type]
    ret

; === Peek Token ===
lexer_peek_token:
    push rbp
    mov rbp, rsp
    
    ; Save current state
    push qword [lexer_position]
    push qword [lexer_line]
    push qword [lexer_column]
    push qword [token_type]
    
    ; Get next token
    call lexer_next_token
    
    ; Save token type
    mov rbx, [token_type]
    
    ; Restore state
    pop qword [token_type]
    pop qword [lexer_column]
    pop qword [lexer_line]
    pop qword [lexer_position]
    
    ; Return peeked token type
    mov rax, rbx
    
    leave
    ret
