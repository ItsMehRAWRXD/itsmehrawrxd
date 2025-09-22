; eon_assembly_lexer.asm
; Complete lexer for the Eon language in x86-64 assembly
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

    ; === Token Type Constants ===
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
    lexer_current_char  resb 1       ; Current character

    ; === Token Buffer ===
    token_value         resb 256     ; Token value buffer
    token_type          resq 1       ; Token type
    token_line          resq 1       ; Token line
    token_column        resq 1       ; Token column

section .text
    global lexer_init
    global lexer_next_token
    global lexer_get_current_token
    global lexer_peek_token
    global lexer_skip_whitespace
    global lexer_is_keyword
    global lexer_is_identifier_start
    global lexer_is_identifier_char
    global lexer_is_digit
    global lexer_is_hex_digit
    global lexer_is_octal_digit
    global lexer_is_binary_digit

; === Initialize Lexer ===
; Args: rdi = source code pointer, rsi = source length
lexer_init:
    push rbp
    mov rbp, rsp
    
    mov [lexer_source], rdi
    mov [lexer_length], rsi
    mov qword [lexer_position], 0
    mov qword [lexer_line], 1
    mov qword [lexer_column], 1
    
    ; Load first character
    call lexer_load_current_char
    
    leave
    ret

; === Load Current Character ===
lexer_load_current_char:
    push rbp
    mov rbp, rsp
    
    mov rax, [lexer_position]
    cmp rax, [lexer_length]
    jge .eof
    
    mov rbx, [lexer_source]
    mov al, [rbx + rax]
    mov [lexer_current_char], al
    jmp .done
    
.eof:
    mov byte [lexer_current_char], 0
    
.done:
    leave
    ret

; === Get Next Token ===
lexer_next_token:
    push rbp
    mov rbp, rsp
    
    ; Skip whitespace
    call lexer_skip_whitespace
    
    ; Check for EOF
    mov al, [lexer_current_char]
    cmp al, 0
    je .eof_token
    
    ; Record token start position
    mov rax, [lexer_position]
    mov [lexer_start], rax
    mov rax, [lexer_line]
    mov [token_line], rax
    mov rax, [lexer_column]
    mov [token_column], rax
    
    ; Determine token type
    call lexer_identify_token
    
    leave
    ret
    
.eof_token:
    mov qword [token_type], TOKEN_EOF
    mov byte [token_value], 0
    leave
    ret

; === Skip Whitespace ===
lexer_skip_whitespace:
    push rbp
    mov rbp, rsp
    
.whitespace_loop:
    mov al, [lexer_current_char]
    
    ; Check for space or tab
    cmp al, ' '
    je .skip_char
    cmp al, 9              ; tab
    je .skip_char
    
    ; Check for newline
    cmp al, 10             ; newline
    je .newline
    cmp al, 13             ; carriage return
    je .newline
    
    ; Not whitespace
    jmp .done
    
.skip_char:
    call lexer_advance
    jmp .whitespace_loop
    
.newline:
    call lexer_advance
    inc qword [lexer_line]
    mov qword [lexer_column], 1
    jmp .whitespace_loop
    
.done:
    leave
    ret

; === Advance Position ===
lexer_advance:
    push rbp
    mov rbp, rsp
    
    inc qword [lexer_position]
    inc qword [lexer_column]
    call lexer_load_current_char
    
    leave
    ret

; === Identify Token Type ===
lexer_identify_token:
    push rbp
    mov rbp, rsp
    
    mov al, [lexer_current_char]
    
    ; Check for letters (identifiers/keywords)
    call lexer_is_identifier_start
    cmp rax, 1
    je .identifier_or_keyword
    
    ; Check for digits (numbers)
    call lexer_is_digit
    cmp rax, 1
    je .number
    
    ; Check for string literal
    cmp al, '"'
    je .string_literal
    
    ; Check for character literal
    cmp al, '''
    je .char_literal
    
    ; Check for operators and punctuation
    call lexer_identify_operator
    
    leave
    ret

; === Identifier or Keyword ===
.identifier_or_keyword:
    call lexer_read_identifier
    call lexer_is_keyword
    cmp rax, 0
    jne .keyword_found
    
    ; It's an identifier
    mov qword [token_type], TOKEN_IDENTIFIER
    jmp .done
    
.keyword_found:
    mov [token_type], rax
    jmp .done

; === Read Identifier ===
lexer_read_identifier:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    mov rbx, token_value
    mov rcx, 0
    
.identifier_loop:
    mov al, [lexer_current_char]
    call lexer_is_identifier_char
    cmp rax, 0
    je .identifier_done
    
    mov [rbx + rcx], al
    inc rcx
    call lexer_advance
    jmp .identifier_loop
    
.identifier_done:
    mov byte [rbx + rcx], 0
    
    pop rcx
    pop rbx
    leave
    ret

; === Number Token ===
.number:
    call lexer_read_number
    mov qword [token_type], TOKEN_NUMBER
    leave
    ret

; === Read Number ===
lexer_read_number:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    mov rbx, token_value
    mov rcx, 0
    
    ; Check for hex prefix
    mov al, [lexer_current_char]
    cmp al, '0'
    jne .decimal_number
    
    call lexer_advance
    mov al, [lexer_current_char]
    cmp al, 'x'
    je .hex_number
    cmp al, 'X'
    je .hex_number
    cmp al, 'b'
    je .binary_number
    cmp al, 'B'
    je .binary_number
    cmp al, 'o'
    je .octal_number
    cmp al, 'O'
    je .octal_number
    
    ; It's a decimal number starting with 0
    mov byte [rbx + rcx], '0'
    inc rcx
    jmp .decimal_loop
    
.hex_number:
    call lexer_advance  ; skip 'x'
    jmp .hex_loop
    
.hex_loop:
    mov al, [lexer_current_char]
    call lexer_is_hex_digit
    cmp rax, 0
    je .number_done
    
    mov [rbx + rcx], al
    inc rcx
    call lexer_advance
    jmp .hex_loop
    
.binary_number:
    call lexer_advance  ; skip 'b'
    jmp .binary_loop
    
.binary_loop:
    mov al, [lexer_current_char]
    call lexer_is_binary_digit
    cmp rax, 0
    je .number_done
    
    mov [rbx + rcx], al
    inc rcx
    call lexer_advance
    jmp .binary_loop
    
.octal_number:
    call lexer_advance  ; skip 'o'
    jmp .octal_loop
    
.octal_loop:
    mov al, [lexer_current_char]
    call lexer_is_octal_digit
    cmp rax, 0
    je .number_done
    
    mov [rbx + rcx], al
    inc rcx
    call lexer_advance
    jmp .octal_loop
    
.decimal_number:
    jmp .decimal_loop
    
.decimal_loop:
    mov al, [lexer_current_char]
    call lexer_is_digit
    cmp rax, 0
    je .check_float
    
    mov [rbx + rcx], al
    inc rcx
    call lexer_advance
    jmp .decimal_loop
    
.check_float:
    ; Check for decimal point
    cmp al, '.'
    jne .number_done
    
    mov [rbx + rcx], al
    inc rcx
    call lexer_advance
    
    ; Read fractional part
.float_loop:
    mov al, [lexer_current_char]
    call lexer_is_digit
    cmp rax, 0
    je .number_done
    
    mov [rbx + rcx], al
    inc rcx
    call lexer_advance
    jmp .float_loop
    
.number_done:
    mov byte [rbx + rcx], 0
    
    pop rcx
    pop rbx
    leave
    ret

; === String Literal ===
.string_literal:
    call lexer_read_string
    mov qword [token_type], TOKEN_STRING
    leave
    ret

; === Read String ===
lexer_read_string:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    mov rbx, token_value
    mov rcx, 0
    
    call lexer_advance  ; skip opening quote
    
.string_loop:
    mov al, [lexer_current_char]
    cmp al, 0
    je .string_error
    cmp al, '"'
    je .string_done
    cmp al, '\'
    je .escape_sequence
    
    mov [rbx + rcx], al
    inc rcx
    call lexer_advance
    jmp .string_loop
    
.escape_sequence:
    call lexer_advance  ; skip backslash
    mov al, [lexer_current_char]
    
    ; Handle escape sequences
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
    
    ; Default: just copy the character
    mov [rbx + rcx], al
    inc rcx
    call lexer_advance
    jmp .string_loop
    
.escape_newline:
    mov byte [rbx + rcx], 10
    inc rcx
    call lexer_advance
    jmp .string_loop
    
.escape_tab:
    mov byte [rbx + rcx], 9
    inc rcx
    call lexer_advance
    jmp .string_loop
    
.escape_carriage:
    mov byte [rbx + rcx], 13
    inc rcx
    call lexer_advance
    jmp .string_loop
    
.escape_backslash:
    mov byte [rbx + rcx], '\'
    inc rcx
    call lexer_advance
    jmp .string_loop
    
.escape_quote:
    mov byte [rbx + rcx], '"'
    inc rcx
    call lexer_advance
    jmp .string_loop
    
.string_done:
    call lexer_advance  ; skip closing quote
    mov byte [rbx + rcx], 0
    
    pop rcx
    pop rbx
    leave
    ret
    
.string_error:
    ; Handle string error
    pop rcx
    pop rbx
    leave
    ret

; === Character Literal ===
.char_literal:
    call lexer_read_char
    mov qword [token_type], TOKEN_CHAR
    leave
    ret

; === Read Character ===
lexer_read_char:
    push rbp
    mov rbp, rsp
    
    call lexer_advance  ; skip opening quote
    
    mov al, [lexer_current_char]
    mov [token_value], al
    
    call lexer_advance  ; skip character
    call lexer_advance  ; skip closing quote
    
    leave
    ret

; === Identify Operator ===
lexer_identify_operator:
    push rbp
    mov rbp, rsp
    
    mov al, [lexer_current_char]
    
    ; Single character operators
    cmp al, '+'
    je .plus
    cmp al, '-'
    je .minus
    cmp al, '*'
    je .multiply
    cmp al, '/'
    je .divide
    cmp al, '%'
    je .modulo
    cmp al, '^'
    je .power
    cmp al, '='
    je .assign_or_equals
    cmp al, '!'
    je .not_or_not_equals
    cmp al, '>'
    je .greater_or_shift
    cmp al, '<'
    je .less_or_shift
    cmp al, '&'
    je .and_or_bitwise_and
    cmp al, '|'
    je .or_or_bitwise_or
    cmp al, '~'
    je .bitwise_not
    cmp al, '('
    je .lparen
    cmp al, ')'
    je .rparen
    cmp al, '{'
    je .lbrace
    cmp al, '}'
    je .rbrace
    cmp al, '['
    je .lbracket
    cmp al, ']'
    je .rbracket
    cmp al, ';'
    je .semicolon
    cmp al, ','
    je .comma
    cmp al, '.'
    je .dot
    cmp al, ':'
    je .colon
    cmp al, '?'
    je .question
    
    ; Unknown character
    jmp .unknown
    
.plus:
    call lexer_advance
    mov al, [lexer_current_char]
    cmp al, '='
    je .plus_assign
    mov qword [token_type], TOKEN_PLUS
    jmp .done
    
.plus_assign:
    call lexer_advance
    mov qword [token_type], TOKEN_PLUS_ASSIGN
    jmp .done
    
.minus:
    call lexer_advance
    mov al, [lexer_current_char]
    cmp al, '='
    je .minus_assign
    cmp al, '>'
    je .arrow
    mov qword [token_type], TOKEN_MINUS
    jmp .done
    
.minus_assign:
    call lexer_advance
    mov qword [token_type], TOKEN_MINUS_ASSIGN
    jmp .done
    
.arrow:
    call lexer_advance
    mov qword [token_type], TOKEN_ARROW
    jmp .done
    
.multiply:
    call lexer_advance
    mov al, [lexer_current_char]
    cmp al, '='
    je .multiply_assign
    mov qword [token_type], TOKEN_MULTIPLY
    jmp .done
    
.multiply_assign:
    call lexer_advance
    mov qword [token_type], TOKEN_MULTIPLY_ASSIGN
    jmp .done
    
.divide:
    call lexer_advance
    mov al, [lexer_current_char]
    cmp al, '='
    je .divide_assign
    mov qword [token_type], TOKEN_DIVIDE
    jmp .done
    
.divide_assign:
    call lexer_advance
    mov qword [token_type], TOKEN_DIVIDE_ASSIGN
    jmp .done
    
.modulo:
    call lexer_advance
    mov qword [token_type], TOKEN_MODULO
    jmp .done
    
.power:
    call lexer_advance
    mov qword [token_type], TOKEN_POWER
    jmp .done
    
.assign_or_equals:
    call lexer_advance
    mov al, [lexer_current_char]
    cmp al, '='
    je .equals
    mov qword [token_type], TOKEN_ASSIGN
    jmp .done
    
.equals:
    call lexer_advance
    mov qword [token_type], TOKEN_EQUALS
    jmp .done
    
.not_or_not_equals:
    call lexer_advance
    mov al, [lexer_current_char]
    cmp al, '='
    je .not_equals
    mov qword [token_type], TOKEN_LOGICAL_NOT
    jmp .done
    
.not_equals:
    call lexer_advance
    mov qword [token_type], TOKEN_NOT_EQUALS
    jmp .done
    
.greater_or_shift:
    call lexer_advance
    mov al, [lexer_current_char]
    cmp al, '='
    je .greater_equal
    cmp al, '>'
    je .right_shift
    mov qword [token_type], TOKEN_GREATER
    jmp .done
    
.greater_equal:
    call lexer_advance
    mov qword [token_type], TOKEN_GREATER_EQUAL
    jmp .done
    
.right_shift:
    call lexer_advance
    mov qword [token_type], TOKEN_RIGHT_SHIFT
    jmp .done
    
.less_or_shift:
    call lexer_advance
    mov al, [lexer_current_char]
    cmp al, '='
    je .less_equal
    cmp al, '<'
    je .left_shift
    mov qword [token_type], TOKEN_LESS
    jmp .done
    
.less_equal:
    call lexer_advance
    mov qword [token_type], TOKEN_LESS_EQUAL
    jmp .done
    
.left_shift:
    call lexer_advance
    mov qword [token_type], TOKEN_LEFT_SHIFT
    jmp .done
    
.and_or_bitwise_and:
    call lexer_advance
    mov al, [lexer_current_char]
    cmp al, '&'
    je .logical_and
    mov qword [token_type], TOKEN_BITWISE_AND
    jmp .done
    
.logical_and:
    call lexer_advance
    mov qword [token_type], TOKEN_LOGICAL_AND
    jmp .done
    
.or_or_bitwise_or:
    call lexer_advance
    mov al, [lexer_current_char]
    cmp al, '|'
    je .logical_or
    mov qword [token_type], TOKEN_BITWISE_OR
    jmp .done
    
.logical_or:
    call lexer_advance
    mov qword [token_type], TOKEN_LOGICAL_OR
    jmp .done
    
.bitwise_not:
    call lexer_advance
    mov qword [token_type], TOKEN_BITWISE_NOT
    jmp .done
    
.lparen:
    call lexer_advance
    mov qword [token_type], TOKEN_LPAREN
    jmp .done
    
.rparen:
    call lexer_advance
    mov qword [token_type], TOKEN_RPAREN
    jmp .done
    
.lbrace:
    call lexer_advance
    mov qword [token_type], TOKEN_LBRACE
    jmp .done
    
.rbrace:
    call lexer_advance
    mov qword [token_type], TOKEN_RBRACE
    jmp .done
    
.lbracket:
    call lexer_advance
    mov qword [token_type], TOKEN_LBRACKET
    jmp .done
    
.rbracket:
    call lexer_advance
    mov qword [token_type], TOKEN_RBRACKET
    jmp .done
    
.semicolon:
    call lexer_advance
    mov qword [token_type], TOKEN_SEMICOLON
    jmp .done
    
.comma:
    call lexer_advance
    mov qword [token_type], TOKEN_COMMA
    jmp .done
    
.dot:
    call lexer_advance
    mov qword [token_type], TOKEN_DOT
    jmp .done
    
.colon:
    call lexer_advance
    mov al, [lexer_current_char]
    cmp al, ':'
    je .double_colon
    mov qword [token_type], TOKEN_COLON
    jmp .done
    
.double_colon:
    call lexer_advance
    mov qword [token_type], TOKEN_DOUBLE_COLON
    jmp .done
    
.question:
    call lexer_advance
    mov qword [token_type], TOKEN_QUESTION
    jmp .done
    
.unknown:
    ; Handle unknown character
    mov qword [token_type], TOKEN_EOF
    
.done:
    leave
    ret

; === Utility Functions ===

; Check if character is identifier start
lexer_is_identifier_start:
    push rbp
    mov rbp, rsp
    
    mov al, [lexer_current_char]
    cmp al, 'a'
    jl .not_identifier_start
    cmp al, 'z'
    jle .is_identifier_start
    cmp al, 'A'
    jl .not_identifier_start
    cmp al, 'Z'
    jle .is_identifier_start
    cmp al, '_'
    je .is_identifier_start
    
.not_identifier_start:
    mov rax, 0
    leave
    ret
    
.is_identifier_start:
    mov rax, 1
    leave
    ret

; Check if character is identifier character
lexer_is_identifier_char:
    push rbp
    mov rbp, rsp
    
    call lexer_is_identifier_start
    cmp rax, 1
    je .is_identifier_char
    
    call lexer_is_digit
    cmp rax, 1
    je .is_identifier_char
    
    mov rax, 0
    leave
    ret
    
.is_identifier_char:
    mov rax, 1
    leave
    ret

; Check if character is digit
lexer_is_digit:
    push rbp
    mov rbp, rsp
    
    mov al, [lexer_current_char]
    cmp al, '0'
    jl .not_digit
    cmp al, '9'
    jg .not_digit
    
    mov rax, 1
    leave
    ret
    
.not_digit:
    mov rax, 0
    leave
    ret

; Check if character is hex digit
lexer_is_hex_digit:
    push rbp
    mov rbp, rsp
    
    call lexer_is_digit
    cmp rax, 1
    je .is_hex_digit
    
    mov al, [lexer_current_char]
    cmp al, 'a'
    jl .not_hex_digit
    cmp al, 'f'
    jle .is_hex_digit
    cmp al, 'A'
    jl .not_hex_digit
    cmp al, 'F'
    jle .is_hex_digit
    
.not_hex_digit:
    mov rax, 0
    leave
    ret
    
.is_hex_digit:
    mov rax, 1
    leave
    ret

; Check if character is octal digit
lexer_is_octal_digit:
    push rbp
    mov rbp, rsp
    
    mov al, [lexer_current_char]
    cmp al, '0'
    jl .not_octal_digit
    cmp al, '7'
    jg .not_octal_digit
    
    mov rax, 1
    leave
    ret
    
.not_octal_digit:
    mov rax, 0
    leave
    ret

; Check if character is binary digit
lexer_is_binary_digit:
    push rbp
    mov rbp, rsp
    
    mov al, [lexer_current_char]
    cmp al, '0'
    je .is_binary_digit
    cmp al, '1'
    je .is_binary_digit
    
    mov rax, 0
    leave
    ret
    
.is_binary_digit:
    mov rax, 1
    leave
    ret

; Check if current token is a keyword
lexer_is_keyword:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    push rdx
    
    ; Compare with each keyword
    mov rdi, token_value
    mov rsi, keyword_def
    call string_compare
    cmp rax, 0
    je .keyword_def_found
    
    mov rdi, token_value
    mov rsi, keyword_model
    call string_compare
    cmp rax, 0
    je .keyword_model_found
    
    mov rdi, token_value
    mov rsi, keyword_func
    call string_compare
    cmp rax, 0
    je .keyword_func_found
    
    mov rdi, token_value
    mov rsi, keyword_loop
    call string_compare
    cmp rax, 0
    je .keyword_loop_found
    
    mov rdi, token_value
    mov rsi, keyword_if
    call string_compare
    cmp rax, 0
    je .keyword_if_found
    
    mov rdi, token_value
    mov rsi, keyword_else
    call string_compare
    cmp rax, 0
    je .keyword_else_found
    
    mov rdi, token_value
    mov rsi, keyword_let
    call string_compare
    cmp rax, 0
    je .keyword_let_found
    
    mov rdi, token_value
    mov rsi, keyword_const
    call string_compare
    cmp rax, 0
    je .keyword_const_found
    
    mov rdi, token_value
    mov rsi, keyword_ret
    call string_compare
    cmp rax, 0
    je .keyword_ret_found
    
    mov rdi, token_value
    mov rsi, keyword_break
    call string_compare
    cmp rax, 0
    je .keyword_break_found
    
    mov rdi, token_value
    mov rsi, keyword_continue
    call string_compare
    cmp rax, 0
    je .keyword_continue_found
    
    mov rdi, token_value
    mov rsi, keyword_import
    call string_compare
    cmp rax, 0
    je .keyword_import_found
    
    mov rdi, token_value
    mov rsi, keyword_export
    call string_compare
    cmp rax, 0
    je .keyword_export_found
    
    mov rdi, token_value
    mov rsi, keyword_match
    call string_compare
    cmp rax, 0
    je .keyword_match_found
    
    mov rdi, token_value
    mov rsi, keyword_case
    call string_compare
    cmp rax, 0
    je .keyword_case_found
    
    mov rdi, token_value
    mov rsi, keyword_default
    call string_compare
    cmp rax, 0
    je .keyword_default_found
    
    mov rdi, token_value
    mov rsi, keyword_try
    call string_compare
    cmp rax, 0
    je .keyword_try_found
    
    mov rdi, token_value
    mov rsi, keyword_catch
    call string_compare
    cmp rax, 0
    je .keyword_catch_found
    
    mov rdi, token_value
    mov rsi, keyword_finally
    call string_compare
    cmp rax, 0
    je .keyword_finally_found
    
    mov rdi, token_value
    mov rsi, keyword_throw
    call string_compare
    cmp rax, 0
    je .keyword_throw_found
    
    mov rdi, token_value
    mov rsi, keyword_int
    call string_compare
    cmp rax, 0
    je .keyword_int_found
    
    mov rdi, token_value
    mov rsi, keyword_float
    call string_compare
    cmp rax, 0
    je .keyword_float_found
    
    mov rdi, token_value
    mov rsi, keyword_bool
    call string_compare
    cmp rax, 0
    je .keyword_bool_found
    
    mov rdi, token_value
    mov rsi, keyword_void
    call string_compare
    cmp rax, 0
    je .keyword_void_found
    
    mov rdi, token_value
    mov rsi, keyword_auto
    call string_compare
    cmp rax, 0
    je .keyword_auto_found
    
    mov rdi, token_value
    mov rsi, keyword_alloc
    call string_compare
    cmp rax, 0
    je .keyword_alloc_found
    
    mov rdi, token_value
    mov rsi, keyword_free
    call string_compare
    cmp rax, 0
    je .keyword_free_found
    
    mov rdi, token_value
    mov rsi, keyword_sizeof
    call string_compare
    cmp rax, 0
    je .keyword_sizeof_found
    
    mov rdi, token_value
    mov rsi, keyword_spawn
    call string_compare
    cmp rax, 0
    je .keyword_spawn_found
    
    mov rdi, token_value
    mov rsi, keyword_shared
    call string_compare
    cmp rax, 0
    je .keyword_shared_found
    
    mov rdi, token_value
    mov rsi, keyword_mutex
    call string_compare
    cmp rax, 0
    je .keyword_mutex_found
    
    mov rdi, token_value
    mov rsi, keyword_lock
    call string_compare
    cmp rax, 0
    je .keyword_lock_found
    
    mov rdi, token_value
    mov rsi, keyword_unlock
    call string_compare
    cmp rax, 0
    je .keyword_unlock_found
    
    ; Not a keyword
    mov rax, 0
    jmp .done
    
.keyword_def_found:
    mov rax, TOKEN_DEF
    jmp .done
    
.keyword_model_found:
    mov rax, TOKEN_MODEL
    jmp .done
    
.keyword_func_found:
    mov rax, TOKEN_FUNC
    jmp .done
    
.keyword_loop_found:
    mov rax, TOKEN_LOOP
    jmp .done
    
.keyword_if_found:
    mov rax, TOKEN_IF
    jmp .done
    
.keyword_else_found:
    mov rax, TOKEN_ELSE
    jmp .done
    
.keyword_let_found:
    mov rax, TOKEN_LET
    jmp .done
    
.keyword_const_found:
    mov rax, TOKEN_CONST
    jmp .done
    
.keyword_ret_found:
    mov rax, TOKEN_RET
    jmp .done
    
.keyword_break_found:
    mov rax, TOKEN_BREAK
    jmp .done
    
.keyword_continue_found:
    mov rax, TOKEN_CONTINUE
    jmp .done
    
.keyword_import_found:
    mov rax, TOKEN_IMPORT
    jmp .done
    
.keyword_export_found:
    mov rax, TOKEN_EXPORT
    jmp .done
    
.keyword_match_found:
    mov rax, TOKEN_MATCH
    jmp .done
    
.keyword_case_found:
    mov rax, TOKEN_CASE
    jmp .done
    
.keyword_default_found:
    mov rax, TOKEN_DEFAULT
    jmp .done
    
.keyword_try_found:
    mov rax, TOKEN_TRY
    jmp .done
    
.keyword_catch_found:
    mov rax, TOKEN_CATCH
    jmp .done
    
.keyword_finally_found:
    mov rax, TOKEN_FINALLY
    jmp .done
    
.keyword_throw_found:
    mov rax, TOKEN_THROW
    jmp .done
    
.keyword_int_found:
    mov rax, TOKEN_INT
    jmp .done
    
.keyword_float_found:
    mov rax, TOKEN_FLOAT
    jmp .done
    
.keyword_bool_found:
    mov rax, TOKEN_BOOL
    jmp .done
    
.keyword_void_found:
    mov rax, TOKEN_VOID
    jmp .done
    
.keyword_auto_found:
    mov rax, TOKEN_AUTO
    jmp .done
    
.keyword_alloc_found:
    mov rax, TOKEN_ALLOC
    jmp .done
    
.keyword_free_found:
    mov rax, TOKEN_FREE
    jmp .done
    
.keyword_sizeof_found:
    mov rax, TOKEN_SIZEOF
    jmp .done
    
.keyword_spawn_found:
    mov rax, TOKEN_SPAWN
    jmp .done
    
.keyword_shared_found:
    mov rax, TOKEN_SHARED
    jmp .done
    
.keyword_mutex_found:
    mov rax, TOKEN_MUTEX
    jmp .done
    
.keyword_lock_found:
    mov rax, TOKEN_LOCK
    jmp .done
    
.keyword_unlock_found:
    mov rax, TOKEN_UNLOCK
    jmp .done
    
.done:
    pop rdx
    pop rcx
    pop rbx
    leave
    ret

; === String Comparison ===
; Args: rdi = string1, rsi = string2
; Returns: rax = 0 if equal, non-zero if different
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

; === Get Current Token ===
lexer_get_current_token:
    push rbp
    mov rbp, rsp
    
    ; Return token information
    mov rax, [token_type]
    mov rbx, token_value
    mov rcx, [token_line]
    mov rdx, [token_column]
    
    leave
    ret

; === Peek Token ===
lexer_peek_token:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    push rdx
    
    ; Save current state
    mov rbx, [lexer_position]
    mov rcx, [lexer_line]
    mov rdx, [lexer_column]
    
    ; Get next token
    call lexer_next_token
    
    ; Restore state
    mov [lexer_position], rbx
    mov [lexer_line], rcx
    mov [lexer_column], rdx
    call lexer_load_current_char
    
    ; Return token type
    mov rax, [token_type]
    
    pop rdx
    pop rcx
    pop rbx
    leave
    ret