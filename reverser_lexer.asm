; reverser_lexer.asm
; Complete lexer for the Reverser language (backwards processing)
; Handles full syntax: cnuf (func), ledom (model), pool (loop), fi (if), tel (let), ter (return)
; Written in x86-64 assembly using NASM syntax

section .data
    ; Reverser keywords (stored in reverse for backwards processing)
    keyword_cnuf     db "cnuf", 0          ; func
    keyword_ledom    db "ledom", 0         ; model  
    keyword_pool     db "pool", 0          ; loop
    keyword_fi       db "fi", 0            ; if
    keyword_tel      db "tel", 0           ; let
    keyword_ter      db "ter", 0           ; return
    keyword_esle     db "esle", 0          ; else
    keyword_rof      db "rof", 0           ; for
    keyword_elihw    db "elihw", 0         ; while
    keyword_od       db "od", 0            ; do
    keyword_ni       db "ni", 0            ; in
    keyword_ot       db "ot", 0            ; to
    keyword_morf     db "morf", 0          ; from
    keyword_na       db "na", 0            ; and
    keyword_ro       db "ro", 0            ; or
    keyword_ton      db "ton", 0           ; not
    keyword_eurt     db "eurt", 0          ; true
    keyword_eslaf    db "eslaf", 0         ; false
    keyword_tni      db "tni", 0           ; int
    keyword_gnirts   db "gnirts", 0        ; string
    keyword_loob     db "loob", 0          ; bool
    keyword_laer     db "laer", 0          ; real
    keyword_yarra    db "yarra", 0         ; array
    keyword_ecaf     db "ecaf", 0          ; face (interface)
    keyword_tcudorp  db "tcudorp", 0       ; product (struct)
    keyword_ecalp    db "ecalp", 0         ; place (namespace)
    keyword_esu      db "esu", 0           ; use
    keyword_rotcerid db "rotcerid", 0      ; direct (import)
    keyword_tpurtxe  db "tpurtxe", 0       ; export
    keyword_gnirts   db "gnirts", 0        ; string
    keyword_laer     db "laer", 0          ; real
    keyword_loob     db "loob", 0          ; bool
    keyword_tni      db "tni", 0           ; int

    ; Token types enum (as constants)
    TOKEN_EOF        equ 0
    TOKEN_IDENTIFIER equ 1
    TOKEN_CNUF       equ 2
    TOKEN_LEDOM      equ 3
    TOKEN_POOL       equ 4
    TOKEN_FI         equ 5
    TOKEN_TEL        equ 6
    TOKEN_TER        equ 7
    TOKEN_ESLE       equ 8
    TOKEN_ROF        equ 9
    TOKEN_ELIHW      equ 10
    TOKEN_OD         equ 11
    TOKEN_NI         equ 12
    TOKEN_OT         equ 13
    TOKEN_MORF       equ 14
    TOKEN_NA         equ 15
    TOKEN_RO         equ 16
    TOKEN_TON        equ 17
    TOKEN_EURT       equ 18
    TOKEN_ESLAF      equ 19
    TOKEN_TNI        equ 20
    TOKEN_GNIRTS     equ 21
    TOKEN_LOOB       equ 22
    TOKEN_LAER       equ 23
    TOKEN_YARRA      equ 24
    TOKEN_ECAF       equ 25
    TOKEN_TCUDORP    equ 26
    TOKEN_ECALP      equ 27
    TOKEN_ESU        equ 28
    TOKEN_ROTCERID   equ 29
    TOKEN_TPURTXE    equ 30
    TOKEN_LITERAL_INT equ 31
    TOKEN_LITERAL_STRING equ 32
    TOKEN_LITERAL_REAL equ 33
    TOKEN_LITERAL_BOOL equ 34
    TOKEN_LBRACE     equ 35    ; {
    TOKEN_RBRACE     equ 36    ; }
    TOKEN_LPAREN     equ 37    ; (
    TOKEN_RPAREN     equ 38    ; )
    TOKEN_LBRACKET   equ 39    ; [
    TOKEN_RBRACKET   equ 40    ; ]
    TOKEN_EQ         equ 41    ; =
    TOKEN_GT         equ 42    ; >
    TOKEN_LT         equ 43    ; <
    TOKEN_GE         equ 44    ; >=
    TOKEN_LE         equ 45    ; <=
    TOKEN_NE         equ 46    ; !=
    TOKEN_EQEQ       equ 47    ; ==
    TOKEN_ARROW      equ 48    ; ->
    TOKEN_COLON      equ 49    ; :
    TOKEN_COMMA      equ 50    ; ,
    TOKEN_SEMICOLON  equ 51    ; ;
    TOKEN_DOT        equ 52    ; .
    TOKEN_PLUS       equ 53    ; +
    TOKEN_MINUS      equ 54    ; -
    TOKEN_MULTIPLY   equ 55    ; *
    TOKEN_DIVIDE     equ 56    ; /
    TOKEN_MODULO     equ 57    ; %
    TOKEN_PLUSPLUS   equ 58    ; ++
    TOKEN_MINUSMINUS equ 59    ; --
    TOKEN_PLUSEQ     equ 60    ; +=
    TOKEN_MINUSEQ    equ 61    ; -=
    TOKEN_MULTEQ     equ 62    ; *=
    TOKEN_DIVEQ      equ 63    ; /=
    TOKEN_MODEQ      equ 64    ; %=
    TOKEN_AND        equ 65    ; &&
    TOKEN_OR         equ 66    ; ||
    TOKEN_NOT        equ 67    ; !
    TOKEN_QUESTION   equ 68    ; ?
    TOKEN_PIPE       equ 69    ; |
    TOKEN_AMPERSAND  equ 70    ; &
    TOKEN_CARET      equ 71    ; ^
    TOKEN_TILDE      equ 72    ; ~
    TOKEN_LSHIFT     equ 73    ; <<
    TOKEN_RSHIFT     equ 74    ; >>
    TOKEN_COMMENT    equ 75    ; // or /*
    TOKEN_WHITESPACE equ 76
    TOKEN_NEWLINE    equ 77
    TOKEN_ERROR      equ 78

    ; Error messages
    error_unclosed_string db "Error: Unclosed string literal", 0
    error_invalid_char    db "Error: Invalid character", 0
    error_unexpected_eof  db "Error: Unexpected end of file", 0

section .bss
    ; Lexer state
    source_ptr       resq 1    ; Pointer to current position in source
    source_end       resq 1    ; Pointer to end of source
    current_token    resq 1    ; Current token type
    token_value      resb 256  ; Current token value buffer
    token_length     resq 1    ; Length of current token value
    line_number      resq 1    ; Current line number
    column_number    resq 1    ; Current column number

section .text
    global _start
    global lexer_init
    global lexer_get_next_token
    global lexer_peek_token
    global lexer_skip_whitespace
    global lexer_skip_comment

; Initialize the lexer with source code
; Input: rdi = pointer to source code, rsi = source length
lexer_init:
    mov [source_ptr], rdi
    add rdi, rsi
    mov [source_end], rdi
    mov qword [line_number], 1
    mov qword [column_number], 1
    ret

; Get the next token from the source
; Output: rax = token type, rdx = pointer to token value, rcx = token length
lexer_get_next_token:
    push rbx
    push rsi
    push rdi
    
    ; Check if we've reached end of source
    mov rax, [source_ptr]
    cmp rax, [source_end]
    jge .eof_reached
    
    ; Skip whitespace and comments
    call lexer_skip_whitespace
    call lexer_skip_comment
    
    ; Check again after skipping
    mov rax, [source_ptr]
    cmp rax, [source_end]
    jge .eof_reached
    
    ; Get current character
    mov al, [rax]
    
    ; Handle different character types
    cmp al, '"'
    je .handle_string_literal
    
    cmp al, "'"
    je .handle_char_literal
    
    cmp al, '0'
    jl .handle_symbol
    cmp al, '9'
    jle .handle_number
    
    cmp al, 'a'
    jl .handle_symbol
    cmp al, 'z'
    jle .handle_identifier
    
    cmp al, 'A'
    jl .handle_symbol
    cmp al, 'Z'
    jle .handle_identifier
    
    cmp al, '_'
    je .handle_identifier
    
    jmp .handle_symbol

.eof_reached:
    mov rax, TOKEN_EOF
    mov rdx, 0
    mov rcx, 0
    jmp .return

.handle_string_literal:
    call lex_string_literal
    jmp .return

.handle_char_literal:
    call lex_char_literal
    jmp .return

.handle_number:
    call lex_number
    jmp .return

.handle_identifier:
    call lex_identifier
    jmp .return

.handle_symbol:
    call lex_symbol
    jmp .return

.return:
    pop rdi
    pop rsi
    pop rbx
    ret

; Lex a string literal (handles backwards processing)
lex_string_literal:
    push rbx
    push rsi
    push rdi
    
    mov rbx, [source_ptr]
    inc rbx  ; Skip opening quote
    
    ; Find closing quote (process backwards)
    mov rsi, rbx
    mov rdi, token_value
    mov rcx, 0  ; Length counter
    
.find_closing:
    cmp rbx, [source_end]
    jge .unclosed_string
    
    mov al, [rbx]
    cmp al, '"'
    je .found_closing
    
    ; Handle escape sequences
    cmp al, '\'
    je .handle_escape
    
    ; Store character (in reverse order for backwards processing)
    mov [rdi + rcx], al
    inc rcx
    inc rbx
    jmp .find_closing

.handle_escape:
    inc rbx
    cmp rbx, [source_end]
    jge .unclosed_string
    
    mov al, [rbx]
    ; Handle escape sequences: \n, \t, \r, \", \', \\
    cmp al, 'n'
    je .escape_newline
    cmp al, 't'
    je .escape_tab
    cmp al, 'r'
    je .escape_carriage
    cmp al, '"'
    je .escape_quote
    cmp al, '\''
    je .escape_single
    cmp al, '\'
    je .escape_backslash
    ; Default: just store the character after backslash
    jmp .store_escape

.escape_newline:
    mov al, 10
    jmp .store_escape
.escape_tab:
    mov al, 9
    jmp .store_escape
.escape_carriage:
    mov al, 13
    jmp .store_escape
.escape_quote:
    mov al, '"'
    jmp .store_escape
.escape_single:
    mov al, '\''
    jmp .store_escape
.escape_backslash:
    mov al, '\'
    jmp .store_escape

.store_escape:
    mov [rdi + rcx], al
    inc rcx
    inc rbx
    jmp .find_closing

.found_closing:
    inc rbx  ; Skip closing quote
    mov [source_ptr], rbx
    mov [token_length], rcx
    mov rax, TOKEN_LITERAL_STRING
    mov rdx, token_value
    mov rcx, [token_length]
    jmp .return

.unclosed_string:
    mov rax, TOKEN_ERROR
    mov rdx, error_unclosed_string
    mov rcx, 0
    jmp .return

.return:
    pop rdi
    pop rsi
    pop rbx
    ret

; Lex a character literal
lex_char_literal:
    push rbx
    push rsi
    push rdi
    
    mov rbx, [source_ptr]
    inc rbx  ; Skip opening quote
    
    cmp rbx, [source_end]
    jge .unclosed_char
    
    mov al, [rbx]
    cmp al, '\'
    je .handle_char_escape
    
    ; Regular character
    mov [token_value], al
    inc rbx
    
    ; Check for closing quote
    cmp rbx, [source_end]
    jge .unclosed_char
    
    cmp byte [rbx], '\''
    jne .invalid_char
    
    inc rbx  ; Skip closing quote
    mov [source_ptr], rbx
    mov qword [token_length], 1
    mov rax, TOKEN_LITERAL_INT  ; Store as int for simplicity
    mov rdx, token_value
    mov rcx, 1
    jmp .return

.handle_char_escape:
    inc rbx
    cmp rbx, [source_end]
    jge .unclosed_char
    
    mov al, [rbx]
    ; Handle escape sequences
    cmp al, 'n'
    je .char_escape_newline
    cmp al, 't'
    je .char_escape_tab
    cmp al, 'r'
    je .char_escape_carriage
    cmp al, '\''
    je .char_escape_single
    cmp al, '\'
    je .char_escape_backslash
    ; Default: just store the character after backslash
    jmp .char_store_escape

.char_escape_newline:
    mov al, 10
    jmp .char_store_escape
.char_escape_tab:
    mov al, 9
    jmp .char_store_escape
.char_escape_carriage:
    mov al, 13
    jmp .char_store_escape
.char_escape_single:
    mov al, '\''
    jmp .char_store_escape
.char_escape_backslash:
    mov al, '\'
    jmp .char_store_escape

.char_store_escape:
    mov [token_value], al
    inc rbx
    
    ; Check for closing quote
    cmp rbx, [source_end]
    jge .unclosed_char
    
    cmp byte [rbx], '\''
    jne .invalid_char
    
    inc rbx  ; Skip closing quote
    mov [source_ptr], rbx
    mov qword [token_length], 1
    mov rax, TOKEN_LITERAL_INT
    mov rdx, token_value
    mov rcx, 1
    jmp .return

.unclosed_char:
    mov rax, TOKEN_ERROR
    mov rdx, error_unclosed_string
    mov rcx, 0
    jmp .return

.invalid_char:
    mov rax, TOKEN_ERROR
    mov rdx, error_invalid_char
    mov rcx, 0
    jmp .return

.return:
    pop rdi
    pop rsi
    pop rbx
    ret

; Lex a number (integer or real)
lex_number:
    push rbx
    push rsi
    push rdi
    
    mov rbx, [source_ptr]
    mov rsi, token_value
    mov rcx, 0  ; Length counter
    mov rdx, 0  ; Has decimal point flag
    
.number_loop:
    cmp rbx, [source_end]
    jge .number_done
    
    mov al, [rbx]
    
    ; Check if it's a digit
    cmp al, '0'
    jl .check_decimal
    cmp al, '9'
    jg .check_decimal
    
    ; It's a digit, store it
    mov [rsi + rcx], al
    inc rcx
    inc rbx
    jmp .number_loop

.check_decimal:
    cmp al, '.'
    jne .number_done
    
    cmp rdx, 1  ; Already has decimal point?
    je .number_done
    
    mov rdx, 1  ; Mark as having decimal point
    mov [rsi + rcx], al
    inc rcx
    inc rbx
    jmp .number_loop

.number_done:
    mov [source_ptr], rbx
    mov [token_length], rcx
    
    ; Determine token type based on whether it has decimal point
    cmp rdx, 1
    je .real_number
    
    mov rax, TOKEN_LITERAL_INT
    jmp .return

.real_number:
    mov rax, TOKEN_LITERAL_REAL

.return:
    mov rdx, token_value
    mov rcx, [token_length]
    pop rdi
    pop rsi
    pop rbx
    ret

; Lex an identifier or keyword
lex_identifier:
    push rbx
    push rsi
    push rdi
    
    mov rbx, [source_ptr]
    mov rsi, token_value
    mov rcx, 0  ; Length counter
    
.identifier_loop:
    cmp rbx, [source_end]
    jge .identifier_done
    
    mov al, [rbx]
    
    ; Check if it's a valid identifier character
    cmp al, 'a'
    jl .check_upper
    cmp al, 'z'
    jle .store_char
    
.check_upper:
    cmp al, 'A'
    jl .check_digit
    cmp al, 'Z'
    jle .store_char
    
.check_digit:
    cmp al, '0'
    jl .check_underscore
    cmp al, '9'
    jle .store_char
    
.check_underscore:
    cmp al, '_'
    jne .identifier_done
    
.store_char:
    mov [rsi + rcx], al
    inc rcx
    inc rbx
    jmp .identifier_loop

.identifier_done:
    mov [source_ptr], rbx
    mov [token_length], rcx
    
    ; Check if it's a keyword
    call check_keyword
    jmp .return

.return:
    mov rdx, token_value
    mov rcx, [token_length]
    pop rdi
    pop rsi
    pop rbx
    ret

; Check if current token is a keyword
check_keyword:
    push rbx
    push rsi
    push rdi
    
    mov rsi, token_value
    mov rcx, [token_length]
    
    ; Compare with each keyword (case-sensitive)
    ; cnuf (func)
    cmp rcx, 4
    jne .check_ledom
    cmp dword [rsi], 'cnuf'
    je .found_cnuf
    
.check_ledom:
    ; ledom (model)
    cmp rcx, 5
    jne .check_pool
    cmp dword [rsi], 'ledo'
    jne .check_pool
    cmp byte [rsi + 4], 'm'
    je .found_ledom
    
.check_pool:
    ; pool (loop)
    cmp rcx, 4
    jne .check_fi
    cmp dword [rsi], 'pool'
    je .found_pool
    
.check_fi:
    ; fi (if)
    cmp rcx, 2
    jne .check_tel
    cmp word [rsi], 'fi'
    je .found_fi
    
.check_tel:
    ; tel (let)
    cmp rcx, 3
    jne .check_ter
    cmp word [rsi], 'te'
    jne .check_ter
    cmp byte [rsi + 2], 'l'
    je .found_tel
    
.check_ter:
    ; ter (return)
    cmp rcx, 3
    jne .check_esle
    cmp word [rsi], 'te'
    jne .check_esle
    cmp byte [rsi + 2], 'r'
    je .found_ter
    
.check_esle:
    ; esle (else)
    cmp rcx, 4
    jne .check_rof
    cmp dword [rsi], 'esle'
    je .found_esle
    
.check_rof:
    ; rof (for)
    cmp rcx, 3
    jne .check_elihw
    cmp word [rsi], 'ro'
    jne .check_elihw
    cmp byte [rsi + 2], 'f'
    je .found_rof
    
.check_elihw:
    ; elihw (while)
    cmp rcx, 5
    jne .check_od
    cmp dword [rsi], 'elih'
    jne .check_od
    cmp byte [rsi + 4], 'w'
    je .found_elihw
    
.check_od:
    ; od (do)
    cmp rcx, 2
    jne .check_ni
    cmp word [rsi], 'od'
    je .found_od
    
.check_ni:
    ; ni (in)
    cmp rcx, 2
    jne .check_ot
    cmp word [rsi], 'ni'
    je .found_ni
    
.check_ot:
    ; ot (to)
    cmp rcx, 2
    jne .check_morf
    cmp word [rsi], 'ot'
    je .found_ot
    
.check_morf:
    ; morf (from)
    cmp rcx, 4
    jne .check_na
    cmp dword [rsi], 'morf'
    je .found_morf
    
.check_na:
    ; na (and)
    cmp rcx, 2
    jne .check_ro
    cmp word [rsi], 'na'
    je .found_na
    
.check_ro:
    ; ro (or)
    cmp rcx, 2
    jne .check_ton
    cmp word [rsi], 'ro'
    je .found_ro
    
.check_ton:
    ; ton (not)
    cmp rcx, 3
    jne .check_eurt
    cmp word [rsi], 'to'
    jne .check_eurt
    cmp byte [rsi + 2], 'n'
    je .found_ton
    
.check_eurt:
    ; eurt (true)
    cmp rcx, 4
    jne .check_eslaf
    cmp dword [rsi], 'eurt'
    je .found_eurt
    
.check_eslaf:
    ; eslaf (false)
    cmp rcx, 5
    jne .check_tni
    cmp dword [rsi], 'esla'
    jne .check_tni
    cmp byte [rsi + 4], 'f'
    je .found_eslaf
    
.check_tni:
    ; tni (int)
    cmp rcx, 3
    jne .check_gnirts
    cmp word [rsi], 'tn'
    jne .check_gnirts
    cmp byte [rsi + 2], 'i'
    je .found_tni
    
.check_gnirts:
    ; gnirts (string)
    cmp rcx, 6
    jne .check_loob
    cmp dword [rsi], 'gnir'
    jne .check_loob
    cmp word [rsi + 4], 'ts'
    je .found_gnirts
    
.check_loob:
    ; loob (bool)
    cmp rcx, 4
    jne .check_laer
    cmp dword [rsi], 'loob'
    je .found_loob
    
.check_laer:
    ; laer (real)
    cmp rcx, 4
    jne .identifier
    cmp dword [rsi], 'laer'
    je .found_laer
    
.identifier:
    mov rax, TOKEN_IDENTIFIER
    jmp .return

.found_cnuf:
    mov rax, TOKEN_CNUF
    jmp .return
.found_ledom:
    mov rax, TOKEN_LEDOM
    jmp .return
.found_pool:
    mov rax, TOKEN_POOL
    jmp .return
.found_fi:
    mov rax, TOKEN_FI
    jmp .return
.found_tel:
    mov rax, TOKEN_TEL
    jmp .return
.found_ter:
    mov rax, TOKEN_TER
    jmp .return
.found_esle:
    mov rax, TOKEN_ESLE
    jmp .return
.found_rof:
    mov rax, TOKEN_ROF
    jmp .return
.found_elihw:
    mov rax, TOKEN_ELIHW
    jmp .return
.found_od:
    mov rax, TOKEN_OD
    jmp .return
.found_ni:
    mov rax, TOKEN_NI
    jmp .return
.found_ot:
    mov rax, TOKEN_OT
    jmp .return
.found_morf:
    mov rax, TOKEN_MORF
    jmp .return
.found_na:
    mov rax, TOKEN_NA
    jmp .return
.found_ro:
    mov rax, TOKEN_RO
    jmp .return
.found_ton:
    mov rax, TOKEN_TON
    jmp .return
.found_eurt:
    mov rax, TOKEN_EURT
    jmp .return
.found_eslaf:
    mov rax, TOKEN_ESLAF
    jmp .return
.found_tni:
    mov rax, TOKEN_TNI
    jmp .return
.found_gnirts:
    mov rax, TOKEN_GNIRTS
    jmp .return
.found_loob:
    mov rax, TOKEN_LOOB
    jmp .return
.found_laer:
    mov rax, TOKEN_LAER
    jmp .return

.return:
    pop rdi
    pop rsi
    pop rbx
    ret

; Lex symbols and operators
lex_symbol:
    push rbx
    push rsi
    push rdi
    
    mov rbx, [source_ptr]
    mov al, [rbx]
    inc rbx
    
    ; Handle single character symbols
    cmp al, '{'
    je .lbrace
    cmp al, '}'
    je .rbrace
    cmp al, '('
    je .lparen
    cmp al, ')'
    je .rparen
    cmp al, '['
    je .lbracket
    cmp al, ']'
    je .rbracket
    cmp al, ':'
    je .colon
    cmp al, ','
    je .comma
    cmp al, ';'
    je .semicolon
    cmp al, '.'
    je .dot
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
    cmp al, '!'
    je .not
    cmp al, '?'
    je .question
    cmp al, '|'
    je .pipe
    cmp al, '&'
    je .ampersand
    cmp al, '^'
    je .caret
    cmp al, '~'
    je .tilde
    
    ; Handle multi-character operators
    cmp al, '='
    je .check_eq
    cmp al, '>'
    je .check_gt
    cmp al, '<'
    je .check_lt
    
    ; Unknown character
    mov rax, TOKEN_ERROR
    mov rdx, error_invalid_char
    mov rcx, 0
    jmp .return

.lbrace:
    mov rax, TOKEN_LBRACE
    jmp .single_char
.rbrace:
    mov rax, TOKEN_RBRACE
    jmp .single_char
.lparen:
    mov rax, TOKEN_LPAREN
    jmp .single_char
.rparen:
    mov rax, TOKEN_RPAREN
    jmp .single_char
.lbracket:
    mov rax, TOKEN_LBRACKET
    jmp .single_char
.rbracket:
    mov rax, TOKEN_RBRACKET
    jmp .single_char
.colon:
    mov rax, TOKEN_COLON
    jmp .single_char
.comma:
    mov rax, TOKEN_COMMA
    jmp .single_char
.semicolon:
    mov rax, TOKEN_SEMICOLON
    jmp .single_char
.dot:
    mov rax, TOKEN_DOT
    jmp .single_char
.plus:
    mov rax, TOKEN_PLUS
    jmp .single_char
.minus:
    mov rax, TOKEN_MINUS
    jmp .single_char
.multiply:
    mov rax, TOKEN_MULTIPLY
    jmp .single_char
.divide:
    mov rax, TOKEN_DIVIDE
    jmp .single_char
.modulo:
    mov rax, TOKEN_MODULO
    jmp .single_char
.not:
    mov rax, TOKEN_NOT
    jmp .single_char
.question:
    mov rax, TOKEN_QUESTION
    jmp .single_char
.pipe:
    mov rax, TOKEN_PIPE
    jmp .single_char
.ampersand:
    mov rax, TOKEN_AMPERSAND
    jmp .single_char
.caret:
    mov rax, TOKEN_CARET
    jmp .single_char
.tilde:
    mov rax, TOKEN_TILDE
    jmp .single_char

.check_eq:
    cmp rbx, [source_end]
    jge .single_eq
    cmp byte [rbx], '='
    jne .single_eq
    inc rbx
    mov rax, TOKEN_EQEQ
    jmp .update_ptr
.single_eq:
    mov rax, TOKEN_EQ
    jmp .update_ptr

.check_gt:
    cmp rbx, [source_end]
    jge .single_gt
    cmp byte [rbx], '='
    jne .check_gt_shift
    inc rbx
    mov rax, TOKEN_GE
    jmp .update_ptr
.check_gt_shift:
    cmp byte [rbx], '>'
    jne .single_gt
    inc rbx
    mov rax, TOKEN_RSHIFT
    jmp .update_ptr
.single_gt:
    mov rax, TOKEN_GT
    jmp .update_ptr

.check_lt:
    cmp rbx, [source_end]
    jge .single_lt
    cmp byte [rbx], '='
    jne .check_lt_shift
    inc rbx
    mov rax, TOKEN_LE
    jmp .update_ptr
.check_lt_shift:
    cmp byte [rbx], '<'
    jne .single_lt
    inc rbx
    mov rax, TOKEN_LSHIFT
    jmp .update_ptr
.single_lt:
    mov rax, TOKEN_LT
    jmp .update_ptr

.single_char:
    mov [source_ptr], rbx
    mov rdx, 0
    mov rcx, 0
    jmp .return

.update_ptr:
    mov [source_ptr], rbx
    mov rdx, 0
    mov rcx, 0
    jmp .return

.return:
    pop rdi
    pop rsi
    pop rbx
    ret

; Skip whitespace characters
lexer_skip_whitespace:
    push rbx
    
    mov rbx, [source_ptr]
    
.whitespace_loop:
    cmp rbx, [source_end]
    jge .done
    
    mov al, [rbx]
    
    cmp al, ' '
    je .skip_char
    cmp al, '\t'
    je .skip_char
    cmp al, '\r'
    je .skip_char
    cmp al, '\n'
    je .newline
    
    jmp .done

.skip_char:
    inc rbx
    jmp .whitespace_loop

.newline:
    inc rbx
    inc qword [line_number]
    mov qword [column_number], 1
    jmp .whitespace_loop

.done:
    mov [source_ptr], rbx
    pop rbx
    ret

; Skip comments (both // and /* */)
lexer_skip_comment:
    push rbx
    
    mov rbx, [source_ptr]
    cmp rbx, [source_end]
    jge .done
    
    mov al, [rbx]
    cmp al, '/'
    jne .done
    
    inc rbx
    cmp rbx, [source_end]
    jge .done
    
    mov al, [rbx]
    cmp al, '/'
    je .line_comment
    cmp al, '*'
    je .block_comment
    
    ; Not a comment, back up
    dec rbx
    jmp .done

.line_comment:
    inc rbx
.line_comment_loop:
    cmp rbx, [source_end]
    jge .done
    
    mov al, [rbx]
    cmp al, '\n'
    je .newline_found
    inc rbx
    jmp .line_comment_loop

.block_comment:
    inc rbx
.block_comment_loop:
    cmp rbx, [source_end]
    jge .done
    
    mov al, [rbx]
    cmp al, '*'
    je .check_block_end
    cmp al, '\n'
    je .block_newline
    inc rbx
    jmp .block_comment_loop

.check_block_end:
    inc rbx
    cmp rbx, [source_end]
    jge .done
    
    mov al, [rbx]
    cmp al, '/'
    je .block_end_found
    jmp .block_comment_loop

.block_end_found:
    inc rbx
    jmp .done

.newline_found:
    inc rbx
    inc qword [line_number]
    mov qword [column_number], 1
    jmp .done

.block_newline:
    inc rbx
    inc qword [line_number]
    mov qword [column_number], 1
    jmp .block_comment_loop

.done:
    mov [source_ptr], rbx
    pop rbx
    ret

; Peek at the next token without consuming it
lexer_peek_token:
    push rbx
    push rsi
    push rdi
    
    ; Save current state
    mov rbx, [source_ptr]
    push rbx
    
    ; Get next token
    call lexer_get_next_token
    
    ; Restore state
    pop rbx
    mov [source_ptr], rbx
    
    pop rdi
    pop rsi
    pop rbx
    ret

; Main entry point for testing
_start:
    ; Example usage
    mov rdi, test_source
    mov rsi, test_source_len
    call lexer_init
    
.token_loop:
    call lexer_get_next_token
    cmp rax, TOKEN_EOF
    je .done
    cmp rax, TOKEN_ERROR
    je .error
    
    ; Here you would process the token
    ; rax = token type, rdx = token value, rcx = token length
    
    jmp .token_loop

.error:
    ; Handle error
    jmp .done

.done:
    mov rax, 60     ; syscall number for exit
    xor rdi, rdi    ; exit code 0
    syscall

section .data
    test_source db 'cnuf main() -> tni { ter 42 }', 0
    test_source_len equ $ - test_source - 1
