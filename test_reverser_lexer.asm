; test_reverser_lexer.asm
; Test program for the Reverser language lexer
; Demonstrates backwards processing of Reverser source code

section .data
    ; Test Reverser source code (backwards syntax)
    test_source1 db 'cnuf main() -> tni { ter 42 }', 0
    test_source1_len equ $ - test_source1 - 1
    
    test_source2 db 'ledom User { di: tni, emanresu: gnirts }', 0
    test_source2_len equ $ - test_source2 - 1
    
    test_source3 db 'fi di > 100 { ter eurt } esle { ter eslaf }', 0
    test_source3_len equ $ - test_source3 - 1
    
    test_source4 db 'pool i morf 0 ot 10 { tel sum = sum + i }', 0
    test_source4_len equ $ - test_source4 - 1
    
    ; Output messages
    msg_token_type db 'Token Type: ', 0
    msg_token_value db 'Value: ', 0
    msg_newline db 10, 0
    msg_separator db '---', 10, 0
    msg_test_start db 'Testing Reverser Lexer:', 10, 0
    msg_test_end db 'Lexer test completed.', 10, 0

section .bss
    ; Buffer for token value display
    token_display resb 256

section .text
    global _start
    extern lexer_init
    extern lexer_get_next_token

; Convert token type to string for display
; Input: rax = token type
; Output: rdx = pointer to string, rcx = string length
token_type_to_string:
    cmp rax, TOKEN_EOF
    je .eof
    cmp rax, TOKEN_IDENTIFIER
    je .identifier
    cmp rax, TOKEN_CNUF
    je .cnuf
    cmp rax, TOKEN_LEDOM
    je .ledom
    cmp rax, TOKEN_POOL
    je .pool
    cmp rax, TOKEN_FI
    je .fi
    cmp rax, TOKEN_TEL
    je .tel
    cmp rax, TOKEN_TER
    je .ter
    cmp rax, TOKEN_ESLE
    je .esle
    cmp rax, TOKEN_ROF
    je .rof
    cmp rax, TOKEN_ELIHW
    je .elihw
    cmp rax, TOKEN_OD
    je .od
    cmp rax, TOKEN_NI
    je .ni
    cmp rax, TOKEN_OT
    je .ot
    cmp rax, TOKEN_MORF
    je .morf
    cmp rax, TOKEN_NA
    je .na
    cmp rax, TOKEN_RO
    je .ro
    cmp rax, TOKEN_TON
    je .ton
    cmp rax, TOKEN_EURT
    je .eurt
    cmp rax, TOKEN_ESLAF
    je .eslaf
    cmp rax, TOKEN_TNI
    je .tni
    cmp rax, TOKEN_GNIRTS
    je .gnirts
    cmp rax, TOKEN_LOOB
    je .loob
    cmp rax, TOKEN_LAER
    je .laer
    cmp rax, TOKEN_LITERAL_INT
    je .literal_int
    cmp rax, TOKEN_LITERAL_STRING
    je .literal_string
    cmp rax, TOKEN_LITERAL_REAL
    je .literal_real
    cmp rax, TOKEN_LITERAL_BOOL
    je .literal_bool
    cmp rax, TOKEN_LBRACE
    je .lbrace
    cmp rax, TOKEN_RBRACE
    je .rbrace
    cmp rax, TOKEN_LPAREN
    je .lparen
    cmp rax, TOKEN_RPAREN
    je .rparen
    cmp rax, TOKEN_LBRACKET
    je .lbracket
    cmp rax, TOKEN_RBRACKET
    je .rbracket
    cmp rax, TOKEN_EQ
    je .eq
    cmp rax, TOKEN_GT
    je .gt
    cmp rax, TOKEN_LT
    je .lt
    cmp rax, TOKEN_GE
    je .ge
    cmp rax, TOKEN_LE
    je .le
    cmp rax, TOKEN_NE
    je .ne
    cmp rax, TOKEN_EQEQ
    je .eqeq
    cmp rax, TOKEN_ARROW
    je .arrow
    cmp rax, TOKEN_COLON
    je .colon
    cmp rax, TOKEN_COMMA
    je .comma
    cmp rax, TOKEN_SEMICOLON
    je .semicolon
    cmp rax, TOKEN_DOT
    je .dot
    cmp rax, TOKEN_PLUS
    je .plus
    cmp rax, TOKEN_MINUS
    je .minus
    cmp rax, TOKEN_MULTIPLY
    je .multiply
    cmp rax, TOKEN_DIVIDE
    je .divide
    cmp rax, TOKEN_MODULO
    je .modulo
    cmp rax, TOKEN_PLUSPLUS
    je .plusplus
    cmp rax, TOKEN_MINUSMINUS
    je .minusminus
    cmp rax, TOKEN_PLUSEQ
    je .pluseq
    cmp rax, TOKEN_MINUSEQ
    je .minuseq
    cmp rax, TOKEN_MULTEQ
    je .multeq
    cmp rax, TOKEN_DIVEQ
    je .diveq
    cmp rax, TOKEN_MODEQ
    je .modeq
    cmp rax, TOKEN_AND
    je .and
    cmp rax, TOKEN_OR
    je .or
    cmp rax, TOKEN_NOT
    je .not
    cmp rax, TOKEN_QUESTION
    je .question
    cmp rax, TOKEN_PIPE
    je .pipe
    cmp rax, TOKEN_AMPERSAND
    je .ampersand
    cmp rax, TOKEN_CARET
    je .caret
    cmp rax, TOKEN_TILDE
    je .tilde
    cmp rax, TOKEN_LSHIFT
    je .lshift
    cmp rax, TOKEN_RSHIFT
    je .rshift
    cmp rax, TOKEN_COMMENT
    je .comment
    cmp rax, TOKEN_WHITESPACE
    je .whitespace
    cmp rax, TOKEN_NEWLINE
    je .newline
    cmp rax, TOKEN_ERROR
    je .error
    
    ; Unknown token type
    mov rdx, unknown_token_str
    mov rcx, unknown_token_len
    ret

.eof:
    mov rdx, eof_str
    mov rcx, eof_len
    ret
.identifier:
    mov rdx, identifier_str
    mov rcx, identifier_len
    ret
.cnuf:
    mov rdx, cnuf_str
    mov rcx, cnuf_len
    ret
.ledom:
    mov rdx, ledom_str
    mov rcx, ledom_len
    ret
.pool:
    mov rdx, pool_str
    mov rcx, pool_len
    ret
.fi:
    mov rdx, fi_str
    mov rcx, fi_len
    ret
.tel:
    mov rdx, tel_str
    mov rcx, tel_len
    ret
.ter:
    mov rdx, ter_str
    mov rcx, ter_len
    ret
.esle:
    mov rdx, esle_str
    mov rcx, esle_len
    ret
.rof:
    mov rdx, rof_str
    mov rcx, rof_len
    ret
.elihw:
    mov rdx, elihw_str
    mov rcx, elihw_len
    ret
.od:
    mov rdx, od_str
    mov rcx, od_len
    ret
.ni:
    mov rdx, ni_str
    mov rcx, ni_len
    ret
.ot:
    mov rdx, ot_str
    mov rcx, ot_len
    ret
.morf:
    mov rdx, morf_str
    mov rcx, morf_len
    ret
.na:
    mov rdx, na_str
    mov rcx, na_len
    ret
.ro:
    mov rdx, ro_str
    mov rcx, ro_len
    ret
.ton:
    mov rdx, ton_str
    mov rcx, ton_len
    ret
.eurt:
    mov rdx, eurt_str
    mov rcx, eurt_len
    ret
.eslaf:
    mov rdx, eslaf_str
    mov rcx, eslaf_len
    ret
.tni:
    mov rdx, tni_str
    mov rcx, tni_len
    ret
.gnirts:
    mov rdx, gnirts_str
    mov rcx, gnirts_len
    ret
.loob:
    mov rdx, loob_str
    mov rcx, loob_len
    ret
.laer:
    mov rdx, laer_str
    mov rcx, laer_len
    ret
.literal_int:
    mov rdx, literal_int_str
    mov rcx, literal_int_len
    ret
.literal_string:
    mov rdx, literal_string_str
    mov rcx, literal_string_len
    ret
.literal_real:
    mov rdx, literal_real_str
    mov rcx, literal_real_len
    ret
.literal_bool:
    mov rdx, literal_bool_str
    mov rcx, literal_bool_len
    ret
.lbrace:
    mov rdx, lbrace_str
    mov rcx, lbrace_len
    ret
.rbrace:
    mov rdx, rbrace_str
    mov rcx, rbrace_len
    ret
.lparen:
    mov rdx, lparen_str
    mov rcx, lparen_len
    ret
.rparen:
    mov rdx, rparen_str
    mov rcx, rparen_len
    ret
.lbracket:
    mov rdx, lbracket_str
    mov rcx, lbracket_len
    ret
.rbracket:
    mov rdx, rbracket_str
    mov rcx, rbracket_len
    ret
.eq:
    mov rdx, eq_str
    mov rcx, eq_len
    ret
.gt:
    mov rdx, gt_str
    mov rcx, gt_len
    ret
.lt:
    mov rdx, lt_str
    mov rcx, lt_len
    ret
.ge:
    mov rdx, ge_str
    mov rcx, ge_len
    ret
.le:
    mov rdx, le_str
    mov rcx, le_len
    ret
.ne:
    mov rdx, ne_str
    mov rcx, ne_len
    ret
.eqeq:
    mov rdx, eqeq_str
    mov rcx, eqeq_len
    ret
.arrow:
    mov rdx, arrow_str
    mov rcx, arrow_len
    ret
.colon:
    mov rdx, colon_str
    mov rcx, colon_len
    ret
.comma:
    mov rdx, comma_str
    mov rcx, comma_len
    ret
.semicolon:
    mov rdx, semicolon_str
    mov rcx, semicolon_len
    ret
.dot:
    mov rdx, dot_str
    mov rcx, dot_len
    ret
.plus:
    mov rdx, plus_str
    mov rcx, plus_len
    ret
.minus:
    mov rdx, minus_str
    mov rcx, minus_len
    ret
.multiply:
    mov rdx, multiply_str
    mov rcx, multiply_len
    ret
.divide:
    mov rdx, divide_str
    mov rcx, divide_len
    ret
.modulo:
    mov rdx, modulo_str
    mov rcx, modulo_len
    ret
.plusplus:
    mov rdx, plusplus_str
    mov rcx, plusplus_len
    ret
.minusminus:
    mov rdx, minusminus_str
    mov rcx, minusminus_len
    ret
.pluseq:
    mov rdx, pluseq_str
    mov rcx, pluseq_len
    ret
.minuseq:
    mov rdx, minuseq_str
    mov rcx, minuseq_len
    ret
.multeq:
    mov rdx, multeq_str
    mov rcx, multeq_len
    ret
.diveq:
    mov rdx, diveq_str
    mov rcx, diveq_len
    ret
.modeq:
    mov rdx, modeq_str
    mov rcx, modeq_len
    ret
.and:
    mov rdx, and_str
    mov rcx, and_len
    ret
.or:
    mov rdx, or_str
    mov rcx, or_len
    ret
.not:
    mov rdx, not_str
    mov rcx, not_len
    ret
.question:
    mov rdx, question_str
    mov rcx, question_len
    ret
.pipe:
    mov rdx, pipe_str
    mov rcx, pipe_len
    ret
.ampersand:
    mov rdx, ampersand_str
    mov rcx, ampersand_len
    ret
.caret:
    mov rdx, caret_str
    mov rcx, caret_len
    ret
.tilde:
    mov rdx, tilde_str
    mov rcx, tilde_len
    ret
.lshift:
    mov rdx, lshift_str
    mov rcx, lshift_len
    ret
.rshift:
    mov rdx, rshift_str
    mov rcx, rshift_len
    ret
.comment:
    mov rdx, comment_str
    mov rcx, comment_len
    ret
.whitespace:
    mov rdx, whitespace_str
    mov rcx, whitespace_len
    ret
.newline:
    mov rdx, newline_str
    mov rcx, newline_len
    ret
.error:
    mov rdx, error_str
    mov rcx, error_len
    ret

; Print a string
; Input: rdi = pointer to string, rsi = string length
print_string:
    push rax
    push rdx
    push rcx
    
    mov rax, 1      ; syscall number for write
    mov rdx, rsi    ; string length
    mov rsi, rdi    ; string pointer
    mov rdi, 1      ; file descriptor (stdout)
    syscall
    
    pop rcx
    pop rdx
    pop rax
    ret

; Test a single source string
; Input: rdi = pointer to source, rsi = source length
test_source:
    push rbx
    push r12
    push r13
    push r14
    
    ; Initialize lexer
    call lexer_init
    mov r12, rdi    ; Save source pointer for display
    mov r13, rsi    ; Save source length
    
    ; Print source code
    call print_string
    mov rdi, msg_newline
    mov rsi, 1
    call print_string
    
.token_loop:
    call lexer_get_next_token
    mov r14, rax    ; Save token type
    
    cmp rax, TOKEN_EOF
    je .done
    cmp rax, TOKEN_ERROR
    je .error
    
    ; Print token type
    mov rdi, msg_token_type
    mov rsi, 12
    call print_string
    
    call token_type_to_string
    mov rdi, rdx
    mov rsi, rcx
    call print_string
    
    ; Print token value if it exists
    cmp rdx, 0
    je .no_value
    
    mov rdi, msg_token_value
    mov rsi, 7
    call print_string
    
    ; Copy token value to display buffer
    mov rdi, token_display
    mov rsi, rdx
    mov rcx, rcx
    rep movsb
    mov byte [rdi], 0
    
    mov rdi, token_display
    mov rsi, rcx
    call print_string
    
.no_value:
    mov rdi, msg_newline
    mov rsi, 1
    call print_string
    
    jmp .token_loop

.error:
    mov rdi, msg_token_type
    mov rsi, 12
    call print_string
    
    call token_type_to_string
    mov rdi, rdx
    mov rsi, rcx
    call print_string
    
    mov rdi, msg_newline
    mov rsi, 1
    call print_string

.done:
    mov rdi, msg_separator
    mov rsi, 4
    call print_string
    
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Main entry point
_start:
    ; Print test header
    mov rdi, msg_test_start
    mov rsi, 24
    call print_string
    
    ; Test source 1: Function definition
    mov rdi, test_source1
    mov rsi, test_source1_len
    call test_source
    
    ; Test source 2: Model definition
    mov rdi, test_source2
    mov rsi, test_source2_len
    call test_source
    
    ; Test source 3: If-else statement
    mov rdi, test_source3
    mov rsi, test_source3_len
    call test_source
    
    ; Test source 4: Loop statement
    mov rdi, test_source4
    mov rsi, test_source4_len
    call test_source
    
    ; Print completion message
    mov rdi, msg_test_end
    mov rsi, 22
    call print_string
    
    ; Exit
    mov rax, 60     ; syscall number for exit
    xor rdi, rdi    ; exit code 0
    syscall

; Token type strings
section .data
    eof_str db 'EOF', 0
    eof_len equ $ - eof_str - 1
    
    identifier_str db 'IDENTIFIER', 0
    identifier_len equ $ - identifier_str - 1
    
    cnuf_str db 'CNUF (func)', 0
    cnuf_len equ $ - cnuf_str - 1
    
    ledom_str db 'LEDOM (model)', 0
    ledom_len equ $ - ledom_str - 1
    
    pool_str db 'POOL (loop)', 0
    pool_len equ $ - pool_str - 1
    
    fi_str db 'FI (if)', 0
    fi_len equ $ - fi_str - 1
    
    tel_str db 'TEL (let)', 0
    tel_len equ $ - tel_str - 1
    
    ter_str db 'TER (return)', 0
    ter_len equ $ - ter_str - 1
    
    esle_str db 'ESLE (else)', 0
    esle_len equ $ - esle_str - 1
    
    rof_str db 'ROF (for)', 0
    rof_len equ $ - rof_str - 1
    
    elihw_str db 'ELIHW (while)', 0
    elihw_len equ $ - elihw_str - 1
    
    od_str db 'OD (do)', 0
    od_len equ $ - od_str - 1
    
    ni_str db 'NI (in)', 0
    ni_len equ $ - ni_str - 1
    
    ot_str db 'OT (to)', 0
    ot_len equ $ - ot_str - 1
    
    morf_str db 'MORF (from)', 0
    morf_len equ $ - morf_str - 1
    
    na_str db 'NA (and)', 0
    na_len equ $ - na_str - 1
    
    ro_str db 'RO (or)', 0
    ro_len equ $ - ro_str - 1
    
    ton_str db 'TON (not)', 0
    ton_len equ $ - ton_str - 1
    
    eurt_str db 'EURT (true)', 0
    eurt_len equ $ - eurt_str - 1
    
    eslaf_str db 'ESLAF (false)', 0
    eslaf_len equ $ - eslaf_str - 1
    
    tni_str db 'TNI (int)', 0
    tni_len equ $ - tni_str - 1
    
    gnirts_str db 'GNIRTS (string)', 0
    gnirts_len equ $ - gnirts_str - 1
    
    loob_str db 'LOOB (bool)', 0
    loob_len equ $ - loob_str - 1
    
    laer_str db 'LAER (real)', 0
    laer_len equ $ - laer_str - 1
    
    literal_int_str db 'LITERAL_INT', 0
    literal_int_len equ $ - literal_int_str - 1
    
    literal_string_str db 'LITERAL_STRING', 0
    literal_string_len equ $ - literal_string_str - 1
    
    literal_real_str db 'LITERAL_REAL', 0
    literal_real_len equ $ - literal_real_str - 1
    
    literal_bool_str db 'LITERAL_BOOL', 0
    literal_bool_len equ $ - literal_bool_str - 1
    
    lbrace_str db 'LBRACE ({)', 0
    lbrace_len equ $ - lbrace_str - 1
    
    rbrace_str db 'RBRACE (})', 0
    rbrace_len equ $ - rbrace_str - 1
    
    lparen_str db 'LPAREN (())', 0
    lparen_len equ $ - lparen_str - 1
    
    rparen_str db 'RPAREN ())', 0
    rparen_len equ $ - rparen_str - 1
    
    lbracket_str db 'LBRACKET ([)', 0
    lbracket_len equ $ - lbracket_str - 1
    
    rbracket_str db 'RBRACKET (])', 0
    rbracket_len equ $ - rbracket_str - 1
    
    eq_str db 'EQ (=)', 0
    eq_len equ $ - eq_str - 1
    
    gt_str db 'GT (>)', 0
    gt_len equ $ - gt_str - 1
    
    lt_str db 'LT (<)', 0
    lt_len equ $ - lt_str - 1
    
    ge_str db 'GE (>=)', 0
    ge_len equ $ - ge_str - 1
    
    le_str db 'LE (<=)', 0
    le_len equ $ - le_str - 1
    
    ne_str db 'NE (!=)', 0
    ne_len equ $ - ne_str - 1
    
    eqeq_str db 'EQEQ (==)', 0
    eqeq_len equ $ - eqeq_str - 1
    
    arrow_str db 'ARROW (->)', 0
    arrow_len equ $ - arrow_str - 1
    
    colon_str db 'COLON (:)', 0
    colon_len equ $ - colon_str - 1
    
    comma_str db 'COMMA (,)', 0
    comma_len equ $ - comma_str - 1
    
    semicolon_str db 'SEMICOLON (;)', 0
    semicolon_len equ $ - semicolon_str - 1
    
    dot_str db 'DOT (.)', 0
    dot_len equ $ - dot_str - 1
    
    plus_str db 'PLUS (+)', 0
    plus_len equ $ - plus_str - 1
    
    minus_str db 'MINUS (-)', 0
    minus_len equ $ - minus_str - 1
    
    multiply_str db 'MULTIPLY (*)', 0
    multiply_len equ $ - multiply_str - 1
    
    divide_str db 'DIVIDE (/)', 0
    divide_len equ $ - divide_str - 1
    
    modulo_str db 'MODULO (%)', 0
    modulo_len equ $ - modulo_str - 1
    
    plusplus_str db 'PLUSPLUS (++)', 0
    plusplus_len equ $ - plusplus_str - 1
    
    minusminus_str db 'MINUSMINUS (--)', 0
    minusminus_len equ $ - minusminus_str - 1
    
    pluseq_str db 'PLUSEQ (+=)', 0
    pluseq_len equ $ - pluseq_str - 1
    
    minuseq_str db 'MINUSEQ (-=)', 0
    minuseq_len equ $ - minuseq_str - 1
    
    multeq_str db 'MULTEQ (*=)', 0
    multeq_len equ $ - multeq_str - 1
    
    diveq_str db 'DIVEQ (/=)', 0
    diveq_len equ $ - diveq_str - 1
    
    modeq_str db 'MODEQ (%=)', 0
    modeq_len equ $ - modeq_str - 1
    
    and_str db 'AND (&&)', 0
    and_len equ $ - and_str - 1
    
    or_str db 'OR (||)', 0
    or_len equ $ - or_str - 1
    
    not_str db 'NOT (!)', 0
    not_len equ $ - not_str - 1
    
    question_str db 'QUESTION (?)', 0
    question_len equ $ - question_str - 1
    
    pipe_str db 'PIPE (|)', 0
    pipe_len equ $ - pipe_str - 1
    
    ampersand_str db 'AMPERSAND (&)', 0
    ampersand_len equ $ - ampersand_str - 1
    
    caret_str db 'CARET (^)', 0
    caret_len equ $ - caret_str - 1
    
    tilde_str db 'TILDE (~)', 0
    tilde_len equ $ - tilde_str - 1
    
    lshift_str db 'LSHIFT (<<)', 0
    lshift_len equ $ - lshift_str - 1
    
    rshift_str db 'RSHIFT (>>)', 0
    rshift_len equ $ - rshift_str - 1
    
    comment_str db 'COMMENT', 0
    comment_len equ $ - comment_str - 1
    
    whitespace_str db 'WHITESPACE', 0
    whitespace_len equ $ - whitespace_str - 1
    
    newline_str db 'NEWLINE', 0
    newline_len equ $ - newline_str - 1
    
    error_str db 'ERROR', 0
    error_len equ $ - error_str - 1
    
    unknown_token_str db 'UNKNOWN', 0
    unknown_token_len equ $ - unknown_token_str - 1
