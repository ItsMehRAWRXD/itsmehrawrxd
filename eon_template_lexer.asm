; eon_template_lexer.asm
; Lexer for Eon Template (.eont) files
; Handles template syntax with placeholders, control structures, and comments

section .data
    ; Template token types
    %define TEMPLATE_TOKEN_TEXT          1
    %define TEMPLATE_TOKEN_PLACEHOLDER   2
    %define TEMPLATE_TOKEN_IF            3
    %define TEMPLATE_TOKEN_ELSE          4
    %define TEMPLATE_TOKEN_ENDIF         5
    %define TEMPLATE_TOKEN_FOR           6
    %define TEMPLATE_TOKEN_ENDFOR        7
    %define TEMPLATE_TOKEN_EACH          8
    %define TEMPLATE_TOKEN_COMMENT       9
    %define TEMPLATE_TOKEN_EOF           10
    %define TEMPLATE_TOKEN_ERROR         11

    ; Template syntax patterns
    placeholder_start     db "{{", 0
    placeholder_end       db "}}", 0
    control_start         db "{%", 0
    control_end           db "%}", 0
    comment_start         db "{#", 0
    comment_end           db "#}", 0
    
    ; Control keywords
    if_keyword            db "if", 0
    else_keyword          db "else", 0
    endif_keyword         db "endif", 0
    for_keyword           db "for", 0
    endfor_keyword        db "endfor", 0
    each_keyword          db "each", 0

section .bss
    template_source       resq 1      ; Pointer to template source
    template_pos          resq 1      ; Current position in source
    template_len          resq 1      ; Length of source
    current_token         resb 32     ; Current token buffer
    token_type            resq 1      ; Current token type
    token_value           resq 1      ; Pointer to token value
    line_number           resq 1      ; Current line number
    column_number         resq 1      ; Current column number

section .text
    global template_lexer_init
    global template_lexer_next
    global template_lexer_get_token
    global template_lexer_get_value

; Initialize template lexer with source
; Args: rdi = source pointer, rsi = source length
template_lexer_init:
    mov     qword [template_source], rdi
    mov     qword [template_pos], 0
    mov     qword [template_len], rsi
    mov     qword [line_number], 1
    mov     qword [column_number], 1
    ret

; Get next token from template source
template_lexer_next:
    push    rbx
    push    rcx
    push    rdx
    
    ; Check if we've reached end of source
    mov     rax, qword [template_pos]
    cmp     rax, qword [template_len]
    jge     .eof_reached
    
    ; Get current character
    mov     rbx, qword [template_source]
    mov     al, byte [rbx + rax]
    
    ; Check for template syntax patterns
    call    check_placeholder_start
    cmp     rax, 1
    je      .parse_placeholder
    
    call    check_control_start
    cmp     rax, 1
    je      .parse_control
    
    call    check_comment_start
    cmp     rax, 1
    je      .parse_comment
    
    ; Regular text token
    call    parse_text_token
    jmp     .done
    
.parse_placeholder:
    call    parse_placeholder_token
    jmp     .done
    
.parse_control:
    call    parse_control_token
    jmp     .done
    
.parse_comment:
    call    parse_comment_token
    jmp     .done
    
.eof_reached:
    mov     qword [token_type], TEMPLATE_TOKEN_EOF
    mov     qword [token_value], 0
    jmp     .done
    
.done:
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Check if current position starts a placeholder
check_placeholder_start:
    mov     rax, qword [template_pos]
    mov     rbx, qword [template_source]
    mov     rcx, qword [template_len]
    
    ; Check if we have at least 2 characters
    add     rax, 2
    cmp     rax, rcx
    jg      .no_match
    
    ; Check for "{{"
    mov     al, byte [rbx + rax - 2]
    cmp     al, '{'
    jne     .no_match
    mov     al, byte [rbx + rax - 1]
    cmp     al, '{'
    jne     .no_match
    
    mov     rax, 1
    ret
.no_match:
    mov     rax, 0
    ret

; Check if current position starts a control structure
check_control_start:
    mov     rax, qword [template_pos]
    mov     rbx, qword [template_source]
    mov     rcx, qword [template_len]
    
    ; Check if we have at least 2 characters
    add     rax, 2
    cmp     rax, rcx
    jg      .no_match
    
    ; Check for "{%"
    mov     al, byte [rbx + rax - 2]
    cmp     al, '{'
    jne     .no_match
    mov     al, byte [rbx + rax - 1]
    cmp     al, '%'
    jne     .no_match
    
    mov     rax, 1
    ret
.no_match:
    mov     rax, 0
    ret

; Check if current position starts a comment
check_comment_start:
    mov     rax, qword [template_pos]
    mov     rbx, qword [template_source]
    mov     rcx, qword [template_len]
    
    ; Check if we have at least 2 characters
    add     rax, 2
    cmp     rax, rcx
    jg      .no_match
    
    ; Check for "{#"
    mov     al, byte [rbx + rax - 2]
    cmp     al, '{'
    jne     .no_match
    mov     al, byte [rbx + rax - 1]
    cmp     al, '#'
    jne     .no_match
    
    mov     rax, 1
    ret
.no_match:
    mov     rax, 0
    ret

; Parse a text token (regular content)
parse_text_token:
    push    rbx
    push    rcx
    push    rdx
    
    mov     rax, qword [template_pos]
    mov     rbx, qword [template_source]
    mov     rcx, qword [template_len]
    mov     rdx, rax  ; Start position
    
    ; Find end of text (next template syntax or EOF)
.text_loop:
    cmp     rax, rcx
    jge     .text_end
    
    ; Check for template syntax
    call    check_placeholder_start
    cmp     rax, 1
    je      .text_end
    
    call    check_control_start
    cmp     rax, 1
    je      .text_end
    
    call    check_comment_start
    cmp     rax, 1
    je      .text_end
    
    ; Move to next character
    inc     rax
    jmp     .text_loop
    
.text_end:
    ; Set token type and value
    mov     qword [token_type], TEMPLATE_TOKEN_TEXT
    mov     qword [token_value], rdx  ; Start position
    mov     qword [template_pos], rax ; Update position
    
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Parse a placeholder token
parse_placeholder_token:
    push    rbx
    push    rcx
    push    rdx
    
    ; Skip "{{"
    mov     rax, qword [template_pos]
    add     rax, 2
    mov     qword [template_pos], rax
    
    mov     rbx, qword [template_source]
    mov     rcx, qword [template_len]
    mov     rdx, rax  ; Start of placeholder content
    
    ; Find closing "}}"
.placeholder_loop:
    cmp     rax, rcx
    jge     .placeholder_error
    
    ; Check for "}}"
    mov     al, byte [rbx + rax]
    cmp     al, '}'
    jne     .next_char
    
    ; Check next character
    inc     rax
    cmp     rax, rcx
    jge     .placeholder_error
    
    mov     al, byte [rbx + rax]
    cmp     al, '}'
    je      .placeholder_end
    
    ; Not closing brace, continue
    dec     rax
.next_char:
    inc     rax
    jmp     .placeholder_loop
    
.placeholder_end:
    ; Set token type and value
    mov     qword [token_type], TEMPLATE_TOKEN_PLACEHOLDER
    mov     qword [token_value], rdx  ; Start of content
    add     rax, 2  ; Skip "}}"
    mov     qword [template_pos], rax
    
    pop     rdx
    pop     rcx
    pop     rbx
    ret
    
.placeholder_error:
    mov     qword [token_type], TEMPLATE_TOKEN_ERROR
    mov     qword [token_value], 0
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Parse a control token
parse_control_token:
    push    rbx
    push    rcx
    push    rdx
    
    ; Skip "{%"
    mov     rax, qword [template_pos]
    add     rax, 2
    mov     qword [template_pos], rax
    
    mov     rbx, qword [template_source]
    mov     rcx, qword [template_len]
    mov     rdx, rax  ; Start of control content
    
    ; Find closing "%}"
.control_loop:
    cmp     rax, rcx
    jge     .control_error
    
    ; Check for "%}"
    mov     al, byte [rbx + rax]
    cmp     al, '%'
    jne     .next_char
    
    ; Check next character
    inc     rax
    cmp     rax, rcx
    jge     .control_error
    
    mov     al, byte [rbx + rax]
    cmp     al, '}'
    je      .control_end
    
    ; Not closing brace, continue
    dec     rax
.next_char:
    inc     rax
    jmp     .control_loop
    
.control_end:
    ; Parse control keyword
    call    parse_control_keyword
    add     rax, 2  ; Skip "%}"
    mov     qword [template_pos], rax
    
    pop     rdx
    pop     rcx
    pop     rbx
    ret
    
.control_error:
    mov     qword [token_type], TEMPLATE_TOKEN_ERROR
    mov     qword [token_value], 0
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Parse control keyword and set appropriate token type
parse_control_keyword:
    push    rbx
    push    rcx
    push    rdx
    
    mov     rbx, qword [template_source]
    mov     rcx, qword [template_pos]
    
    ; Skip whitespace
.skip_whitespace:
    mov     al, byte [rbx + rcx]
    cmp     al, ' '
    je      .skip_space
    cmp     al, '\t'
    je      .skip_space
    cmp     al, '\n'
    je      .skip_space
    cmp     al, '\r'
    je      .skip_space
    jmp     .check_keyword
    
.skip_space:
    inc     rcx
    jmp     .skip_whitespace
    
.check_keyword:
    ; Check for "if"
    call    check_keyword_match
    cmp     rax, 1
    je      .set_if_token
    
    ; Check for "else"
    call    check_keyword_match
    cmp     rax, 1
    je      .set_else_token
    
    ; Check for "endif"
    call    check_keyword_match
    cmp     rax, 1
    je      .set_endif_token
    
    ; Check for "for"
    call    check_keyword_match
    cmp     rax, 1
    je      .set_for_token
    
    ; Check for "endfor"
    call    check_keyword_match
    cmp     rax, 1
    je      .set_endfor_token
    
    ; Check for "each"
    call    check_keyword_match
    cmp     rax, 1
    je      .set_each_token
    
    ; Unknown keyword
    mov     qword [token_type], TEMPLATE_TOKEN_ERROR
    jmp     .done
    
.set_if_token:
    mov     qword [token_type], TEMPLATE_TOKEN_IF
    jmp     .done
    
.set_else_token:
    mov     qword [token_type], TEMPLATE_TOKEN_ELSE
    jmp     .done
    
.set_endif_token:
    mov     qword [token_type], TEMPLATE_TOKEN_ENDIF
    jmp     .done
    
.set_for_token:
    mov     qword [token_type], TEMPLATE_TOKEN_FOR
    jmp     .done
    
.set_endfor_token:
    mov     qword [token_type], TEMPLATE_TOKEN_ENDFOR
    jmp     .done
    
.set_each_token:
    mov     qword [token_type], TEMPLATE_TOKEN_EACH
    jmp     .done
    
.done:
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Parse a comment token
parse_comment_token:
    push    rbx
    push    rcx
    push    rdx
    
    ; Skip "{#"
    mov     rax, qword [template_pos]
    add     rax, 2
    mov     qword [template_pos], rax
    
    mov     rbx, qword [template_source]
    mov     rcx, qword [template_len]
    
    ; Find closing "#}"
.comment_loop:
    cmp     rax, rcx
    jge     .comment_error
    
    ; Check for "#}"
    mov     al, byte [rbx + rax]
    cmp     al, '#'
    jne     .next_char
    
    ; Check next character
    inc     rax
    cmp     rax, rcx
    jge     .comment_error
    
    mov     al, byte [rbx + rax]
    cmp     al, '}'
    je      .comment_end
    
    ; Not closing brace, continue
    dec     rax
.next_char:
    inc     rax
    jmp     .comment_loop
    
.comment_end:
    ; Set token type (comments are ignored)
    mov     qword [token_type], TEMPLATE_TOKEN_COMMENT
    mov     qword [token_value], 0
    add     rax, 2  ; Skip "#}"
    mov     qword [template_pos], rax
    
    pop     rdx
    pop     rcx
    pop     rbx
    ret
    
.comment_error:
    mov     qword [token_type], TEMPLATE_TOKEN_ERROR
    mov     qword [token_value], 0
    pop     rdx
    pop     rcx
    pop     rbx
    ret

; Get current token type
template_lexer_get_token:
    mov     rax, qword [token_type]
    ret

; Get current token value
template_lexer_get_value:
    mov     rax, qword [token_value]
    ret
