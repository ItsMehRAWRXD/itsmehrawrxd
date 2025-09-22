; error_handling.asm
; Robust error handling and recovery mechanisms for compiler stages
; Provides comprehensive error reporting, recovery, and diagnostics

section .data
    ; Error severity levels
    ERROR_INFO     equ 0
    ERROR_WARNING  equ 1
    ERROR_ERROR    equ 2
    ERROR_FATAL    equ 3
    
    ; Error categories
    ERROR_LEXICAL    equ 0
    ERROR_SYNTAX     equ 1
    ERROR_SEMANTIC   equ 2
    ERROR_CODEGEN    equ 3
    ERROR_LINKER     equ 4
    ERROR_RUNTIME    equ 5
    
    ; Error codes
    ERR_UNEXPECTED_CHAR      equ 1000
    ERR_UNTERMINATED_STRING  equ 1001
    ERR_INVALID_NUMBER       equ 1002
    ERR_UNEXPECTED_TOKEN     equ 2000
    ERR_MISSING_SEMICOLON    equ 2001
    ERR_MISSING_BRACE        equ 2002
    ERR_INVALID_EXPRESSION   equ 2003
    ERR_UNDEFINED_IDENTIFIER equ 3000
    ERR_TYPE_MISMATCH        equ 3001
    ERR_REDEFINED_SYMBOL     equ 3002
    ERR_INVALID_ASSIGNMENT   equ 3003
    ERR_CODEGEN_FAILURE      equ 4000
    ERR_REGISTER_SPILL       equ 4001
    ERR_UNRESOLVED_SYMBOL    equ 5000
    ERR_MEMORY_FAULT         equ 6000
    ERR_STACK_OVERFLOW       equ 6001
    
    ; Error messages
    msg_unexpected_char      db "Unexpected character", 0
    msg_unterminated_string  db "Unterminated string literal", 0
    msg_invalid_number       db "Invalid number format", 0
    msg_unexpected_token     db "Unexpected token", 0
    msg_missing_semicolon    db "Missing semicolon", 0
    msg_missing_brace        db "Missing closing brace", 0
    msg_invalid_expression   db "Invalid expression", 0
    msg_undefined_identifier db "Undefined identifier", 0
    msg_type_mismatch        db "Type mismatch", 0
    msg_redefined_symbol     db "Symbol already defined", 0
    msg_invalid_assignment   db "Invalid assignment", 0
    msg_codegen_failure      db "Code generation failed", 0
    msg_register_spill       db "Register allocation failed", 0
    msg_unresolved_symbol    db "Unresolved symbol", 0
    msg_memory_fault         db "Memory access fault", 0
    msg_stack_overflow       db "Stack overflow", 0
    
    ; Error message table
    error_messages:
        dq ERR_UNEXPECTED_CHAR,      msg_unexpected_char
        dq ERR_UNTERMINATED_STRING,  msg_unterminated_string
        dq ERR_INVALID_NUMBER,       msg_invalid_number
        dq ERR_UNEXPECTED_TOKEN,     msg_unexpected_token
        dq ERR_MISSING_SEMICOLON,    msg_missing_semicolon
        dq ERR_MISSING_BRACE,        msg_missing_brace
        dq ERR_INVALID_EXPRESSION,   msg_invalid_expression
        dq ERR_UNDEFINED_IDENTIFIER, msg_undefined_identifier
        dq ERR_TYPE_MISMATCH,        msg_type_mismatch
        dq ERR_REDEFINED_SYMBOL,     msg_redefined_symbol
        dq ERR_INVALID_ASSIGNMENT,   msg_invalid_assignment
        dq ERR_CODEGEN_FAILURE,      msg_codegen_failure
        dq ERR_REGISTER_SPILL,       msg_register_spill
        dq ERR_UNRESOLVED_SYMBOL,    msg_unresolved_symbol
        dq ERR_MEMORY_FAULT,         msg_memory_fault
        dq ERR_STACK_OVERFLOW,       msg_stack_overflow
        dq 0, 0  ; End marker
    
    ; Color codes for terminal output
    color_reset    db 27, "[0m", 0
    color_red      db 27, "[31m", 0
    color_yellow   db 27, "[33m", 0
    color_blue     db 27, "[34m", 0
    color_green    db 27, "[32m", 0
    color_bold     db 27, "[1m", 0

section .bss
    ; Error context stack
    error_contexts     resb 4096   ; Stack of error contexts
    context_stack_ptr  resq 1      ; Current context stack pointer
    
    ; Error list
    error_list         resb 8192   ; Array of error records
    error_count        resq 1      ; Number of errors
    max_errors         resq 1      ; Maximum errors before stopping
    
    ; Error recovery state
    recovery_tokens    resb 256    ; Tokens for recovery
    recovery_count     resq 1      ; Number of recovery tokens
    
    ; Current error context
    current_filename   resq 1      ; Current source filename
    current_line       resq 1      ; Current line number
    current_column     resq 1      ; Current column number
    
    ; Error statistics
    info_count         resq 1
    warning_count      resq 1
    error_count_total  resq 1
    fatal_count        resq 1

section .text
    global error_init
    global error_push_context
    global error_pop_context
    global error_set_location
    global error_report
    global error_report_with_suggestion
    global error_recover
    global error_print_summary
    global error_has_errors
    global error_get_count
    global error_clear_all

; Error record structure (64 bytes)
; [0-7]:   Error code
; [8-15]:  Severity level
; [16-23]: Category
; [24-31]: Line number
; [32-39]: Column number
; [40-47]: Filename pointer
; [48-55]: Message pointer
; [56-63]: Suggestion pointer

; Error context structure (32 bytes)
; [0-7]:   Filename pointer
; [8-15]:  Line number
; [16-23]: Column number
; [24-31]: Stage identifier

; Initialize error handling system
error_init:
    push rbx
    push rcx
    
    ; Initialize counters
    mov qword [error_count], 0
    mov qword [max_errors], 100
    mov qword [recovery_count], 0
    mov qword [info_count], 0
    mov qword [warning_count], 0
    mov qword [error_count_total], 0
    mov qword [fatal_count], 0
    
    ; Initialize context stack
    mov qword [context_stack_ptr], error_contexts
    
    ; Initialize current location
    mov qword [current_filename], 0
    mov qword [current_line], 1
    mov qword [current_column], 1
    
    ; Set up default recovery tokens
    call setup_recovery_tokens
    
    pop rcx
    pop rbx
    ret

; Push error context onto stack
; Input: rdi = filename, rsi = line, rdx = column, rcx = stage
error_push_context:
    push rbx
    push r8
    
    ; Get current context stack position
    mov rbx, [context_stack_ptr]
    
    ; Store context
    mov [rbx], rdi      ; Filename
    mov [rbx + 8], rsi  ; Line
    mov [rbx + 16], rdx ; Column
    mov [rbx + 24], rcx ; Stage
    
    ; Move stack pointer
    add rbx, 32
    mov [context_stack_ptr], rbx
    
    ; Update current location
    mov [current_filename], rdi
    mov [current_line], rsi
    mov [current_column], rdx
    
    pop r8
    pop rbx
    ret

; Pop error context from stack
error_pop_context:
    push rbx
    
    ; Check if stack is not empty
    mov rbx, [context_stack_ptr]
    cmp rbx, error_contexts
    jle .stack_empty
    
    ; Move stack pointer back
    sub rbx, 32
    mov [context_stack_ptr], rbx
    
    ; Restore current location from previous context
    cmp rbx, error_contexts
    je .no_previous
    
    sub rbx, 32
    mov rax, [rbx]
    mov [current_filename], rax
    mov rax, [rbx + 8]
    mov [current_line], rax
    mov rax, [rbx + 16]
    mov [current_column], rax
    add rbx, 32
    jmp .return

.no_previous:
    mov qword [current_filename], 0
    mov qword [current_line], 1
    mov qword [current_column], 1
    jmp .return

.stack_empty:
    ; Stack underflow - this is a bug
    mov rdi, ERR_STACK_OVERFLOW
    mov rsi, ERROR_FATAL
    mov rdx, ERROR_RUNTIME
    call error_report

.return:
    pop rbx
    ret

; Set current location for error reporting
; Input: rdi = filename, rsi = line, rdx = column
error_set_location:
    mov [current_filename], rdi
    mov [current_line], rsi
    mov [current_column], rdx
    ret

; Report an error
; Input: rdi = error code, rsi = severity, rdx = category
error_report:
    push rbx
    push rcx
    push r8
    push r9
    
    ; Check if we've hit the error limit
    mov rax, [error_count]
    cmp rax, [max_errors]
    jge .too_many_errors
    
    ; Get error record slot
    mov rbx, [error_count]
    imul rbx, 64
    add rbx, error_list
    
    ; Fill error record
    mov [rbx], rdi          ; Error code
    mov [rbx + 8], rsi      ; Severity
    mov [rbx + 16], rdx     ; Category
    mov rax, [current_line]
    mov [rbx + 24], rax     ; Line number
    mov rax, [current_column]
    mov [rbx + 32], rax     ; Column number
    mov rax, [current_filename]
    mov [rbx + 40], rax     ; Filename
    
    ; Get error message
    mov r8, rdi
    call get_error_message
    mov [rbx + 48], rax     ; Message pointer
    mov qword [rbx + 56], 0 ; No suggestion
    
    ; Update counters
    inc qword [error_count]
    
    ; Update severity counters
    cmp rsi, ERROR_INFO
    je .count_info
    cmp rsi, ERROR_WARNING
    je .count_warning
    cmp rsi, ERROR_ERROR
    je .count_error
    cmp rsi, ERROR_FATAL
    je .count_fatal
    jmp .print_error

.count_info:
    inc qword [info_count]
    jmp .print_error

.count_warning:
    inc qword [warning_count]
    jmp .print_error

.count_error:
    inc qword [error_count_total]
    jmp .print_error

.count_fatal:
    inc qword [fatal_count]

.print_error:
    ; Print error immediately
    mov rdi, rbx
    call print_error_record
    
    ; If fatal error, stop compilation
    cmp rsi, ERROR_FATAL
    je .fatal_error
    
    jmp .return

.too_many_errors:
    ; Print message about too many errors
    call print_too_many_errors
    jmp .fatal_error

.fatal_error:
    ; Exit with error code
    mov rax, 60  ; sys_exit
    mov rdi, 1   ; Exit code 1
    syscall

.return:
    pop r9
    pop r8
    pop rcx
    pop rbx
    ret

; Report error with suggestion
; Input: rdi = error code, rsi = severity, rdx = category, rcx = suggestion
error_report_with_suggestion:
    push rbx
    push r8
    push r9
    
    ; Same as error_report but with suggestion
    mov rax, [error_count]
    cmp rax, [max_errors]
    jge .too_many_errors
    
    mov rbx, [error_count]
    imul rbx, 64
    add rbx, error_list
    
    ; Fill error record
    mov [rbx], rdi          ; Error code
    mov [rbx + 8], rsi      ; Severity
    mov [rbx + 16], rdx     ; Category
    mov rax, [current_line]
    mov [rbx + 24], rax     ; Line number
    mov rax, [current_column]
    mov [rbx + 32], rax     ; Column number
    mov rax, [current_filename]
    mov [rbx + 40], rax     ; Filename
    
    ; Get error message
    mov r8, rdi
    call get_error_message
    mov [rbx + 48], rax     ; Message pointer
    mov [rbx + 56], rcx     ; Suggestion pointer
    
    ; Update counters and print
    inc qword [error_count]
    mov rdi, rbx
    call print_error_record
    
    jmp .return

.too_many_errors:
    call print_too_many_errors

.return:
    pop r9
    pop r8
    pop rbx
    ret

; Error recovery mechanism
; Input: rdi = recovery strategy
error_recover:
    push rbx
    push rcx
    push rdx
    
    ; Different recovery strategies
    cmp rdi, 0
    je .skip_to_semicolon
    cmp rdi, 1
    je .skip_to_brace
    cmp rdi, 2
    je .skip_to_statement
    
    jmp .return

.skip_to_semicolon:
    ; Skip tokens until semicolon or EOF
    call skip_to_token_semicolon
    jmp .return

.skip_to_brace:
    ; Skip tokens until closing brace
    call skip_to_token_brace
    jmp .return

.skip_to_statement:
    ; Skip to next statement boundary
    call skip_to_statement_boundary

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Print error summary
error_print_summary:
    push rbx
    push rcx
    push rdx
    
    ; Print header
    mov rdi, color_bold
    call print_string
    mov rdi, summary_header
    call print_string
    mov rdi, color_reset
    call print_string
    
    ; Print counts
    mov rdi, info_count_msg
    call print_string
    mov rdi, [info_count]
    call print_number
    call print_newline
    
    mov rdi, warning_count_msg
    call print_string
    mov rdi, [warning_count]
    call print_number
    call print_newline
    
    mov rdi, error_count_msg
    call print_string
    mov rdi, [error_count_total]
    call print_number
    call print_newline
    
    mov rdi, fatal_count_msg
    call print_string
    mov rdi, [fatal_count]
    call print_number
    call print_newline
    
    ; Print total
    mov rdi, total_count_msg
    call print_string
    mov rdi, [error_count]
    call print_number
    call print_newline
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Check if there are any errors
; Output: rax = 1 if errors, 0 if no errors
error_has_errors:
    mov rax, [error_count_total]
    add rax, [fatal_count]
    cmp rax, 0
    je .no_errors
    mov rax, 1
    ret

.no_errors:
    mov rax, 0
    ret

; Get total error count
; Output: rax = total error count
error_get_count:
    mov rax, [error_count]
    ret

; Clear all errors
error_clear_all:
    mov qword [error_count], 0
    mov qword [info_count], 0
    mov qword [warning_count], 0
    mov qword [error_count_total], 0
    mov qword [fatal_count], 0
    ret

; Get error message for error code
; Input: rdi = error code
; Output: rax = message pointer
get_error_message:
    push rbx
    push rcx
    
    mov rbx, error_messages
.search_loop:
    mov rcx, [rbx]
    cmp rcx, 0
    je .not_found
    cmp rcx, rdi
    je .found
    add rbx, 16
    jmp .search_loop

.found:
    mov rax, [rbx + 8]
    jmp .return

.not_found:
    mov rax, unknown_error_msg

.return:
    pop rcx
    pop rbx
    ret

; Print error record
; Input: rdi = error record pointer
print_error_record:
    push rbx
    push rcx
    push rdx
    push rsi
    
    mov rbx, rdi  ; Save error record
    
    ; Print filename and location
    mov rdi, [rbx + 40]  ; Filename
    cmp rdi, 0
    je .no_filename
    call print_string
    mov rdi, colon_char
    call print_string

.no_filename:
    mov rdi, [rbx + 24]  ; Line number
    call print_number
    mov rdi, colon_char
    call print_string
    mov rdi, [rbx + 32]  ; Column number
    call print_number
    mov rdi, colon_space
    call print_string
    
    ; Print severity with color
    mov rax, [rbx + 8]   ; Severity
    cmp rax, ERROR_FATAL
    je .print_fatal
    cmp rax, ERROR_ERROR
    je .print_error
    cmp rax, ERROR_WARNING
    je .print_warning
    cmp rax, ERROR_INFO
    je .print_info
    jmp .print_message

.print_fatal:
    mov rdi, color_red
    call print_string
    mov rdi, color_bold
    call print_string
    mov rdi, fatal_label
    call print_string
    jmp .print_message

.print_error:
    mov rdi, color_red
    call print_string
    mov rdi, error_label
    call print_string
    jmp .print_message

.print_warning:
    mov rdi, color_yellow
    call print_string
    mov rdi, warning_label
    call print_string
    jmp .print_message

.print_info:
    mov rdi, color_blue
    call print_string
    mov rdi, info_label
    call print_string

.print_message:
    mov rdi, color_reset
    call print_string
    mov rdi, [rbx + 48]  ; Message
    call print_string
    call print_newline
    
    ; Print suggestion if available
    mov rdi, [rbx + 56]  ; Suggestion
    cmp rdi, 0
    je .no_suggestion
    
    mov rdi, color_green
    call print_string
    mov rdi, suggestion_label
    call print_string
    mov rdi, color_reset
    call print_string
    mov rdi, [rbx + 56]
    call print_string
    call print_newline

.no_suggestion:
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; Setup default recovery tokens
setup_recovery_tokens:
    ; TODO: Initialize recovery token list
    ret

; Skip to semicolon for recovery
skip_to_token_semicolon:
    ; TODO: Implement token skipping
    ret

; Skip to brace for recovery
skip_to_token_brace:
    ; TODO: Implement brace skipping
    ret

; Skip to statement boundary
skip_to_statement_boundary:
    ; TODO: Implement statement boundary detection
    ret

; Print string helper
; Input: rdi = string pointer
print_string:
    push rax
    push rdx
    push rcx
    push rsi
    
    mov rsi, rdi
    call string_length
    mov rdx, rax
    
    mov rax, 1      ; sys_write
    mov rdi, 2      ; stderr
    syscall
    
    pop rsi
    pop rcx
    pop rdx
    pop rax
    ret

; Print number helper
; Input: rdi = number
print_number:
    push rax
    push rbx
    push rcx
    push rdx
    
    mov rax, rdi
    mov rbx, 10
    mov rcx, 0
    
    ; Convert to string (reverse)
.convert_loop:
    xor rdx, rdx
    div rbx
    add rdx, '0'
    push rdx
    inc rcx
    test rax, rax
    jnz .convert_loop
    
    ; Print digits
.print_loop:
    pop rax
    mov [temp_digit], al
    mov rdi, temp_digit
    mov rsi, 1
    call print_string_len
    dec rcx
    jnz .print_loop
    
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret

; Print string with length
; Input: rdi = string, rsi = length
print_string_len:
    push rax
    push rdx
    
    mov rax, 1      ; sys_write
    mov rdx, rsi    ; length
    mov rsi, rdi    ; string
    mov rdi, 2      ; stderr
    syscall
    
    pop rdx
    pop rax
    ret

; Print newline
print_newline:
    push rdi
    push rsi
    
    mov rdi, newline_char
    mov rsi, 1
    call print_string_len
    
    pop rsi
    pop rdi
    ret

; Get string length
; Input: rdi = string
; Output: rax = length
string_length:
    push rbx
    push rcx
    
    mov rbx, rdi
    mov rcx, 0
    
.count_loop:
    cmp byte [rbx + rcx], 0
    je .count_done
    inc rcx
    jmp .count_loop

.count_done:
    mov rax, rcx
    
    pop rcx
    pop rbx
    ret

; Print too many errors message
print_too_many_errors:
    mov rdi, color_red
    call print_string
    mov rdi, color_bold
    call print_string
    mov rdi, too_many_errors_msg
    call print_string
    mov rdi, color_reset
    call print_string
    ret

section .data
    ; Labels and messages
    fatal_label        db "fatal error: ", 0
    error_label        db "error: ", 0
    warning_label      db "warning: ", 0
    info_label         db "info: ", 0
    suggestion_label   db "suggestion: ", 0
    
    colon_char         db ":", 0
    colon_space        db ": ", 0
    newline_char       db 10
    
    summary_header     db "Compilation Summary:", 10, 0
    info_count_msg     db "Info messages: ", 0
    warning_count_msg  db "Warnings: ", 0
    error_count_msg    db "Errors: ", 0
    fatal_count_msg    db "Fatal errors: ", 0
    total_count_msg    db "Total issues: ", 0
    
    unknown_error_msg  db "Unknown error", 0
    too_many_errors_msg db "Too many errors, stopping compilation", 10, 0
    
    temp_digit         db 0
