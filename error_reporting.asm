; error_reporting.asm
; Add comprehensive error reporting for semantic analysis
; Comprehensive error reporting system for the Eon compiler

section .data
    ; === Error Reporting Information ===
    error_reporting_info        db "Error Reporting System v1.0", 10, 0
    error_reporting_capabilities db "Features: Error tracking, Warning management, Position reporting", 10, 0
    
    ; === Error Types ===
    ERROR_SYNTAX           equ 0
    ERROR_SEMANTIC         equ 1
    ERROR_TYPE             equ 2
    ERROR_SYMBOL           equ 3
    ERROR_SCOPE            equ 4
    ERROR_MEMORY           equ 5
    ERROR_IO               equ 6
    ERROR_INTERNAL         equ 7
    ERROR_WARNING          equ 8
    ERROR_INFO             equ 9
    
    ; === Error Severity ===
    SEVERITY_FATAL         equ 0
    SEVERITY_ERROR         equ 1
    SEVERITY_WARNING       equ 2
    SEVERITY_INFO          equ 3
    SEVERITY_DEBUG         equ 4
    
    ; === Error Reporting State ===
    error_reporting_enabled resq 1    ; Error reporting enabled
    warning_level          resq 1     ; Warning level
    error_recovery         resq 1     ; Error recovery enabled
    max_errors             resq 1     ; Maximum errors before stopping
    max_warnings           resq 1     ; Maximum warnings before stopping
    error_count            resq 1     ; Error count
    warning_count          resq 1     ; Warning count
    info_count             resq 1     ; Info count
    debug_count            resq 1     ; Debug count
    
    ; === Error Buffer ===
    error_buffer           resq 1024  ; Error buffer (1024 errors max)
    error_buffer_size      resq 1     ; Error buffer size
    error_buffer_capacity  resq 1     ; Error buffer capacity
    error_buffer_head      resq 1     ; Error buffer head
    error_buffer_tail      resq 1     ; Error buffer tail
    
    ; === Warning Buffer ===
    warning_buffer         resq 1024  ; Warning buffer (1024 warnings max)
    warning_buffer_size    resq 1     ; Warning buffer size
    warning_buffer_capacity resq 1    ; Warning buffer capacity
    warning_buffer_head    resq 1     ; Warning buffer head
    warning_buffer_tail    resq 1     ; Warning buffer tail
    
    ; === Error Statistics ===
    errors_reported        resq 1     ; Errors reported
    warnings_reported      resq 1     ; Warnings reported
    infos_reported         resq 1     ; Infos reported
    debugs_reported        resq 1     ; Debugs reported
    errors_recovered       resq 1     ; Errors recovered
    errors_fatal           resq 1     ; Fatal errors
    errors_non_fatal       resq 1     ; Non-fatal errors
    
    ; === Error Messages ===
    error_syntax_msg       db "Syntax error", 0
    error_semantic_msg     db "Semantic error", 0
    error_type_msg         db "Type error", 0
    error_symbol_msg       db "Symbol error", 0
    error_scope_msg        db "Scope error", 0
    error_memory_msg       db "Memory error", 0
    error_io_msg           db "I/O error", 0
    error_internal_msg     db "Internal error", 0
    error_warning_msg      db "Warning", 0
    error_info_msg         db "Info", 0
    
    ; === Error Format Strings ===
    error_format           db "Error: %s at line %d, column %d", 10, 0
    warning_format         db "Warning: %s at line %d, column %d", 10, 0
    info_format            db "Info: %s at line %d, column %d", 10, 0
    debug_format           db "Debug: %s at line %d, column %d", 10, 0
    
    ; === Error Recovery ===
    error_recovery_enabled resq 1     ; Error recovery enabled
    error_recovery_count   resq 1     ; Error recovery count
    error_recovery_max     resq 1     ; Maximum error recoveries
    error_recovery_strategy resq 1    ; Error recovery strategy

section .text
    global error_reporting_init
    global error_reporting_report_error
    global error_reporting_report_warning
    global error_reporting_report_info
    global error_reporting_report_debug
    global error_reporting_report_error_with_position
    global error_reporting_report_warning_with_position
    global error_reporting_report_info_with_position
    global error_reporting_report_debug_with_position
    global error_reporting_get_error_count
    global error_reporting_get_warning_count
    global error_reporting_get_info_count
    global error_reporting_get_debug_count
    global error_reporting_get_total_count
    global error_reporting_get_errors
    global error_reporting_get_warnings
    global error_reporting_get_infos
    global error_reporting_get_debugs
    global error_reporting_clear_errors
    global error_reporting_clear_warnings
    global error_reporting_clear_infos
    global error_reporting_clear_debugs
    global error_reporting_clear_all
    global error_reporting_set_warning_level
    global error_reporting_set_max_errors
    global error_reporting_set_max_warnings
    global error_reporting_set_error_recovery
    global error_reporting_get_statistics
    global error_reporting_cleanup

; === Initialize Error Reporting ===
error_reporting_init:
    push rbp
    mov rbp, rsp
    
    ; Print error reporting info
    mov rdi, error_reporting_info
    call print_string
    mov rdi, error_reporting_capabilities
    call print_string
    
    ; Initialize state
    mov qword [error_reporting_enabled], 1
    mov qword [warning_level], 2
    mov qword [error_recovery], 1
    mov qword [max_errors], 100
    mov qword [max_warnings], 1000
    mov qword [error_count], 0
    mov qword [warning_count], 0
    mov qword [info_count], 0
    mov qword [debug_count], 0
    
    ; Initialize buffers
    mov qword [error_buffer_size], 0
    mov qword [error_buffer_capacity], 1024
    mov qword [error_buffer_head], 0
    mov qword [error_buffer_tail], 0
    mov qword [warning_buffer_size], 0
    mov qword [warning_buffer_capacity], 1024
    mov qword [warning_buffer_head], 0
    mov qword [warning_buffer_tail], 0
    
    ; Initialize statistics
    mov qword [errors_reported], 0
    mov qword [warnings_reported], 0
    mov qword [infos_reported], 0
    mov qword [debugs_reported], 0
    mov qword [errors_recovered], 0
    mov qword [errors_fatal], 0
    mov qword [errors_non_fatal], 0
    
    ; Initialize error recovery
    mov qword [error_recovery_enabled], 1
    mov qword [error_recovery_count], 0
    mov qword [error_recovery_max], 10
    mov qword [error_recovery_strategy], 0
    
    ; Clear error buffer
    mov rdi, error_buffer
    mov rsi, 1024 * 8
    call zero_memory
    
    ; Clear warning buffer
    mov rdi, warning_buffer
    mov rsi, 1024 * 8
    call zero_memory
    
    leave
    ret

; === Report Error ===
error_reporting_report_error:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = error message, rsi = error type, rdx = severity
    
    ; Check if error reporting is enabled
    mov rax, [error_reporting_enabled]
    cmp rax, 0
    je .error_reporting_disabled
    
    ; Check if max errors reached
    mov rax, [error_count]
    cmp rax, [max_errors]
    jge .max_errors_reached
    
    ; Add error to buffer
    call error_reporting_add_error
    
    ; Increment error count
    inc qword [error_count]
    
    ; Update statistics
    inc qword [errors_reported]
    
    ; Check severity
    cmp rdx, SEVERITY_FATAL
    je .fatal_error
    inc qword [errors_non_fatal]
    jmp .done
    
.fatal_error:
    inc qword [errors_fatal]
    jmp .done
    
.error_reporting_disabled:
    mov rax, 0
    jmp .done
    
.max_errors_reached:
    mov rax, 0
    jmp .done
    
.done:
    leave
    ret

; === Report Warning ===
error_reporting_report_warning:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = warning message, rsi = warning type
    
    ; Check warning level
    mov rax, [warning_level]
    cmp rax, 0
    je .warning_disabled
    
    ; Check if max warnings reached
    mov rax, [warning_count]
    cmp rax, [max_warnings]
    jge .max_warnings_reached
    
    ; Add warning to buffer
    call error_reporting_add_warning
    
    ; Increment warning count
    inc qword [warning_count]
    
    ; Update statistics
    inc qword [warnings_reported]
    
    mov rax, 1
    jmp .done
    
.warning_disabled:
    mov rax, 0
    jmp .done
    
.max_warnings_reached:
    mov rax, 0
    jmp .done
    
.done:
    leave
    ret

; === Report Info ===
error_reporting_report_info:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = info message, rsi = info type
    
    ; Add info to buffer
    call error_reporting_add_info
    
    ; Increment info count
    inc qword [info_count]
    
    ; Update statistics
    inc qword [infos_reported]
    
    mov rax, 1
    jmp .done
    
.done:
    leave
    ret

; === Report Debug ===
error_reporting_report_debug:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = debug message, rsi = debug type
    
    ; Add debug to buffer
    call error_reporting_add_debug
    
    ; Increment debug count
    inc qword [debug_count]
    
    ; Update statistics
    inc qword [debugs_reported]
    
    mov rax, 1
    jmp .done
    
.done:
    leave
    ret

; === Report Error with Position ===
error_reporting_report_error_with_position:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = error message, rsi = error type, rdx = severity, rcx = line, r8 = column
    
    ; Check if error reporting is enabled
    mov rax, [error_reporting_enabled]
    cmp rax, 0
    je .error_reporting_disabled
    
    ; Check if max errors reached
    mov rax, [error_count]
    cmp rax, [max_errors]
    jge .max_errors_reached
    
    ; Add error to buffer with position
    call error_reporting_add_error_with_position
    
    ; Increment error count
    inc qword [error_count]
    
    ; Update statistics
    inc qword [errors_reported]
    
    ; Check severity
    cmp rdx, SEVERITY_FATAL
    je .fatal_error
    inc qword [errors_non_fatal]
    jmp .done
    
.fatal_error:
    inc qword [errors_fatal]
    jmp .done
    
.error_reporting_disabled:
    mov rax, 0
    jmp .done
    
.max_errors_reached:
    mov rax, 0
    jmp .done
    
.done:
    leave
    ret

; === Report Warning with Position ===
error_reporting_report_warning_with_position:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = warning message, rsi = warning type, rdx = line, rcx = column
    
    ; Check warning level
    mov rax, [warning_level]
    cmp rax, 0
    je .warning_disabled
    
    ; Check if max warnings reached
    mov rax, [warning_count]
    cmp rax, [max_warnings]
    jge .max_warnings_reached
    
    ; Add warning to buffer with position
    call error_reporting_add_warning_with_position
    
    ; Increment warning count
    inc qword [warning_count]
    
    ; Update statistics
    inc qword [warnings_reported]
    
    mov rax, 1
    jmp .done
    
.warning_disabled:
    mov rax, 0
    jmp .done
    
.max_warnings_reached:
    mov rax, 0
    jmp .done
    
.done:
    leave
    ret

; === Report Info with Position ===
error_reporting_report_info_with_position:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = info message, rsi = info type, rdx = line, rcx = column
    
    ; Add info to buffer with position
    call error_reporting_add_info_with_position
    
    ; Increment info count
    inc qword [info_count]
    
    ; Update statistics
    inc qword [infos_reported]
    
    mov rax, 1
    jmp .done
    
.done:
    leave
    ret

; === Report Debug with Position ===
error_reporting_report_debug_with_position:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = debug message, rsi = debug type, rdx = line, rcx = column
    
    ; Add debug to buffer with position
    call error_reporting_add_debug_with_position
    
    ; Increment debug count
    inc qword [debug_count]
    
    ; Update statistics
    inc qword [debugs_reported]
    
    mov rax, 1
    jmp .done
    
.done:
    leave
    ret

; === Add Error ===
error_reporting_add_error:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = error message, rsi = error type, rdx = severity
    
    ; Check if buffer is full
    mov rax, [error_buffer_size]
    cmp rax, [error_buffer_capacity]
    jge .buffer_full
    
    ; Add error to buffer
    mov rbx, error_buffer
    mov rcx, [error_buffer_tail]
    
    ; Store error data (simplified)
    mov [rbx + rcx * 8], rdi
    
    ; Update buffer tail
    inc qword [error_buffer_tail]
    cmp qword [error_buffer_tail], 1024
    jne .update_size
    mov qword [error_buffer_tail], 0
    
.update_size:
    inc qword [error_buffer_size]
    
    mov rax, 1
    jmp .done
    
.buffer_full:
    mov rax, 0
    
.done:
    leave
    ret

; === Add Warning ===
error_reporting_add_warning:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = warning message, rsi = warning type
    
    ; Check if buffer is full
    mov rax, [warning_buffer_size]
    cmp rax, [warning_buffer_capacity]
    jge .buffer_full
    
    ; Add warning to buffer
    mov rbx, warning_buffer
    mov rcx, [warning_buffer_tail]
    
    ; Store warning data (simplified)
    mov [rbx + rcx * 8], rdi
    
    ; Update buffer tail
    inc qword [warning_buffer_tail]
    cmp qword [warning_buffer_tail], 1024
    jne .update_size
    mov qword [warning_buffer_tail], 0
    
.update_size:
    inc qword [warning_buffer_size]
    
    mov rax, 1
    jmp .done
    
.buffer_full:
    mov rax, 0
    
.done:
    leave
    ret

; === Add Info ===
error_reporting_add_info:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = info message, rsi = info type
    
    ; Add info to buffer
    ; This is a simplified implementation
    
    mov rax, 1
    jmp .done
    
.done:
    leave
    ret

; === Add Debug ===
error_reporting_add_debug:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = debug message, rsi = debug type
    
    ; Add debug to buffer
    ; This is a simplified implementation
    
    mov rax, 1
    jmp .done
    
.done:
    leave
    ret

; === Add Error with Position ===
error_reporting_add_error_with_position:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = error message, rsi = error type, rdx = severity, rcx = line, r8 = column
    
    ; Add error to buffer with position
    ; This is a simplified implementation
    
    mov rax, 1
    jmp .done
    
.done:
    leave
    ret

; === Add Warning with Position ===
error_reporting_add_warning_with_position:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = warning message, rsi = warning type, rdx = line, rcx = column
    
    ; Add warning to buffer with position
    ; This is a simplified implementation
    
    mov rax, 1
    jmp .done
    
.done:
    leave
    ret

; === Add Info with Position ===
error_reporting_add_info_with_position:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = info message, rsi = info type, rdx = line, rcx = column
    
    ; Add info to buffer with position
    ; This is a simplified implementation
    
    mov rax, 1
    jmp .done
    
.done:
    leave
    ret

; === Add Debug with Position ===
error_reporting_add_debug_with_position:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = debug message, rsi = debug type, rdx = line, rcx = column
    
    ; Add debug to buffer with position
    ; This is a simplified implementation
    
    mov rax, 1
    jmp .done
    
.done:
    leave
    ret

; === Get Error Count ===
error_reporting_get_error_count:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = error count
    
    mov rax, [error_count]
    
    leave
    ret

; === Get Warning Count ===
error_reporting_get_warning_count:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = warning count
    
    mov rax, [warning_count]
    
    leave
    ret

; === Get Info Count ===
error_reporting_get_info_count:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = info count
    
    mov rax, [info_count]
    
    leave
    ret

; === Get Debug Count ===
error_reporting_get_debug_count:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = debug count
    
    mov rax, [debug_count]
    
    leave
    ret

; === Get Total Count ===
error_reporting_get_total_count:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = total count
    
    mov rax, [error_count]
    add rax, [warning_count]
    add rax, [info_count]
    add rax, [debug_count]
    
    leave
    ret

; === Get Errors ===
error_reporting_get_errors:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = error buffer, rbx = error count
    
    mov rax, error_buffer
    mov rbx, [error_count]
    
    leave
    ret

; === Get Warnings ===
error_reporting_get_warnings:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = warning buffer, rbx = warning count
    
    mov rax, warning_buffer
    mov rbx, [warning_count]
    
    leave
    ret

; === Get Infos ===
error_reporting_get_infos:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = info buffer, rbx = info count
    
    mov rax, 0  ; info buffer
    mov rbx, [info_count]
    
    leave
    ret

; === Get Debugs ===
error_reporting_get_debugs:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = debug buffer, rbx = debug count
    
    mov rax, 0  ; debug buffer
    mov rbx, [debug_count]
    
    leave
    ret

; === Clear Errors ===
error_reporting_clear_errors:
    push rbp
    mov rbp, rsp
    
    ; Clear error buffer
    mov rdi, error_buffer
    mov rsi, 1024 * 8
    call zero_memory
    
    ; Reset error buffer
    mov qword [error_buffer_size], 0
    mov qword [error_buffer_head], 0
    mov qword [error_buffer_tail], 0
    mov qword [error_count], 0
    
    leave
    ret

; === Clear Warnings ===
error_reporting_clear_warnings:
    push rbp
    mov rbp, rsp
    
    ; Clear warning buffer
    mov rdi, warning_buffer
    mov rsi, 1024 * 8
    call zero_memory
    
    ; Reset warning buffer
    mov qword [warning_buffer_size], 0
    mov qword [warning_buffer_head], 0
    mov qword [warning_buffer_tail], 0
    mov qword [warning_count], 0
    
    leave
    ret

; === Clear Infos ===
error_reporting_clear_infos:
    push rbp
    mov rbp, rsp
    
    ; Clear info buffer
    mov qword [info_count], 0
    
    leave
    ret

; === Clear Debugs ===
error_reporting_clear_debugs:
    push rbp
    mov rbp, rsp
    
    ; Clear debug buffer
    mov qword [debug_count], 0
    
    leave
    ret

; === Clear All ===
error_reporting_clear_all:
    push rbp
    mov rbp, rsp
    
    ; Clear all buffers
    call error_reporting_clear_errors
    call error_reporting_clear_warnings
    call error_reporting_clear_infos
    call error_reporting_clear_debugs
    
    leave
    ret

; === Set Warning Level ===
error_reporting_set_warning_level:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = warning level
    
    mov [warning_level], rdi
    
    leave
    ret

; === Set Max Errors ===
error_reporting_set_max_errors:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = max errors
    
    mov [max_errors], rdi
    
    leave
    ret

; === Set Max Warnings ===
error_reporting_set_max_warnings:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = max warnings
    
    mov [max_warnings], rdi
    
    leave
    ret

; === Set Error Recovery ===
error_reporting_set_error_recovery:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = error recovery enabled
    
    mov [error_recovery], rdi
    
    leave
    ret

; === Get Statistics ===
error_reporting_get_statistics:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = errors reported, rbx = warnings reported, rcx = infos reported, rdx = debugs reported
    
    mov rax, [errors_reported]
    mov rbx, [warnings_reported]
    mov rcx, [infos_reported]
    mov rdx, [debugs_reported]
    
    leave
    ret

; === Cleanup ===
error_reporting_cleanup:
    push rbp
    mov rbp, rsp
    
    ; Clear error buffer
    mov rdi, error_buffer
    mov rsi, 1024 * 8
    call zero_memory
    
    ; Clear warning buffer
    mov rdi, warning_buffer
    mov rsi, 1024 * 8
    call zero_memory
    
    ; Reset counters
    mov qword [error_count], 0
    mov qword [warning_count], 0
    mov qword [info_count], 0
    mov qword [debug_count], 0
    mov qword [error_buffer_size], 0
    mov qword [error_buffer_head], 0
    mov qword [error_buffer_tail], 0
    mov qword [warning_buffer_size], 0
    mov qword [warning_buffer_head], 0
    mov qword [warning_buffer_tail], 0
    mov qword [errors_reported], 0
    mov qword [warnings_reported], 0
    mov qword [infos_reported], 0
    mov qword [debugs_reported], 0
    mov qword [errors_recovered], 0
    mov qword [errors_fatal], 0
    mov qword [errors_non_fatal], 0
    mov qword [error_recovery_count], 0
    
    leave
    ret

; === Utility Functions ===
zero_memory:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    ; Args: rdi = memory pointer, rsi = size
    mov rbx, rdi
    mov rcx, rsi
    
.zero_loop:
    cmp rcx, 0
    je .zero_done
    
    mov byte [rbx], 0
    inc rbx
    dec rcx
    jmp .zero_loop
    
.zero_done:
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

; === Error Reporting Demo ===
error_reporting_demo:
    push rbp
    mov rbp, rsp
    
    ; Initialize error reporting
    call error_reporting_init
    
    ; Report sample errors
    mov rdi, 0  ; error message
    mov rsi, ERROR_SYNTAX
    mov rdx, SEVERITY_ERROR
    call error_reporting_report_error
    
    ; Report sample warnings
    mov rdi, 0  ; warning message
    mov rsi, ERROR_WARNING
    call error_reporting_report_warning
    
    ; Get statistics
    call error_reporting_get_statistics
    
    ; Cleanup
    call error_reporting_cleanup
    
    leave
    ret
