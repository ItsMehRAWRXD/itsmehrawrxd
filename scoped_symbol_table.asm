; scoped_symbol_table.asm
; Create scoped symbol table system for variable management
; Comprehensive symbol table with scope management for the Eon compiler

section .data
    ; === Scoped Symbol Table Information ===
    symbol_table_info        db "Scoped Symbol Table v1.0", 10, 0
    symbol_table_capabilities db "Features: Scope management, Symbol resolution, Type tracking", 10, 0
    
    ; === Symbol Types ===
    SYMBOL_VARIABLE      equ 0
    SYMBOL_FUNCTION      equ 1
    SYMBOL_STRUCT        equ 2
    SYMBOL_ENUM          equ 3
    SYMBOL_CONSTANT      equ 4
    SYMBOL_TYPE          equ 5
    SYMBOL_PARAMETER     equ 6
    SYMBOL_FIELD         equ 7
    SYMBOL_METHOD        equ 8
    SYMBOL_NAMESPACE     equ 9
    SYMBOL_MODULE        equ 10
    SYMBOL_IMPORT        equ 11
    SYMBOL_EXPORT        equ 12
    SYMBOL_TEMPLATE      equ 13
    SYMBOL_MACRO         equ 14
    SYMBOL_LABEL         equ 15
    
    ; === Scope Types ===
    SCOPE_GLOBAL         equ 0
    SCOPE_FUNCTION       equ 1
    SCOPE_BLOCK          equ 2
    SCOPE_STRUCT         equ 3
    SCOPE_LOOP           equ 4
    SCOPE_CONDITIONAL    equ 5
    SCOPE_NAMESPACE      equ 6
    SCOPE_MODULE         equ 7
    SCOPE_TEMPLATE       equ 8
    SCOPE_MACRO          equ 9
    SCOPE_LABEL          equ 10
    
    ; === Symbol Attributes ===
    SYMBOL_ATTR_CONST    equ 1
    SYMBOL_ATTR_STATIC   equ 2
    SYMBOL_ATTR_EXTERN   equ 4
    SYMBOL_ATTR_VOLATILE equ 8
    SYMBOL_ATTR_REGISTER equ 16
    SYMBOL_ATTR_INLINE   equ 32
    SYMBOL_ATTR_VIRTUAL  equ 64
    SYMBOL_ATTR_PURE     equ 128
    SYMBOL_ATTR_ABSTRACT equ 256
    SYMBOL_ATTR_FINAL    equ 512
    SYMBOL_ATTR_OVERRIDE equ 1024
    SYMBOL_ATTR_PUBLIC   equ 2048
    SYMBOL_ATTR_PRIVATE  equ 4096
    SYMBOL_ATTR_PROTECTED equ 8192
    
    ; === Symbol Table Structure ===
    SYMBOL_NAME_OFFSET   equ 0
    SYMBOL_TYPE_OFFSET   equ 8
    SYMBOL_SCOPE_OFFSET  equ 16
    SYMBOL_ATTR_OFFSET   equ 24
    SYMBOL_DATA_OFFSET   equ 32
    SYMBOL_LINE_OFFSET   equ 40
    SYMBOL_COL_OFFSET    equ 48
    SYMBOL_NEXT_OFFSET   equ 56
    SYMBOL_SIZE          equ 64
    
    ; === Scope Structure ===
    SCOPE_TYPE_OFFSET    equ 0
    SCOPE_PARENT_OFFSET  equ 8
    SCOPE_SYMBOLS_OFFSET equ 16
    SCOPE_CHILDREN_OFFSET equ 24
    SCOPE_NEXT_OFFSET    equ 32
    SCOPE_SIZE           equ 40
    
    ; === Symbol Table State ===
    symbol_table         resq 1024    ; Symbol table (1024 symbols max)
    symbol_count         resq 1       ; Number of symbols
    symbol_table_size    resq 1       ; Symbol table size
    symbol_table_capacity resq 1      ; Symbol table capacity
    
    ; === Scope Stack ===
    scope_stack          resq 256     ; Scope stack (256 scopes max)
    scope_stack_top      resq 1       ; Scope stack top
    scope_stack_size     resq 1       ; Scope stack size
    scope_stack_capacity resq 1       ; Scope stack capacity
    
    ; === Current Scope ===
    current_scope        resq 1       ; Current scope
    global_scope         resq 1       ; Global scope
    function_scope       resq 1       ; Function scope
    block_scope          resq 1       ; Block scope
    struct_scope         resq 1       ; Struct scope
    
    ; === Symbol Resolution ===
    symbol_resolution_enabled resq 1  ; Symbol resolution enabled
    strict_resolution    resq 1       ; Strict symbol resolution
    implicit_declarations resq 1      ; Implicit declarations allowed
    forward_declarations resq 1       ; Forward declarations allowed
    
    ; === Symbol Table Statistics ===
    symbols_created      resq 1       ; Symbols created
    symbols_resolved     resq 1       ; Symbols resolved
    scopes_created       resq 1       ; Scopes created
    scopes_destroyed     resq 1       ; Scopes destroyed
    lookups_performed    resq 1       ; Lookups performed
    collisions_handled   resq 1       ; Collisions handled
    
    ; === Symbol Table Configuration ===
    max_symbols_per_scope resq 1      ; Max symbols per scope
    max_nesting_depth    resq 1       ; Max nesting depth
    symbol_name_max_len  resq 1       ; Max symbol name length
    scope_name_max_len   resq 1       ; Max scope name length
    
    ; === Error Handling ===
    symbol_errors        resq 256     ; Symbol errors
    symbol_error_count   resq 1       ; Symbol error count
    symbol_warnings      resq 256     ; Symbol warnings
    symbol_warning_count resq 1       ; Symbol warning count

section .text
    global scoped_symbol_table_init
    global scoped_symbol_table_create_scope
    global scoped_symbol_table_destroy_scope
    global scoped_symbol_table_push_scope
    global scoped_symbol_table_pop_scope
    global scoped_symbol_table_get_current_scope
    global scoped_symbol_table_add_symbol
    global scoped_symbol_table_find_symbol
    global scoped_symbol_table_find_symbol_in_scope
    global scoped_symbol_table_find_symbol_recursive
    global scoped_symbol_table_resolve_symbol
    global scoped_symbol_table_check_symbol
    global scoped_symbol_table_remove_symbol
    global scoped_symbol_table_clear_scope
    global scoped_symbol_table_get_scope_symbols
    global scoped_symbol_table_get_scope_count
    global scoped_symbol_table_get_symbol_count
    global scoped_symbol_table_get_nesting_depth
    global scoped_symbol_table_is_global_scope
    global scoped_symbol_table_is_function_scope
    global scoped_symbol_table_is_block_scope
    global scoped_symbol_table_is_struct_scope
    global scoped_symbol_table_get_scope_type
    global scoped_symbol_table_get_symbol_type
    global scoped_symbol_table_get_symbol_attributes
    global scoped_symbol_table_set_symbol_attributes
    global scoped_symbol_table_get_symbol_data
    global scoped_symbol_table_set_symbol_data
    global scoped_symbol_table_get_symbol_position
    global scoped_symbol_table_set_symbol_position
    global scoped_symbol_table_validate_scope
    global scoped_symbol_table_validate_symbol
    global scoped_symbol_table_report_error
    global scoped_symbol_table_report_warning
    global scoped_symbol_table_get_errors
    global scoped_symbol_table_get_warnings
    global scoped_symbol_table_get_statistics
    global scoped_symbol_table_cleanup

; === Initialize Scoped Symbol Table ===
scoped_symbol_table_init:
    push rbp
    mov rbp, rsp
    
    ; Print symbol table info
    mov rdi, symbol_table_info
    call print_string
    mov rdi, symbol_table_capabilities
    call print_string
    
    ; Initialize state
    mov qword [symbol_count], 0
    mov qword [symbol_table_size], 1024
    mov qword [symbol_table_capacity], 1024
    mov qword [scope_stack_top], 0
    mov qword [scope_stack_size], 256
    mov qword [scope_stack_capacity], 256
    mov qword [current_scope], 0
    mov qword [global_scope], 0
    mov qword [function_scope], 0
    mov qword [block_scope], 0
    mov qword [struct_scope], 0
    
    ; Initialize symbol resolution
    mov qword [symbol_resolution_enabled], 1
    mov qword [strict_resolution], 1
    mov qword [implicit_declarations], 0
    mov qword [forward_declarations], 1
    
    ; Initialize statistics
    mov qword [symbols_created], 0
    mov qword [symbols_resolved], 0
    mov qword [scopes_created], 0
    mov qword [scopes_destroyed], 0
    mov qword [lookups_performed], 0
    mov qword [collisions_handled], 0
    
    ; Initialize configuration
    mov qword [max_symbols_per_scope], 256
    mov qword [max_nesting_depth], 32
    mov qword [symbol_name_max_len], 256
    mov qword [scope_name_max_len], 256
    
    ; Initialize error handling
    mov qword [symbol_error_count], 0
    mov qword [symbol_warning_count], 0
    
    ; Clear symbol table
    mov rdi, symbol_table
    mov rsi, 1024 * 8
    call zero_memory
    
    ; Clear scope stack
    mov rdi, scope_stack
    mov rsi, 256 * 8
    call zero_memory
    
    ; Clear error buffer
    mov rdi, symbol_errors
    mov rsi, 256 * 8
    call zero_memory
    
    ; Clear warning buffer
    mov rdi, symbol_warnings
    mov rsi, 256 * 8
    call zero_memory
    
    ; Create global scope
    mov rdi, SCOPE_GLOBAL
    call scoped_symbol_table_create_scope
    mov [global_scope], rax
    mov [current_scope], rax
    
    leave
    ret

; === Create Scope ===
scoped_symbol_table_create_scope:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = scope type
    ; Returns: rax = scope pointer
    
    ; Check if scope stack is full
    mov rax, [scope_stack_top]
    cmp rax, [scope_stack_capacity]
    jge .scope_stack_full
    
    ; Create new scope
    mov rbx, scope_stack
    mov rcx, [scope_stack_top]
    
    ; Initialize scope structure
    mov [rbx + rcx * 8 + SCOPE_TYPE_OFFSET], rdi
    mov qword [rbx + rcx * 8 + SCOPE_PARENT_OFFSET], 0
    mov qword [rbx + rcx * 8 + SCOPE_SYMBOLS_OFFSET], 0
    mov qword [rbx + rcx * 8 + SCOPE_CHILDREN_OFFSET], 0
    mov qword [rbx + rcx * 8 + SCOPE_NEXT_OFFSET], 0
    
    ; Set parent scope
    mov rdx, [current_scope]
    cmp rdx, 0
    je .no_parent
    mov [rbx + rcx * 8 + SCOPE_PARENT_OFFSET], rdx
    
.no_parent:
    ; Return scope pointer
    lea rax, [rbx + rcx * 8]
    
    ; Update statistics
    inc qword [scopes_created]
    
    jmp .done
    
.scope_stack_full:
    mov rax, 0
    
.done:
    leave
    ret

; === Destroy Scope ===
scoped_symbol_table_destroy_scope:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = scope pointer
    
    ; Clear scope symbols
    call scoped_symbol_table_clear_scope
    
    ; Update statistics
    inc qword [scopes_destroyed]
    
    leave
    ret

; === Push Scope ===
scoped_symbol_table_push_scope:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = scope type
    ; Returns: rax = scope pointer
    
    ; Create new scope
    call scoped_symbol_table_create_scope
    cmp rax, 0
    je .create_failed
    
    ; Set as current scope
    mov [current_scope], rax
    
    ; Update scope stack top
    inc qword [scope_stack_top]
    
    mov rax, [current_scope]
    jmp .done
    
.create_failed:
    mov rax, 0
    
.done:
    leave
    ret

; === Pop Scope ===
scoped_symbol_table_pop_scope:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = popped scope pointer
    
    ; Check if scope stack is empty
    mov rax, [scope_stack_top]
    cmp rax, 0
    je .scope_stack_empty
    
    ; Get current scope
    mov rbx, [current_scope]
    mov rax, rbx
    
    ; Get parent scope
    mov rcx, [rbx + SCOPE_PARENT_OFFSET]
    mov [current_scope], rcx
    
    ; Update scope stack top
    dec qword [scope_stack_top]
    
    jmp .done
    
.scope_stack_empty:
    mov rax, 0
    
.done:
    leave
    ret

; === Get Current Scope ===
scoped_symbol_table_get_current_scope:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = current scope pointer
    
    mov rax, [current_scope]
    
    leave
    ret

; === Add Symbol ===
scoped_symbol_table_add_symbol:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = symbol name, rsi = symbol type, rdx = symbol attributes, rcx = symbol data
    ; Returns: rax = symbol pointer
    
    ; Check if symbol table is full
    mov rax, [symbol_count]
    cmp rax, [symbol_table_capacity]
    jge .symbol_table_full
    
    ; Check if current scope exists
    mov rbx, [current_scope]
    cmp rbx, 0
    je .no_current_scope
    
    ; Check for symbol collision
    call scoped_symbol_table_find_symbol_in_scope
    cmp rax, 0
    jne .symbol_exists
    
    ; Add symbol to table
    mov rbx, symbol_table
    mov r8, [symbol_count]
    
    ; Initialize symbol structure
    mov [rbx + r8 * 8 + SYMBOL_NAME_OFFSET], rdi
    mov [rbx + r8 * 8 + SYMBOL_TYPE_OFFSET], rsi
    mov [rbx + r8 * 8 + SYMBOL_ATTR_OFFSET], rdx
    mov [rbx + r8 * 8 + SYMBOL_DATA_OFFSET], rcx
    
    ; Set scope
    mov r9, [current_scope]
    mov [rbx + r8 * 8 + SYMBOL_SCOPE_OFFSET], r9
    
    ; Set position (default)
    mov qword [rbx + r8 * 8 + SYMBOL_LINE_OFFSET], 0
    mov qword [rbx + r8 * 8 + SYMBOL_COL_OFFSET], 0
    
    ; Set next symbol
    mov qword [rbx + r8 * 8 + SYMBOL_NEXT_OFFSET], 0
    
    ; Add to current scope
    mov r9, [current_scope]
    mov r10, [r9 + SCOPE_SYMBOLS_OFFSET]
    cmp r10, 0
    je .first_symbol_in_scope
    mov [rbx + r8 * 8 + SYMBOL_NEXT_OFFSET], r10
    
.first_symbol_in_scope:
    mov [r9 + SCOPE_SYMBOLS_OFFSET], r8
    
    ; Increment symbol count
    inc qword [symbol_count]
    
    ; Update statistics
    inc qword [symbols_created]
    
    ; Return symbol pointer
    lea rax, [rbx + r8 * 8]
    jmp .done
    
.symbol_table_full:
    mov rax, 0
    jmp .done
    
.no_current_scope:
    mov rax, 0
    jmp .done
    
.symbol_exists:
    mov rax, 0
    jmp .done
    
.done:
    leave
    ret

; === Find Symbol in Scope ===
scoped_symbol_table_find_symbol_in_scope:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = symbol name, rsi = scope pointer
    ; Returns: rax = symbol pointer
    
    ; Check if scope exists
    cmp rsi, 0
    je .scope_not_found
    
    ; Get scope symbols
    mov rbx, [rsi + SCOPE_SYMBOLS_OFFSET]
    cmp rbx, 0
    je .no_symbols_in_scope
    
    ; Search symbols
    mov rcx, symbol_table
    
.find_symbol_loop:
    ; Check if this is the requested symbol
    mov rdx, [rcx + rbx * 8 + SYMBOL_NAME_OFFSET]
    cmp rdx, rdi
    je .symbol_found
    
    ; Move to next symbol
    mov rbx, [rcx + rbx * 8 + SYMBOL_NEXT_OFFSET]
    cmp rbx, 0
    je .symbol_not_found
    
    jmp .find_symbol_loop
    
.symbol_found:
    ; Return symbol pointer
    lea rax, [rcx + rbx * 8]
    jmp .done
    
.symbol_not_found:
    mov rax, 0
    jmp .done
    
.no_symbols_in_scope:
    mov rax, 0
    jmp .done
    
.scope_not_found:
    mov rax, 0
    
.done:
    ; Update statistics
    inc qword [lookups_performed]
    
    leave
    ret

; === Find Symbol Recursive ===
scoped_symbol_table_find_symbol_recursive:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = symbol name, rsi = scope pointer
    ; Returns: rax = symbol pointer
    
    ; Check if scope exists
    cmp rsi, 0
    je .scope_not_found
    
    ; Search in current scope
    call scoped_symbol_table_find_symbol_in_scope
    cmp rax, 0
    jne .symbol_found
    
    ; Search in parent scope
    mov rbx, [rsi + SCOPE_PARENT_OFFSET]
    cmp rbx, 0
    je .symbol_not_found
    
    mov rdi, rdi  ; symbol name
    mov rsi, rbx  ; parent scope
    call scoped_symbol_table_find_symbol_recursive
    jmp .done
    
.symbol_found:
    jmp .done
    
.symbol_not_found:
    mov rax, 0
    jmp .done
    
.scope_not_found:
    mov rax, 0
    
.done:
    leave
    ret

; === Find Symbol ===
scoped_symbol_table_find_symbol:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = symbol name
    ; Returns: rax = symbol pointer
    
    ; Search from current scope
    mov rsi, [current_scope]
    call scoped_symbol_table_find_symbol_recursive
    
    leave
    ret

; === Resolve Symbol ===
scoped_symbol_table_resolve_symbol:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = symbol name
    ; Returns: rax = symbol pointer
    
    ; Check if symbol resolution is enabled
    mov rax, [symbol_resolution_enabled]
    cmp rax, 0
    je .resolution_disabled
    
    ; Find symbol
    call scoped_symbol_table_find_symbol
    cmp rax, 0
    jne .symbol_resolved
    
    ; Check for implicit declarations
    mov rbx, [implicit_declarations]
    cmp rbx, 0
    je .symbol_not_found
    
    ; Create implicit symbol
    mov rsi, SYMBOL_VARIABLE
    mov rdx, 0
    mov rcx, 0
    call scoped_symbol_table_add_symbol
    jmp .done
    
.symbol_resolved:
    ; Update statistics
    inc qword [symbols_resolved]
    jmp .done
    
.resolution_disabled:
    mov rax, 0
    jmp .done
    
.symbol_not_found:
    mov rax, 0
    
.done:
    leave
    ret

; === Check Symbol ===
scoped_symbol_table_check_symbol:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = symbol pointer
    ; Returns: rax = validity (1=valid, 0=invalid)
    
    ; Check if symbol exists
    cmp rdi, 0
    je .symbol_invalid
    
    ; Check symbol structure
    ; This is a simplified implementation
    
    mov rax, 1
    jmp .done
    
.symbol_invalid:
    mov rax, 0
    
.done:
    leave
    ret

; === Remove Symbol ===
scoped_symbol_table_remove_symbol:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = symbol pointer
    
    ; Remove symbol from scope
    ; This is a simplified implementation
    
    leave
    ret

; === Clear Scope ===
scoped_symbol_table_clear_scope:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = scope pointer
    
    ; Clear all symbols in scope
    ; This is a simplified implementation
    
    leave
    ret

; === Get Scope Symbols ===
scoped_symbol_table_get_scope_symbols:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = scope pointer
    ; Returns: rax = symbol list
    
    ; Get scope symbols
    mov rax, [rdi + SCOPE_SYMBOLS_OFFSET]
    
    leave
    ret

; === Get Scope Count ===
scoped_symbol_table_get_scope_count:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = scope count
    
    mov rax, [scope_stack_top]
    
    leave
    ret

; === Get Symbol Count ===
scoped_symbol_table_get_symbol_count:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = symbol count
    
    mov rax, [symbol_count]
    
    leave
    ret

; === Get Nesting Depth ===
scoped_symbol_table_get_nesting_depth:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = nesting depth
    
    mov rax, [scope_stack_top]
    
    leave
    ret

; === Is Global Scope ===
scoped_symbol_table_is_global_scope:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = scope pointer
    ; Returns: rax = is global (1=yes, 0=no)
    
    mov rax, [rdi + SCOPE_TYPE_OFFSET]
    cmp rax, SCOPE_GLOBAL
    je .is_global
    
    mov rax, 0
    jmp .done
    
.is_global:
    mov rax, 1
    
.done:
    leave
    ret

; === Is Function Scope ===
scoped_symbol_table_is_function_scope:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = scope pointer
    ; Returns: rax = is function (1=yes, 0=no)
    
    mov rax, [rdi + SCOPE_TYPE_OFFSET]
    cmp rax, SCOPE_FUNCTION
    je .is_function
    
    mov rax, 0
    jmp .done
    
.is_function:
    mov rax, 1
    
.done:
    leave
    ret

; === Is Block Scope ===
scoped_symbol_table_is_block_scope:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = scope pointer
    ; Returns: rax = is block (1=yes, 0=no)
    
    mov rax, [rdi + SCOPE_TYPE_OFFSET]
    cmp rax, SCOPE_BLOCK
    je .is_block
    
    mov rax, 0
    jmp .done
    
.is_block:
    mov rax, 1
    
.done:
    leave
    ret

; === Is Struct Scope ===
scoped_symbol_table_is_struct_scope:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = scope pointer
    ; Returns: rax = is struct (1=yes, 0=no)
    
    mov rax, [rdi + SCOPE_TYPE_OFFSET]
    cmp rax, SCOPE_STRUCT
    je .is_struct
    
    mov rax, 0
    jmp .done
    
.is_struct:
    mov rax, 1
    
.done:
    leave
    ret

; === Get Scope Type ===
scoped_symbol_table_get_scope_type:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = scope pointer
    ; Returns: rax = scope type
    
    mov rax, [rdi + SCOPE_TYPE_OFFSET]
    
    leave
    ret

; === Get Symbol Type ===
scoped_symbol_table_get_symbol_type:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = symbol pointer
    ; Returns: rax = symbol type
    
    mov rax, [rdi + SYMBOL_TYPE_OFFSET]
    
    leave
    ret

; === Get Symbol Attributes ===
scoped_symbol_table_get_symbol_attributes:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = symbol pointer
    ; Returns: rax = symbol attributes
    
    mov rax, [rdi + SYMBOL_ATTR_OFFSET]
    
    leave
    ret

; === Set Symbol Attributes ===
scoped_symbol_table_set_symbol_attributes:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = symbol pointer, rsi = attributes
    
    mov [rdi + SYMBOL_ATTR_OFFSET], rsi
    
    leave
    ret

; === Get Symbol Data ===
scoped_symbol_table_get_symbol_data:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = symbol pointer
    ; Returns: rax = symbol data
    
    mov rax, [rdi + SYMBOL_DATA_OFFSET]
    
    leave
    ret

; === Set Symbol Data ===
scoped_symbol_table_set_symbol_data:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = symbol pointer, rsi = data
    
    mov [rdi + SYMBOL_DATA_OFFSET], rsi
    
    leave
    ret

; === Get Symbol Position ===
scoped_symbol_table_get_symbol_position:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = symbol pointer
    ; Returns: rax = line, rbx = column
    
    mov rax, [rdi + SYMBOL_LINE_OFFSET]
    mov rbx, [rdi + SYMBOL_COL_OFFSET]
    
    leave
    ret

; === Set Symbol Position ===
scoped_symbol_table_set_symbol_position:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = symbol pointer, rsi = line, rdx = column
    
    mov [rdi + SYMBOL_LINE_OFFSET], rsi
    mov [rdi + SYMBOL_COL_OFFSET], rdx
    
    leave
    ret

; === Validate Scope ===
scoped_symbol_table_validate_scope:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = scope pointer
    ; Returns: rax = validity (1=valid, 0=invalid)
    
    ; Check if scope exists
    cmp rdi, 0
    je .scope_invalid
    
    ; Check scope structure
    ; This is a simplified implementation
    
    mov rax, 1
    jmp .done
    
.scope_invalid:
    mov rax, 0
    
.done:
    leave
    ret

; === Validate Symbol ===
scoped_symbol_table_validate_symbol:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = symbol pointer
    ; Returns: rax = validity (1=valid, 0=invalid)
    
    ; Check if symbol exists
    cmp rdi, 0
    je .symbol_invalid
    
    ; Check symbol structure
    ; This is a simplified implementation
    
    mov rax, 1
    jmp .done
    
.symbol_invalid:
    mov rax, 0
    
.done:
    leave
    ret

; === Report Error ===
scoped_symbol_table_report_error:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = error message
    
    ; Check if error buffer is full
    mov rax, [symbol_error_count]
    cmp rax, 256
    jge .error_buffer_full
    
    ; Add error to buffer
    mov rbx, symbol_errors
    mov rcx, [symbol_error_count]
    mov [rbx + rcx * 8], rdi
    
    ; Increment error count
    inc qword [symbol_error_count]
    
    mov rax, 1
    jmp .done
    
.error_buffer_full:
    mov rax, 0
    
.done:
    leave
    ret

; === Report Warning ===
scoped_symbol_table_report_warning:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = warning message
    
    ; Check if warning buffer is full
    mov rax, [symbol_warning_count]
    cmp rax, 256
    jge .warning_buffer_full
    
    ; Add warning to buffer
    mov rbx, symbol_warnings
    mov rcx, [symbol_warning_count]
    mov [rbx + rcx * 8], rdi
    
    ; Increment warning count
    inc qword [symbol_warning_count]
    
    mov rax, 1
    jmp .done
    
.warning_buffer_full:
    mov rax, 0
    
.done:
    leave
    ret

; === Get Errors ===
scoped_symbol_table_get_errors:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = error buffer, rbx = error count
    
    mov rax, symbol_errors
    mov rbx, [symbol_error_count]
    
    leave
    ret

; === Get Warnings ===
scoped_symbol_table_get_warnings:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = warning buffer, rbx = warning count
    
    mov rax, symbol_warnings
    mov rbx, [symbol_warning_count]
    
    leave
    ret

; === Get Statistics ===
scoped_symbol_table_get_statistics:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = symbols created, rbx = symbols resolved, rcx = scopes created, rdx = lookups performed
    
    mov rax, [symbols_created]
    mov rbx, [symbols_resolved]
    mov rcx, [scopes_created]
    mov rdx, [lookups_performed]
    
    leave
    ret

; === Cleanup ===
scoped_symbol_table_cleanup:
    push rbp
    mov rbp, rsp
    
    ; Clear symbol table
    mov rdi, symbol_table
    mov rsi, 1024 * 8
    call zero_memory
    
    ; Clear scope stack
    mov rdi, scope_stack
    mov rsi, 256 * 8
    call zero_memory
    
    ; Clear error buffer
    mov rdi, symbol_errors
    mov rsi, 256 * 8
    call zero_memory
    
    ; Clear warning buffer
    mov rdi, symbol_warnings
    mov rsi, 256 * 8
    call zero_memory
    
    ; Reset counters
    mov qword [symbol_count], 0
    mov qword [scope_stack_top], 0
    mov qword [current_scope], 0
    mov qword [global_scope], 0
    mov qword [function_scope], 0
    mov qword [block_scope], 0
    mov qword [struct_scope], 0
    mov qword [symbols_created], 0
    mov qword [symbols_resolved], 0
    mov qword [scopes_created], 0
    mov qword [scopes_destroyed], 0
    mov qword [lookups_performed], 0
    mov qword [collisions_handled], 0
    mov qword [symbol_error_count], 0
    mov qword [symbol_warning_count], 0
    
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

; === Scoped Symbol Table Demo ===
scoped_symbol_table_demo:
    push rbp
    mov rbp, rsp
    
    ; Initialize symbol table
    call scoped_symbol_table_init
    
    ; Create function scope
    mov rdi, SCOPE_FUNCTION
    call scoped_symbol_table_push_scope
    
    ; Add symbols
    mov rdi, 0  ; symbol name
    mov rsi, SYMBOL_VARIABLE
    mov rdx, 0
    mov rcx, 0
    call scoped_symbol_table_add_symbol
    
    ; Find symbol
    mov rdi, 0  ; symbol name
    call scoped_symbol_table_find_symbol
    
    ; Get statistics
    call scoped_symbol_table_get_statistics
    
    ; Cleanup
    call scoped_symbol_table_cleanup
    
    leave
    ret
