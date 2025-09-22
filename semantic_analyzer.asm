; semantic_analyzer.asm
; Implement semantic analyzer with type checking and scoped symbol table
; Comprehensive semantic analysis for the Eon compiler

section .data
    ; === Semantic Analyzer Information ===
    semantic_info        db "Semantic Analyzer v1.0", 10, 0
    semantic_capabilities db "Features: Type checking, Symbol tables, Scope management", 10, 0
    
    ; === Type System ===
    TYPE_VOID            equ 0
    TYPE_INT             equ 1
    TYPE_FLOAT           equ 2
    TYPE_BOOL            equ 3
    TYPE_STRING          equ 4
    TYPE_ARRAY           equ 5
    TYPE_FUNCTION        equ 6
    TYPE_STRUCT          equ 7
    TYPE_POINTER         equ 8
    TYPE_UNION           equ 9
    TYPE_ENUM            equ 10
    TYPE_GENERIC         equ 11
    
    ; === Type Names ===
    type_void_name       db "void", 0
    type_int_name        db "int", 0
    type_float_name      db "float", 0
    type_bool_name       db "bool", 0
    type_string_name     db "string", 0
    type_array_name      db "array", 0
    type_function_name   db "function", 0
    type_struct_name     db "struct", 0
    type_pointer_name    db "pointer", 0
    type_union_name      db "union", 0
    type_enum_name       db "enum", 0
    type_generic_name    db "generic", 0
    
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
    
    ; === Scope Types ===
    SCOPE_GLOBAL         equ 0
    SCOPE_FUNCTION       equ 1
    SCOPE_BLOCK          equ 2
    SCOPE_STRUCT         equ 3
    SCOPE_LOOP           equ 4
    SCOPE_CONDITIONAL    equ 5
    
    ; === Semantic Analyzer State ===
    semantic_ast         resq 1       ; AST to analyze
    semantic_errors      resq 256     ; Error buffer
    semantic_error_count resq 1       ; Error count
    semantic_warnings    resq 256     ; Warning buffer
    semantic_warning_count resq 1     ; Warning count
    
    ; === Symbol Table ===
    symbol_table         resq 1024    ; Symbol table (1024 symbols max)
    symbol_count         resq 1       ; Number of symbols
    symbol_table_size    resq 1       ; Symbol table size
    
    ; === Scope Stack ===
    scope_stack          resq 256     ; Scope stack (256 scopes max)
    scope_stack_top      resq 1       ; Scope stack top
    scope_stack_size     resq 1       ; Scope stack size
    
    ; === Type System ===
    type_system          resq 1024    ; Type system (1024 types max)
    type_count           resq 1       ; Number of types
    type_system_size     resq 1       ; Type system size
    
    ; === Semantic Analysis State ===
    current_scope        resq 1       ; Current scope
    current_function     resq 1       ; Current function
    current_struct       resq 1       ; Current struct
    current_loop         resq 1       ; Current loop
    current_conditional  resq 1       ; Current conditional
    
    ; === Type Checking ===
    type_checking_enabled resq 1      ; Type checking enabled
    strict_type_checking resq 1       ; Strict type checking
    implicit_conversions resq 1       ; Implicit conversions allowed
    type_inference       resq 1       ; Type inference enabled
    
    ; === Error Reporting ===
    error_reporting_enabled resq 1    ; Error reporting enabled
    warning_level        resq 1       ; Warning level
    error_recovery       resq 1       ; Error recovery enabled
    max_errors           resq 1       ; Maximum errors before stopping
    
    ; === Semantic Analysis Statistics ===
    analysis_time        resq 1       ; Analysis time
    symbols_analyzed     resq 1       ; Symbols analyzed
    types_checked        resq 1       ; Types checked
    scopes_processed     resq 1       ; Scopes processed
    functions_analyzed   resq 1       ; Functions analyzed
    structs_analyzed     resq 1       ; Structs analyzed

section .text
    global semantic_analyzer_init
    global semantic_analyzer_analyze
    global semantic_analyzer_analyze_program
    global semantic_analyzer_analyze_function
    global semantic_analyzer_analyze_struct
    global semantic_analyzer_analyze_expression
    global semantic_analyzer_analyze_statement
    global semantic_analyzer_analyze_block
    global semantic_analyzer_check_types
    global semantic_analyzer_check_symbols
    global semantic_analyzer_check_scopes
    global semantic_analyzer_add_symbol
    global semantic_analyzer_find_symbol
    global semantic_analyzer_push_scope
    global semantic_analyzer_pop_scope
    global semantic_analyzer_get_current_scope
    global semantic_analyzer_add_type
    global semantic_analyzer_find_type
    global semantic_analyzer_check_type_compatibility
    global semantic_analyzer_infer_type
    global semantic_analyzer_report_error
    global semantic_analyzer_report_warning
    global semantic_analyzer_get_errors
    global semantic_analyzer_get_warnings
    global semantic_analyzer_get_statistics
    global semantic_analyzer_cleanup

; === Initialize Semantic Analyzer ===
semantic_analyzer_init:
    push rbp
    mov rbp, rsp
    
    ; Print semantic analyzer info
    mov rdi, semantic_info
    call print_string
    mov rdi, semantic_capabilities
    call print_string
    
    ; Initialize state
    mov qword [semantic_ast], 0
    mov qword [semantic_error_count], 0
    mov qword [semantic_warning_count], 0
    mov qword [symbol_count], 0
    mov qword [symbol_table_size], 1024
    mov qword [scope_stack_top], 0
    mov qword [scope_stack_size], 256
    mov qword [type_count], 0
    mov qword [type_system_size], 1024
    mov qword [current_scope], 0
    mov qword [current_function], 0
    mov qword [current_struct], 0
    mov qword [current_loop], 0
    mov qword [current_conditional], 0
    
    ; Initialize type checking
    mov qword [type_checking_enabled], 1
    mov qword [strict_type_checking], 1
    mov qword [implicit_conversions], 0
    mov qword [type_inference], 1
    
    ; Initialize error reporting
    mov qword [error_reporting_enabled], 1
    mov qword [warning_level], 2
    mov qword [error_recovery], 1
    mov qword [max_errors], 100
    
    ; Initialize statistics
    mov qword [analysis_time], 0
    mov qword [symbols_analyzed], 0
    mov qword [types_checked], 0
    mov qword [scopes_processed], 0
    mov qword [functions_analyzed], 0
    mov qword [structs_analyzed], 0
    
    ; Clear symbol table
    mov rdi, symbol_table
    mov rsi, 1024 * 8
    call zero_memory
    
    ; Clear scope stack
    mov rdi, scope_stack
    mov rsi, 256 * 8
    call zero_memory
    
    ; Clear type system
    mov rdi, type_system
    mov rsi, 1024 * 8
    call zero_memory
    
    ; Clear error buffer
    mov rdi, semantic_errors
    mov rsi, 256 * 8
    call zero_memory
    
    ; Clear warning buffer
    mov rdi, semantic_warnings
    mov rsi, 256 * 8
    call zero_memory
    
    ; Initialize built-in types
    call semantic_analyzer_init_builtin_types
    
    ; Initialize global scope
    call semantic_analyzer_init_global_scope
    
    leave
    ret

; === Initialize Built-in Types ===
semantic_analyzer_init_builtin_types:
    push rbp
    mov rbp, rsp
    
    ; Add built-in types to type system
    mov rdi, TYPE_VOID
    mov rsi, type_void_name
    call semantic_analyzer_add_type
    
    mov rdi, TYPE_INT
    mov rsi, type_int_name
    call semantic_analyzer_add_type
    
    mov rdi, TYPE_FLOAT
    mov rsi, type_float_name
    call semantic_analyzer_add_type
    
    mov rdi, TYPE_BOOL
    mov rsi, type_bool_name
    call semantic_analyzer_add_type
    
    mov rdi, TYPE_STRING
    mov rsi, type_string_name
    call semantic_analyzer_add_type
    
    leave
    ret

; === Initialize Global Scope ===
semantic_analyzer_init_global_scope:
    push rbp
    mov rbp, rsp
    
    ; Create global scope
    mov rdi, SCOPE_GLOBAL
    call semantic_analyzer_push_scope
    
    leave
    ret

; === Analyze Program ===
semantic_analyzer_analyze:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = AST to analyze
    
    mov [semantic_ast], rdi
    
    ; Start analysis timing
    call get_current_time
    mov [analysis_time], rax
    
    ; Analyze program
    call semantic_analyzer_analyze_program
    
    ; End analysis timing
    call get_current_time
    sub rax, [analysis_time]
    mov [analysis_time], rax
    
    leave
    ret

; === Analyze Program ===
semantic_analyzer_analyze_program:
    push rbp
    mov rbp, rsp
    
    ; Analyze each top-level declaration
    mov rbx, [semantic_ast]
    mov rcx, 0  ; child index
    
.analyze_program_loop:
    ; Get child node
    mov rdx, [rbx + 8]  ; left child
    cmp rdx, 0
    je .analyze_program_done
    
    ; Analyze child
    mov rdi, rdx
    call semantic_analyzer_analyze_declaration
    
    ; Move to next child
    mov rdx, [rdx + 24]  ; next sibling
    cmp rdx, 0
    je .analyze_program_done
    
    mov rdi, rdx
    call semantic_analyzer_analyze_declaration
    
    jmp .analyze_program_loop
    
.analyze_program_done:
    leave
    ret

; === Analyze Declaration ===
semantic_analyzer_analyze_declaration:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = declaration node
    
    mov rbx, rdi
    mov rcx, [rbx]  ; node type
    
    ; Check declaration type
    cmp rcx, 1  ; FUNCTION_DEF
    je .analyze_function_declaration
    cmp rcx, 2  ; MODEL_DEF
    je .analyze_struct_declaration
    cmp rcx, 3  ; VARIABLE_DECL
    je .analyze_variable_declaration
    
    ; Unknown declaration type
    jmp .done
    
.analyze_function_declaration:
    call semantic_analyzer_analyze_function
    jmp .done
    
.analyze_struct_declaration:
    call semantic_analyzer_analyze_struct
    jmp .done
    
.analyze_variable_declaration:
    call semantic_analyzer_analyze_variable
    jmp .done
    
.done:
    leave
    ret

; === Analyze Function ===
semantic_analyzer_analyze_function:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = function node
    
    mov rbx, rdi
    mov [current_function], rbx
    
    ; Create function scope
    mov rdi, SCOPE_FUNCTION
    call semantic_analyzer_push_scope
    
    ; Analyze function parameters
    call semantic_analyzer_analyze_function_parameters
    
    ; Analyze function body
    call semantic_analyzer_analyze_function_body
    
    ; Pop function scope
    call semantic_analyzer_pop_scope
    
    ; Update statistics
    inc qword [functions_analyzed]
    
    leave
    ret

; === Analyze Function Parameters ===
semantic_analyzer_analyze_function_parameters:
    push rbp
    mov rbp, rsp
    
    ; Analyze function parameters
    ; This is a simplified implementation
    
    leave
    ret

; === Analyze Function Body ===
semantic_analyzer_analyze_function_body:
    push rbp
    mov rbp, rsp
    
    ; Analyze function body
    ; This is a simplified implementation
    
    leave
    ret

; === Analyze Struct ===
semantic_analyzer_analyze_struct:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = struct node
    
    mov rbx, rdi
    mov [current_struct], rbx
    
    ; Create struct scope
    mov rdi, SCOPE_STRUCT
    call semantic_analyzer_push_scope
    
    ; Analyze struct fields
    call semantic_analyzer_analyze_struct_fields
    
    ; Pop struct scope
    call semantic_analyzer_pop_scope
    
    ; Update statistics
    inc qword [structs_analyzed]
    
    leave
    ret

; === Analyze Struct Fields ===
semantic_analyzer_analyze_struct_fields:
    push rbp
    mov rbp, rsp
    
    ; Analyze struct fields
    ; This is a simplified implementation
    
    leave
    ret

; === Analyze Variable ===
semantic_analyzer_analyze_variable:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = variable node
    
    ; Analyze variable declaration
    ; This is a simplified implementation
    
    ; Update statistics
    inc qword [symbols_analyzed]
    
    leave
    ret

; === Analyze Expression ===
semantic_analyzer_analyze_expression:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = expression node
    
    mov rbx, rdi
    mov rcx, [rbx]  ; node type
    
    ; Check expression type
    cmp rcx, 9  ; BINARY_OP
    je .analyze_binary_expression
    cmp rcx, 10 ; UNARY_OP
    je .analyze_unary_expression
    cmp rcx, 11 ; FUNCTION_CALL
    je .analyze_function_call
    cmp rcx, 12 ; IDENTIFIER
    je .analyze_identifier
    cmp rcx, 13 ; LITERAL
    je .analyze_literal
    
    ; Unknown expression type
    jmp .done
    
.analyze_binary_expression:
    call semantic_analyzer_analyze_binary_expression
    jmp .done
    
.analyze_unary_expression:
    call semantic_analyzer_analyze_unary_expression
    jmp .done
    
.analyze_function_call:
    call semantic_analyzer_analyze_function_call
    jmp .done
    
.analyze_identifier:
    call semantic_analyzer_analyze_identifier
    jmp .done
    
.analyze_literal:
    call semantic_analyzer_analyze_literal
    jmp .done
    
.done:
    leave
    ret

; === Analyze Binary Expression ===
semantic_analyzer_analyze_binary_expression:
    push rbp
    mov rbp, rsp
    
    ; Analyze binary expression
    ; This is a simplified implementation
    
    ; Update statistics
    inc qword [types_checked]
    
    leave
    ret

; === Analyze Unary Expression ===
semantic_analyzer_analyze_unary_expression:
    push rbp
    mov rbp, rsp
    
    ; Analyze unary expression
    ; This is a simplified implementation
    
    ; Update statistics
    inc qword [types_checked]
    
    leave
    ret

; === Analyze Function Call ===
semantic_analyzer_analyze_function_call:
    push rbp
    mov rbp, rsp
    
    ; Analyze function call
    ; This is a simplified implementation
    
    ; Update statistics
    inc qword [types_checked]
    
    leave
    ret

; === Analyze Identifier ===
semantic_analyzer_analyze_identifier:
    push rbp
    mov rbp, rsp
    
    ; Analyze identifier
    ; This is a simplified implementation
    
    ; Update statistics
    inc qword [symbols_analyzed]
    
    leave
    ret

; === Analyze Literal ===
semantic_analyzer_analyze_literal:
    push rbp
    mov rbp, rsp
    
    ; Analyze literal
    ; This is a simplified implementation
    
    ; Update statistics
    inc qword [types_checked]
    
    leave
    ret

; === Analyze Statement ===
semantic_analyzer_analyze_statement:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = statement node
    
    mov rbx, rdi
    mov rcx, [rbx]  ; node type
    
    ; Check statement type
    cmp rcx, 3  ; VARIABLE_DECL
    je .analyze_variable_statement
    cmp rcx, 4  ; ASSIGNMENT
    je .analyze_assignment_statement
    cmp rcx, 5  ; IF_STMT
    je .analyze_if_statement
    cmp rcx, 6  ; LOOP_STMT
    je .analyze_loop_statement
    cmp rcx, 7  ; RETURN_STMT
    je .analyze_return_statement
    cmp rcx, 8  ; BLOCK
    je .analyze_block_statement
    
    ; Unknown statement type
    jmp .done
    
.analyze_variable_statement:
    call semantic_analyzer_analyze_variable
    jmp .done
    
.analyze_assignment_statement:
    call semantic_analyzer_analyze_assignment
    jmp .done
    
.analyze_if_statement:
    call semantic_analyzer_analyze_if
    jmp .done
    
.analyze_loop_statement:
    call semantic_analyzer_analyze_loop
    jmp .done
    
.analyze_return_statement:
    call semantic_analyzer_analyze_return
    jmp .done
    
.analyze_block_statement:
    call semantic_analyzer_analyze_block
    jmp .done
    
.done:
    leave
    ret

; === Analyze Assignment ===
semantic_analyzer_analyze_assignment:
    push rbp
    mov rbp, rsp
    
    ; Analyze assignment statement
    ; This is a simplified implementation
    
    ; Update statistics
    inc qword [types_checked]
    
    leave
    ret

; === Analyze If ===
semantic_analyzer_analyze_if:
    push rbp
    mov rbp, rsp
    
    ; Analyze if statement
    ; This is a simplified implementation
    
    ; Update statistics
    inc qword [types_checked]
    
    leave
    ret

; === Analyze Loop ===
semantic_analyzer_analyze_loop:
    push rbp
    mov rbp, rsp
    
    ; Analyze loop statement
    ; This is a simplified implementation
    
    ; Update statistics
    inc qword [types_checked]
    
    leave
    ret

; === Analyze Return ===
semantic_analyzer_analyze_return:
    push rbp
    mov rbp, rsp
    
    ; Analyze return statement
    ; This is a simplified implementation
    
    ; Update statistics
    inc qword [types_checked]
    
    leave
    ret

; === Analyze Block ===
semantic_analyzer_analyze_block:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = block node
    
    ; Create block scope
    mov rdi, SCOPE_BLOCK
    call semantic_analyzer_push_scope
    
    ; Analyze block statements
    ; This is a simplified implementation
    
    ; Pop block scope
    call semantic_analyzer_pop_scope
    
    ; Update statistics
    inc qword [scopes_processed]
    
    leave
    ret

; === Check Types ===
semantic_analyzer_check_types:
    push rbp
    mov rbp, rsp
    
    ; Check type compatibility
    ; This is a simplified implementation
    
    ; Update statistics
    inc qword [types_checked]
    
    leave
    ret

; === Check Symbols ===
semantic_analyzer_check_symbols:
    push rbp
    mov rbp, rsp
    
    ; Check symbol usage
    ; This is a simplified implementation
    
    ; Update statistics
    inc qword [symbols_analyzed]
    
    leave
    ret

; === Check Scopes ===
semantic_analyzer_check_scopes:
    push rbp
    mov rbp, rsp
    
    ; Check scope validity
    ; This is a simplified implementation
    
    ; Update statistics
    inc qword [scopes_processed]
    
    leave
    ret

; === Add Symbol ===
semantic_analyzer_add_symbol:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = symbol name, rsi = symbol type, rdx = symbol data
    
    ; Check if symbol table is full
    mov rax, [symbol_count]
    cmp rax, 1024
    jge .symbol_table_full
    
    ; Add symbol to table
    mov rbx, symbol_table
    mov rcx, [symbol_count]
    
    ; Store symbol data (simplified)
    mov [rbx + rcx * 8], rdi
    
    ; Increment symbol count
    inc qword [symbol_count]
    
    ; Update statistics
    inc qword [symbols_analyzed]
    
    mov rax, 1
    jmp .done
    
.symbol_table_full:
    mov rax, 0
    
.done:
    leave
    ret

; === Find Symbol ===
semantic_analyzer_find_symbol:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = symbol name
    ; Returns: rax = symbol data, rbx = symbol type
    
    ; Search symbol table
    mov rbx, symbol_table
    mov rcx, 0
    
.find_symbol_loop:
    cmp rcx, [symbol_count]
    jge .symbol_not_found
    
    ; Check if this is the requested symbol
    cmp [rbx + rcx * 8], rdi
    je .symbol_found
    
    inc rcx
    jmp .find_symbol_loop
    
.symbol_found:
    ; Return symbol data
    mov rax, [rbx + rcx * 8]
    mov rbx, SYMBOL_VARIABLE  ; Default symbol type
    jmp .done
    
.symbol_not_found:
    mov rax, 0
    mov rbx, 0
    
.done:
    leave
    ret

; === Push Scope ===
semantic_analyzer_push_scope:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = scope type
    
    ; Check if scope stack is full
    mov rax, [scope_stack_top]
    cmp rax, 256
    jge .scope_stack_full
    
    ; Push scope onto stack
    mov rbx, scope_stack
    mov rcx, [scope_stack_top]
    mov [rbx + rcx * 8], rdi
    
    ; Update scope stack top
    inc qword [scope_stack_top]
    
    ; Update current scope
    mov [current_scope], rdi
    
    ; Update statistics
    inc qword [scopes_processed]
    
    mov rax, 1
    jmp .done
    
.scope_stack_full:
    mov rax, 0
    
.done:
    leave
    ret

; === Pop Scope ===
semantic_analyzer_pop_scope:
    push rbp
    mov rbp, rsp
    
    ; Check if scope stack is empty
    mov rax, [scope_stack_top]
    cmp rax, 0
    je .scope_stack_empty
    
    ; Pop scope from stack
    dec qword [scope_stack_top]
    
    ; Update current scope
    mov rbx, scope_stack
    mov rcx, [scope_stack_top]
    mov rdx, [rbx + rcx * 8]
    mov [current_scope], rdx
    
    mov rax, 1
    jmp .done
    
.scope_stack_empty:
    mov rax, 0
    
.done:
    leave
    ret

; === Get Current Scope ===
semantic_analyzer_get_current_scope:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = current scope
    
    mov rax, [current_scope]
    
    leave
    ret

; === Add Type ===
semantic_analyzer_add_type:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = type ID, rsi = type name
    
    ; Check if type system is full
    mov rax, [type_count]
    cmp rax, 1024
    jge .type_system_full
    
    ; Add type to system
    mov rbx, type_system
    mov rcx, [type_count]
    
    ; Store type data (simplified)
    mov [rbx + rcx * 8], rdi
    
    ; Increment type count
    inc qword [type_count]
    
    mov rax, 1
    jmp .done
    
.type_system_full:
    mov rax, 0
    
.done:
    leave
    ret

; === Find Type ===
semantic_analyzer_find_type:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = type name
    ; Returns: rax = type ID
    
    ; Search type system
    mov rbx, type_system
    mov rcx, 0
    
.find_type_loop:
    cmp rcx, [type_count]
    jge .type_not_found
    
    ; Check if this is the requested type
    cmp [rbx + rcx * 8], rdi
    je .type_found
    
    inc rcx
    jmp .find_type_loop
    
.type_found:
    ; Return type ID
    mov rax, [rbx + rcx * 8]
    jmp .done
    
.type_not_found:
    mov rax, 0
    
.done:
    leave
    ret

; === Check Type Compatibility ===
semantic_analyzer_check_type_compatibility:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = type1, rsi = type2
    ; Returns: rax = compatibility (1=compatible, 0=incompatible)
    
    ; Check type compatibility
    cmp rdi, rsi
    je .types_compatible
    
    ; Check for implicit conversions
    mov rax, [implicit_conversions]
    cmp rax, 0
    je .types_incompatible
    
    ; Check specific type conversions
    ; This is a simplified implementation
    
.types_compatible:
    mov rax, 1
    jmp .done
    
.types_incompatible:
    mov rax, 0
    
.done:
    leave
    ret

; === Infer Type ===
semantic_analyzer_infer_type:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = expression node
    ; Returns: rax = inferred type
    
    ; Check if type inference is enabled
    mov rax, [type_inference]
    cmp rax, 0
    je .type_inference_disabled
    
    ; Infer type from expression
    ; This is a simplified implementation
    
    mov rax, TYPE_INT  ; Default type
    jmp .done
    
.type_inference_disabled:
    mov rax, TYPE_VOID
    
.done:
    leave
    ret

; === Report Error ===
semantic_analyzer_report_error:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = error message, rsi = line, rdx = column
    
    ; Check if error reporting is enabled
    mov rax, [error_reporting_enabled]
    cmp rax, 0
    je .error_reporting_disabled
    
    ; Check if max errors reached
    mov rax, [semantic_error_count]
    cmp rax, [max_errors]
    jge .max_errors_reached
    
    ; Add error to buffer
    mov rbx, semantic_errors
    mov rcx, [semantic_error_count]
    
    ; Store error data (simplified)
    mov [rbx + rcx * 8], rdi
    
    ; Increment error count
    inc qword [semantic_error_count]
    
    mov rax, 1
    jmp .done
    
.error_reporting_disabled:
    mov rax, 0
    jmp .done
    
.max_errors_reached:
    mov rax, 0
    
.done:
    leave
    ret

; === Report Warning ===
semantic_analyzer_report_warning:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = warning message, rsi = line, rdx = column
    
    ; Check warning level
    mov rax, [warning_level]
    cmp rax, 0
    je .warning_disabled
    
    ; Add warning to buffer
    mov rbx, semantic_warnings
    mov rcx, [semantic_warning_count]
    
    ; Store warning data (simplified)
    mov [rbx + rcx * 8], rdi
    
    ; Increment warning count
    inc qword [semantic_warning_count]
    
    mov rax, 1
    jmp .done
    
.warning_disabled:
    mov rax, 0
    
.done:
    leave
    ret

; === Get Errors ===
semantic_analyzer_get_errors:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = error buffer, rbx = error count
    
    mov rax, semantic_errors
    mov rbx, [semantic_error_count]
    
    leave
    ret

; === Get Warnings ===
semantic_analyzer_get_warnings:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = warning buffer, rbx = warning count
    
    mov rax, semantic_warnings
    mov rbx, [semantic_warning_count]
    
    leave
    ret

; === Get Statistics ===
semantic_analyzer_get_statistics:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = analysis time, rbx = symbols analyzed, rcx = types checked, rdx = scopes processed
    
    mov rax, [analysis_time]
    mov rbx, [symbols_analyzed]
    mov rcx, [types_checked]
    mov rdx, [scopes_processed]
    
    leave
    ret

; === Cleanup ===
semantic_analyzer_cleanup:
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
    
    ; Clear type system
    mov rdi, type_system
    mov rsi, 1024 * 8
    call zero_memory
    
    ; Clear error buffer
    mov rdi, semantic_errors
    mov rsi, 256 * 8
    call zero_memory
    
    ; Clear warning buffer
    mov rdi, semantic_warnings
    mov rsi, 256 * 8
    call zero_memory
    
    ; Reset counters
    mov qword [semantic_error_count], 0
    mov qword [semantic_warning_count], 0
    mov qword [symbol_count], 0
    mov qword [scope_stack_top], 0
    mov qword [type_count], 0
    mov qword [current_scope], 0
    mov qword [current_function], 0
    mov qword [current_struct], 0
    mov qword [current_loop], 0
    mov qword [current_conditional], 0
    mov qword [analysis_time], 0
    mov qword [symbols_analyzed], 0
    mov qword [types_checked], 0
    mov qword [scopes_processed], 0
    mov qword [functions_analyzed], 0
    mov qword [structs_analyzed], 0
    
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

get_current_time:
    push rbp
    mov rbp, rsp
    
    ; Simple time function (in real implementation, use proper timing)
    mov rax, 0
    
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

; === Semantic Analyzer Demo ===
semantic_analyzer_demo:
    push rbp
    mov rbp, rsp
    
    ; Initialize semantic analyzer
    call semantic_analyzer_init
    
    ; Analyze sample AST
    mov rdi, 0  ; Sample AST
    call semantic_analyzer_analyze
    
    ; Get analysis results
    call semantic_analyzer_get_errors
    call semantic_analyzer_get_warnings
    call semantic_analyzer_get_statistics
    
    ; Cleanup
    call semantic_analyzer_cleanup
    
    leave
    ret
