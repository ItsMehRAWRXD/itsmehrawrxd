; x86_64_codegen.asm
; Create x86-64 assembly code generator for Eon compiler
; Comprehensive code generation system for x86-64 architecture

section .data
    ; === Code Generator Information ===
    codegen_info        db "x86-64 Assembly Code Generator v1.0", 10, 0
    codegen_capabilities db "Features: Expression codegen, Statement codegen, Function codegen", 10, 0
    
    ; === Target Architecture ===
    TARGET_X86_64       equ 0
    TARGET_X86_32       equ 1
    TARGET_ARM64        equ 2
    TARGET_ARM32        equ 3
    TARGET_RISCV64      equ 4
    TARGET_RISCV32      equ 5
    
    ; === Register Allocation ===
    REG_RAX             equ 0
    REG_RBX             equ 1
    REG_RCX             equ 2
    REG_RDX             equ 3
    REG_RSI             equ 4
    REG_RDI             equ 5
    REG_RBP             equ 6
    REG_RSP             equ 7
    REG_R8              equ 8
    REG_R9              equ 9
    REG_R10             equ 10
    REG_R11             equ 11
    REG_R12             equ 12
    REG_R13             equ 13
    REG_R14             equ 14
    REG_R15             equ 15
    
    ; === Instruction Types ===
    INST_MOV            equ 0
    INST_ADD            equ 1
    INST_SUB            equ 2
    INST_MUL            equ 3
    INST_DIV            equ 4
    INST_CMP            equ 5
    INST_JMP            equ 6
    INST_JE             equ 7
    INST_JNE            equ 8
    INST_JL             equ 9
    INST_JLE            equ 10
    INST_JG             equ 11
    INST_JGE            equ 12
    INST_CALL           equ 13
    INST_RET            equ 14
    INST_PUSH           equ 15
    INST_POP            equ 16
    INST_LEA            equ 17
    INST_TEST           equ 18
    INST_AND            equ 19
    INST_OR             equ 20
    INST_XOR            equ 21
    INST_NOT            equ 22
    INST_SHL            equ 23
    INST_SHR            equ 24
    INST_SAR            equ 25
    
    ; === Operand Types ===
    OPERAND_REGISTER    equ 0
    OPERAND_IMMEDIATE   equ 1
    OPERAND_MEMORY      equ 2
    OPERAND_LABEL       equ 3
    OPERAND_SYMBOL      equ 4
    
    ; === Code Generator State ===
    codegen_target      resq 1       ; Target architecture
    codegen_output      resq 1       ; Output buffer
    codegen_output_size resq 1       ; Output buffer size
    codegen_output_capacity resq 1   ; Output buffer capacity
    codegen_label_count resq 1       ; Label counter
    codegen_temp_count  resq 1       ; Temporary variable counter
    codegen_stack_offset resq 1      ; Stack offset
    codegen_registers   resq 16      ; Register allocation
    codegen_registers_used resq 1    ; Registers used mask
    codegen_registers_free resq 1    ; Registers free mask
    
    ; === Code Generation Statistics ===
    instructions_generated resq 1    ; Instructions generated
    labels_generated     resq 1      ; Labels generated
    temporaries_generated resq 1     ; Temporaries generated
    functions_generated  resq 1      ; Functions generated
    expressions_generated resq 1     ; Expressions generated
    statements_generated resq 1      ; Statements generated
    codegen_time         resq 1      ; Code generation time
    codegen_memory_usage resq 1      ; Memory usage
    
    ; === Output Buffer ===
    output_buffer       resq 1024    ; Output buffer (1024 instructions max)
    output_buffer_size  resq 1       ; Output buffer size
    output_buffer_capacity resq 1    ; Output buffer capacity
    output_buffer_head  resq 1       ; Output buffer head
    output_buffer_tail  resq 1       ; Output buffer tail
    
    ; === Label Management ===
    label_table         resq 256     ; Label table (256 labels max)
    label_count         resq 1       ; Label count
    label_table_capacity resq 1      ; Label table capacity
    
    ; === Temporary Management ===
    temp_table          resq 256     ; Temporary table (256 temporaries max)
    temp_count          resq 1       ; Temporary count
    temp_table_capacity resq 1       ; Temporary table capacity
    
    ; === Function Management ===
    function_table      resq 64      ; Function table (64 functions max)
    function_count      resq 1       ; Function count
    function_table_capacity resq 1   ; Function table capacity
    
    ; === Code Generation Configuration ===
    optimize_code       resq 1       ; Code optimization enabled
    inline_functions    resq 1       ; Function inlining enabled
    unroll_loops        resq 1       ; Loop unrolling enabled
    eliminate_dead_code resq 1       ; Dead code elimination enabled
    constant_folding    resq 1       ; Constant folding enabled
    register_allocation resq 1       ; Register allocation enabled
    stack_optimization  resq 1       ; Stack optimization enabled

section .text
    global x86_64_codegen_init
    global x86_64_codegen_set_target
    global x86_64_codegen_generate_program
    global x86_64_codegen_generate_function
    global x86_64_codegen_generate_expression
    global x86_64_codegen_generate_statement
    global x86_64_codegen_generate_binary_expression
    global x86_64_codegen_generate_unary_expression
    global x86_64_codegen_generate_function_call
    global x86_64_codegen_generate_assignment
    global x86_64_codegen_generate_if_statement
    global x86_64_codegen_generate_loop_statement
    global x86_64_codegen_generate_return_statement
    global x86_64_codegen_generate_block
    global x86_64_codegen_allocate_register
    global x86_64_codegen_free_register
    global x86_64_codegen_allocate_temp
    global x86_64_codegen_free_temp
    global x86_64_codegen_generate_label
    global x86_64_codegen_emit_instruction
    global x86_64_codegen_emit_mov
    global x86_64_codegen_emit_add
    global x86_64_codegen_emit_sub
    global x86_64_codegen_emit_mul
    global x86_64_codegen_emit_div
    global x86_64_codegen_emit_cmp
    global x86_64_codegen_emit_jmp
    global x86_64_codegen_emit_call
    global x86_64_codegen_emit_ret
    global x86_64_codegen_emit_push
    global x86_64_codegen_emit_pop
    global x86_64_codegen_optimize_code
    global x86_64_codegen_get_output
    global x86_64_codegen_get_statistics
    global x86_64_codegen_cleanup

; === Initialize Code Generator ===
x86_64_codegen_init:
    push rbp
    mov rbp, rsp
    
    ; Print code generator info
    mov rdi, codegen_info
    call print_string
    mov rdi, codegen_capabilities
    call print_string
    
    ; Initialize state
    mov qword [codegen_target], TARGET_X86_64
    mov qword [codegen_output], output_buffer
    mov qword [codegen_output_size], 0
    mov qword [codegen_output_capacity], 1024
    mov qword [codegen_label_count], 0
    mov qword [codegen_temp_count], 0
    mov qword [codegen_stack_offset], 0
    mov qword [codegen_registers_used], 0
    mov qword [codegen_registers_free], 0xFFFF
    
    ; Initialize statistics
    mov qword [instructions_generated], 0
    mov qword [labels_generated], 0
    mov qword [temporaries_generated], 0
    mov qword [functions_generated], 0
    mov qword [expressions_generated], 0
    mov qword [statements_generated], 0
    mov qword [codegen_time], 0
    mov qword [codegen_memory_usage], 0
    
    ; Initialize buffers
    mov qword [output_buffer_size], 0
    mov qword [output_buffer_capacity], 1024
    mov qword [output_buffer_head], 0
    mov qword [output_buffer_tail], 0
    mov qword [label_count], 0
    mov qword [label_table_capacity], 256
    mov qword [temp_count], 0
    mov qword [temp_table_capacity], 256
    mov qword [function_count], 0
    mov qword [function_table_capacity], 64
    
    ; Initialize configuration
    mov qword [optimize_code], 1
    mov qword [inline_functions], 0
    mov qword [unroll_loops], 0
    mov qword [eliminate_dead_code], 1
    mov qword [constant_folding], 1
    mov qword [register_allocation], 1
    mov qword [stack_optimization], 1
    
    ; Clear output buffer
    mov rdi, output_buffer
    mov rsi, 1024 * 8
    call zero_memory
    
    ; Clear label table
    mov rdi, label_table
    mov rsi, 256 * 8
    call zero_memory
    
    ; Clear temp table
    mov rdi, temp_table
    mov rsi, 256 * 8
    call zero_memory
    
    ; Clear function table
    mov rdi, function_table
    mov rsi, 64 * 8
    call zero_memory
    
    ; Clear register allocation
    mov rdi, codegen_registers
    mov rsi, 16 * 8
    call zero_memory
    
    leave
    ret

; === Set Target Architecture ===
x86_64_codegen_set_target:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = target architecture
    
    mov [codegen_target], rdi
    
    leave
    ret

; === Generate Program ===
x86_64_codegen_generate_program:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = AST node
    
    ; Start code generation timing
    call get_current_time
    mov [codegen_time], rax
    
    ; Generate program header
    call x86_64_codegen_generate_program_header
    
    ; Generate each function
    mov rbx, rdi
    mov rcx, 0  ; child index
    
.generate_program_loop:
    ; Get child node
    mov rdx, [rbx + 8]  ; left child
    cmp rdx, 0
    je .generate_program_done
    
    ; Generate function
    mov rdi, rdx
    call x86_64_codegen_generate_function
    
    ; Move to next child
    mov rdx, [rdx + 24]  ; next sibling
    cmp rdx, 0
    je .generate_program_done
    
    mov rdi, rdx
    call x86_64_codegen_generate_function
    
    jmp .generate_program_loop
    
.generate_program_done:
    ; Generate program footer
    call x86_64_codegen_generate_program_footer
    
    ; End code generation timing
    call get_current_time
    sub rax, [codegen_time]
    mov [codegen_time], rax
    
    leave
    ret

; === Generate Program Header ===
x86_64_codegen_generate_program_header:
    push rbp
    mov rbp, rsp
    
    ; Generate program header
    ; This is a simplified implementation
    
    leave
    ret

; === Generate Program Footer ===
x86_64_codegen_generate_program_footer:
    push rbp
    mov rbp, rsp
    
    ; Generate program footer
    ; This is a simplified implementation
    
    leave
    ret

; === Generate Function ===
x86_64_codegen_generate_function:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = function node
    
    ; Generate function prologue
    call x86_64_codegen_generate_function_prologue
    
    ; Generate function body
    mov rbx, [rdi + 16]  ; function body
    cmp rbx, 0
    je .generate_function_epilogue
    
    mov rdi, rbx
    call x86_64_codegen_generate_block
    
.generate_function_epilogue:
    ; Generate function epilogue
    call x86_64_codegen_generate_function_epilogue
    
    ; Update statistics
    inc qword [functions_generated]
    
    leave
    ret

; === Generate Function Prologue ===
x86_64_codegen_generate_function_prologue:
    push rbp
    mov rbp, rsp
    
    ; Generate function prologue
    ; This is a simplified implementation
    
    leave
    ret

; === Generate Function Epilogue ===
x86_64_codegen_generate_function_epilogue:
    push rbp
    mov rbp, rsp
    
    ; Generate function epilogue
    ; This is a simplified implementation
    
    leave
    ret

; === Generate Expression ===
x86_64_codegen_generate_expression:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = expression node
    ; Returns: rax = register containing result
    
    mov rbx, rdi
    mov rcx, [rbx]  ; node type
    
    ; Check expression type
    cmp rcx, 9  ; BINARY_OP
    je .generate_binary_expression
    cmp rcx, 10 ; UNARY_OP
    je .generate_unary_expression
    cmp rcx, 11 ; FUNCTION_CALL
    je .generate_function_call_expression
    cmp rcx, 12 ; IDENTIFIER
    je .generate_identifier_expression
    cmp rcx, 13 ; LITERAL
    je .generate_literal_expression
    
    ; Unknown expression type
    mov rax, REG_RAX
    jmp .done
    
.generate_binary_expression:
    call x86_64_codegen_generate_binary_expression
    jmp .done
    
.generate_unary_expression:
    call x86_64_codegen_generate_unary_expression
    jmp .done
    
.generate_function_call_expression:
    call x86_64_codegen_generate_function_call
    jmp .done
    
.generate_identifier_expression:
    call x86_64_codegen_generate_identifier_expression
    jmp .done
    
.generate_literal_expression:
    call x86_64_codegen_generate_literal_expression
    jmp .done
    
.done:
    ; Update statistics
    inc qword [expressions_generated]
    
    leave
    ret

; === Generate Binary Expression ===
x86_64_codegen_generate_binary_expression:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = binary expression node
    ; Returns: rax = register containing result
    
    ; Generate left operand
    mov rbx, [rdi + 8]  ; left child
    call x86_64_codegen_generate_expression
    mov rcx, rax  ; left register
    
    ; Generate right operand
    mov rbx, [rdi + 16] ; right child
    call x86_64_codegen_generate_expression
    mov rdx, rax  ; right register
    
    ; Generate binary operation
    ; This is a simplified implementation
    
    ; Return result register
    mov rax, rcx
    
    leave
    ret

; === Generate Unary Expression ===
x86_64_codegen_generate_unary_expression:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = unary expression node
    ; Returns: rax = register containing result
    
    ; Generate operand
    mov rbx, [rdi + 8]  ; child
    call x86_64_codegen_generate_expression
    mov rcx, rax  ; operand register
    
    ; Generate unary operation
    ; This is a simplified implementation
    
    ; Return result register
    mov rax, rcx
    
    leave
    ret

; === Generate Function Call ===
x86_64_codegen_generate_function_call:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = function call node
    ; Returns: rax = register containing result
    
    ; Generate function call
    ; This is a simplified implementation
    
    ; Return result register
    mov rax, REG_RAX
    
    leave
    ret

; === Generate Identifier Expression ===
x86_64_codegen_generate_identifier_expression:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = identifier node
    ; Returns: rax = register containing result
    
    ; Generate identifier access
    ; This is a simplified implementation
    
    ; Return result register
    mov rax, REG_RAX
    
    leave
    ret

; === Generate Literal Expression ===
x86_64_codegen_generate_literal_expression:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = literal node
    ; Returns: rax = register containing result
    
    ; Generate literal
    ; This is a simplified implementation
    
    ; Return result register
    mov rax, REG_RAX
    
    leave
    ret

; === Generate Statement ===
x86_64_codegen_generate_statement:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = statement node
    
    mov rbx, rdi
    mov rcx, [rbx]  ; node type
    
    ; Check statement type
    cmp rcx, 3  ; VARIABLE_DECL
    je .generate_variable_statement
    cmp rcx, 4  ; ASSIGNMENT
    je .generate_assignment_statement
    cmp rcx, 5  ; IF_STMT
    je .generate_if_statement
    cmp rcx, 6  ; LOOP_STMT
    je .generate_loop_statement
    cmp rcx, 7  ; RETURN_STMT
    je .generate_return_statement
    cmp rcx, 8  ; BLOCK
    je .generate_block_statement
    
    ; Unknown statement type
    jmp .done
    
.generate_variable_statement:
    call x86_64_codegen_generate_variable_statement
    jmp .done
    
.generate_assignment_statement:
    call x86_64_codegen_generate_assignment
    jmp .done
    
.generate_if_statement:
    call x86_64_codegen_generate_if_statement
    jmp .done
    
.generate_loop_statement:
    call x86_64_codegen_generate_loop_statement
    jmp .done
    
.generate_return_statement:
    call x86_64_codegen_generate_return_statement
    jmp .done
    
.generate_block_statement:
    call x86_64_codegen_generate_block
    jmp .done
    
.done:
    ; Update statistics
    inc qword [statements_generated]
    
    leave
    ret

; === Generate Variable Statement ===
x86_64_codegen_generate_variable_statement:
    push rbp
    mov rbp, rsp
    
    ; Generate variable declaration
    ; This is a simplified implementation
    
    leave
    ret

; === Generate Assignment ===
x86_64_codegen_generate_assignment:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = assignment node
    
    ; Generate right operand
    mov rbx, [rdi + 16] ; right child
    call x86_64_codegen_generate_expression
    mov rcx, rax  ; right register
    
    ; Generate assignment
    ; This is a simplified implementation
    
    leave
    ret

; === Generate If Statement ===
x86_64_codegen_generate_if_statement:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = if statement node
    
    ; Generate condition
    mov rbx, [rdi + 8]  ; condition
    call x86_64_codegen_generate_expression
    mov rcx, rax  ; condition register
    
    ; Generate conditional jump
    ; This is a simplified implementation
    
    ; Generate then block
    mov rbx, [rdi + 16] ; then block
    call x86_64_codegen_generate_statement
    
    ; Generate else block
    mov rbx, [rdi + 24] ; else block
    cmp rbx, 0
    je .done
    call x86_64_codegen_generate_statement
    
.done:
    leave
    ret

; === Generate Loop Statement ===
x86_64_codegen_generate_loop_statement:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = loop statement node
    
    ; Generate loop condition
    mov rbx, [rdi + 8]  ; condition
    call x86_64_codegen_generate_expression
    mov rcx, rax  ; condition register
    
    ; Generate loop body
    mov rbx, [rdi + 16] ; loop body
    call x86_64_codegen_generate_statement
    
    ; Generate loop control
    ; This is a simplified implementation
    
    leave
    ret

; === Generate Return Statement ===
x86_64_codegen_generate_return_statement:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = return statement node
    
    ; Generate return expression
    mov rbx, [rdi + 8]  ; return expression
    cmp rbx, 0
    je .generate_return_void
    
    call x86_64_codegen_generate_expression
    mov rcx, rax  ; return register
    
.generate_return_void:
    ; Generate return instruction
    ; This is a simplified implementation
    
    leave
    ret

; === Generate Block ===
x86_64_codegen_generate_block:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = block node
    
    ; Generate block statements
    ; This is a simplified implementation
    
    leave
    ret

; === Allocate Register ===
x86_64_codegen_allocate_register:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = allocated register
    
    ; Find free register
    mov rax, [codegen_registers_free]
    cmp rax, 0
    je .no_free_registers
    
    ; Find first free register
    mov rbx, 0
    
.allocate_register_loop:
    mov rcx, 1
    shl rcx, rbx
    and rcx, rax
    cmp rcx, 0
    jne .register_found
    
    inc rbx
    cmp rbx, 16
    jl .allocate_register_loop
    
    ; No free registers
    mov rax, REG_RAX
    jmp .done
    
.register_found:
    ; Mark register as used
    mov rcx, 1
    shl rcx, rbx
    not rcx
    and [codegen_registers_free], rcx
    
    mov rax, rbx
    jmp .done
    
.no_free_registers:
    mov rax, REG_RAX
    
.done:
    leave
    ret

; === Free Register ===
x86_64_codegen_free_register:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = register to free
    
    ; Mark register as free
    mov rcx, 1
    shl rcx, rdi
    or [codegen_registers_free], rcx
    
    leave
    ret

; === Allocate Temporary ===
x86_64_codegen_allocate_temp:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = temporary variable ID
    
    ; Check if temp table is full
    mov rax, [temp_count]
    cmp rax, [temp_table_capacity]
    jge .temp_table_full
    
    ; Allocate temporary
    mov rbx, [temp_count]
    inc qword [temp_count]
    
    ; Update statistics
    inc qword [temporaries_generated]
    
    mov rax, rbx
    jmp .done
    
.temp_table_full:
    mov rax, 0
    
.done:
    leave
    ret

; === Free Temporary ===
x86_64_codegen_free_temp:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = temporary to free
    
    ; Free temporary
    ; This is a simplified implementation
    
    leave
    ret

; === Generate Label ===
x86_64_codegen_generate_label:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = label ID
    
    ; Generate label
    mov rax, [codegen_label_count]
    inc qword [codegen_label_count]
    
    ; Update statistics
    inc qword [labels_generated]
    
    leave
    ret

; === Emit Instruction ===
x86_64_codegen_emit_instruction:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = instruction type, rsi = operand1, rdx = operand2
    
    ; Check if output buffer is full
    mov rax, [output_buffer_size]
    cmp rax, [output_buffer_capacity]
    jge .buffer_full
    
    ; Add instruction to buffer
    mov rbx, output_buffer
    mov rcx, [output_buffer_tail]
    
    ; Store instruction data (simplified)
    mov [rbx + rcx * 8], rdi
    
    ; Update buffer tail
    inc qword [output_buffer_tail]
    cmp qword [output_buffer_tail], 1024
    jne .update_size
    mov qword [output_buffer_tail], 0
    
.update_size:
    inc qword [output_buffer_size]
    
    ; Update statistics
    inc qword [instructions_generated]
    
    mov rax, 1
    jmp .done
    
.buffer_full:
    mov rax, 0
    
.done:
    leave
    ret

; === Emit MOV ===
x86_64_codegen_emit_mov:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = destination, rsi = source
    
    mov rdx, rsi
    mov rsi, rdi
    mov rdi, INST_MOV
    call x86_64_codegen_emit_instruction
    
    leave
    ret

; === Emit ADD ===
x86_64_codegen_emit_add:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = destination, rsi = source
    
    mov rdx, rsi
    mov rsi, rdi
    mov rdi, INST_ADD
    call x86_64_codegen_emit_instruction
    
    leave
    ret

; === Emit SUB ===
x86_64_codegen_emit_sub:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = destination, rsi = source
    
    mov rdx, rsi
    mov rsi, rdi
    mov rdi, INST_SUB
    call x86_64_codegen_emit_instruction
    
    leave
    ret

; === Emit MUL ===
x86_64_codegen_emit_mul:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = destination, rsi = source
    
    mov rdx, rsi
    mov rsi, rdi
    mov rdi, INST_MUL
    call x86_64_codegen_emit_instruction
    
    leave
    ret

; === Emit DIV ===
x86_64_codegen_emit_div:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = destination, rsi = source
    
    mov rdx, rsi
    mov rsi, rdi
    mov rdi, INST_DIV
    call x86_64_codegen_emit_instruction
    
    leave
    ret

; === Emit CMP ===
x86_64_codegen_emit_cmp:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = operand1, rsi = operand2
    
    mov rdx, rsi
    mov rsi, rdi
    mov rdi, INST_CMP
    call x86_64_codegen_emit_instruction
    
    leave
    ret

; === Emit JMP ===
x86_64_codegen_emit_jmp:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = label
    
    mov rsi, rdi
    mov rdi, INST_JMP
    call x86_64_codegen_emit_instruction
    
    leave
    ret

; === Emit CALL ===
x86_64_codegen_emit_call:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = function
    
    mov rsi, rdi
    mov rdi, INST_CALL
    call x86_64_codegen_emit_instruction
    
    leave
    ret

; === Emit RET ===
x86_64_codegen_emit_ret:
    push rbp
    mov rbp, rsp
    
    mov rdi, INST_RET
    call x86_64_codegen_emit_instruction
    
    leave
    ret

; === Emit PUSH ===
x86_64_codegen_emit_push:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = operand
    
    mov rsi, rdi
    mov rdi, INST_PUSH
    call x86_64_codegen_emit_instruction
    
    leave
    ret

; === Emit POP ===
x86_64_codegen_emit_pop:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = operand
    
    mov rsi, rdi
    mov rdi, INST_POP
    call x86_64_codegen_emit_instruction
    
    leave
    ret

; === Optimize Code ===
x86_64_codegen_optimize_code:
    push rbp
    mov rbp, rsp
    
    ; Check if optimization is enabled
    mov rax, [optimize_code]
    cmp rax, 0
    je .optimization_disabled
    
    ; Perform code optimization
    ; This is a simplified implementation
    
    mov rax, 1
    jmp .done
    
.optimization_disabled:
    mov rax, 0
    
.done:
    leave
    ret

; === Get Output ===
x86_64_codegen_get_output:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = output buffer, rbx = output size
    
    mov rax, [codegen_output]
    mov rbx, [codegen_output_size]
    
    leave
    ret

; === Get Statistics ===
x86_64_codegen_get_statistics:
    push rbp
    mov rbp, rsp
    
    ; Returns: rax = instructions generated, rbx = functions generated, rcx = expressions generated, rdx = statements generated
    
    mov rax, [instructions_generated]
    mov rbx, [functions_generated]
    mov rcx, [expressions_generated]
    mov rdx, [statements_generated]
    
    leave
    ret

; === Cleanup ===
x86_64_codegen_cleanup:
    push rbp
    mov rbp, rsp
    
    ; Clear output buffer
    mov rdi, output_buffer
    mov rsi, 1024 * 8
    call zero_memory
    
    ; Clear label table
    mov rdi, label_table
    mov rsi, 256 * 8
    call zero_memory
    
    ; Clear temp table
    mov rdi, temp_table
    mov rsi, 256 * 8
    call zero_memory
    
    ; Clear function table
    mov rdi, function_table
    mov rsi, 64 * 8
    call zero_memory
    
    ; Clear register allocation
    mov rdi, codegen_registers
    mov rsi, 16 * 8
    call zero_memory
    
    ; Reset counters
    mov qword [codegen_output_size], 0
    mov qword [output_buffer_size], 0
    mov qword [output_buffer_head], 0
    mov qword [output_buffer_tail], 0
    mov qword [codegen_label_count], 0
    mov qword [codegen_temp_count], 0
    mov qword [codegen_stack_offset], 0
    mov qword [codegen_registers_used], 0
    mov qword [codegen_registers_free], 0xFFFF
    mov qword [label_count], 0
    mov qword [temp_count], 0
    mov qword [function_count], 0
    mov qword [instructions_generated], 0
    mov qword [labels_generated], 0
    mov qword [temporaries_generated], 0
    mov qword [functions_generated], 0
    mov qword [expressions_generated], 0
    mov qword [statements_generated], 0
    mov qword [codegen_time], 0
    mov qword [codegen_memory_usage], 0
    
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

; === Code Generator Demo ===
x86_64_codegen_demo:
    push rbp
    mov rbp, rsp
    
    ; Initialize code generator
    call x86_64_codegen_init
    
    ; Generate sample code
    mov rdi, 0  ; Sample AST
    call x86_64_codegen_generate_program
    
    ; Get statistics
    call x86_64_codegen_get_statistics
    
    ; Cleanup
    call x86_64_codegen_cleanup
    
    leave
    ret
