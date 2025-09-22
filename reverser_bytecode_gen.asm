; reverser_bytecode_gen.asm
; Bytecode generator for Reverser language
; Translates AST into bytecode for the stack-based runtime

%include "reverser_ast.asm"
%include "reverser_runtime.asm"

section .data
    ; Bytecode instruction opcodes
    OP_PUSH_IMM    equ 0x01
    OP_PUSH_VAR    equ 0x02
    OP_POP_VAR     equ 0x03
    OP_ADD         equ 0x04
    OP_SUB         equ 0x05
    OP_MUL         equ 0x06
    OP_DIV         equ 0x07
    OP_CALL        equ 0x08
    OP_RET         equ 0x09
    OP_JMP         equ 0x0A
    OP_JZ          equ 0x0B
    OP_ALLOC       equ 0x0C
    OP_FREE        equ 0x0D
    OP_DUP         equ 0x0E
    OP_SWAP        equ 0x0F
    OP_ROT         equ 0x10
    OP_GT          equ 0x11
    OP_LT          equ 0x12
    OP_EQ          equ 0x13
    OP_NE          equ 0x14
    OP_AND         equ 0x15
    OP_OR          equ 0x16
    OP_NOT         equ 0x17
    OP_LOAD        equ 0x18
    OP_STORE       equ 0x19
    OP_GET_FIELD   equ 0x1A
    OP_SET_FIELD   equ 0x1B
    OP_NEW_OBJECT  equ 0x1C
    OP_DELETE      equ 0x1D
    OP_CAST        equ 0x1E
    OP_SIZE_OF     equ 0x1F
    OP_ADDR_OF     equ 0x20
    OP_DEREF       equ 0x21

    ; Bytecode buffer
    bytecode_buffer     resb 65536  ; 64KB bytecode buffer
    bytecode_size       resq 1      ; Current bytecode size
    bytecode_pos        resq 1      ; Current position in buffer
    
    ; Function table
    function_table      resq 256    ; Function addresses
    function_count      resq 1      ; Number of functions
    
    ; Variable table
    variable_table      resq 1024   ; Variable addresses
    variable_count      resq 1      ; Number of variables
    
    ; String table
    string_table        resb 8192   ; String constants
    string_count        resq 1      ; Number of strings

section .text
    global bytecode_init
    global bytecode_generate
    global bytecode_emit
    global bytecode_emit_imm
    global bytecode_emit_jump
    global bytecode_emit_call
    global bytecode_get_function_id
    global bytecode_get_variable_id
    global bytecode_get_string_id

; Initialize bytecode generator
bytecode_init:
    push rbx
    
    mov qword [bytecode_size], 0
    mov qword [bytecode_pos], 0
    mov qword [function_count], 0
    mov qword [variable_count], 0
    mov qword [string_count], 0
    
    ; Clear tables
    mov rcx, 256
    mov rdi, function_table
    xor rax, rax
    rep stosq
    
    mov rcx, 1024
    mov rdi, variable_table
    xor rax, rax
    rep stosq
    
    pop rbx
    ret

; Generate bytecode from AST
; Input: rdi = AST root node
; Output: rax = bytecode size
bytecode_generate:
    push rbx
    push rcx
    push rdx
    push rsi
    
    call bytecode_init
    
    ; Generate bytecode for each top-level node
    mov rbx, rdi
    call ast_get_child
    mov rbx, rax
    mov rcx, 0  ; Child index
    
.generate_loop:
    cmp rbx, 0
    je .generate_done
    
    mov rdi, rbx
    call ast_get_child
    cmp rax, 0
    je .next_node
    
    ; Generate bytecode for this node
    mov rdi, rax
    call generate_node_bytecode
    
.next_node:
    inc rcx
    mov rdi, rbx
    mov rsi, rcx
    call ast_get_child
    mov rbx, rax
    jmp .generate_loop

.generate_done:
    mov rax, [bytecode_size]
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; Generate bytecode for a specific AST node
; Input: rdi = AST node
generate_node_bytecode:
    push rbx
    push rcx
    push rdx
    
    mov rbx, rdi
    call ast_get_type
    mov rcx, rax
    
    ; Generate bytecode based on node type
    cmp rcx, AST_FUNCTION
    je .generate_function
    cmp rcx, AST_MODEL
    je .generate_model
    cmp rcx, AST_BLOCK
    je .generate_block
    cmp rcx, AST_VARIABLE
    je .generate_variable
    cmp rcx, AST_ASSIGNMENT
    je .generate_assignment
    cmp rcx, AST_RETURN
    je .generate_return
    cmp rcx, AST_IF
    je .generate_if
    cmp rcx, AST_LOOP
    je .generate_loop
    cmp rcx, AST_BINARY_OP
    je .generate_binary_op
    cmp rcx, AST_UNARY_OP
    je .generate_unary_op
    cmp rcx, AST_LITERAL
    je .generate_literal
    cmp rcx, AST_IDENTIFIER
    je .generate_identifier
    cmp rcx, AST_FUNCTION_CALL
    je .generate_function_call
    cmp rcx, AST_MEMBER_ACCESS
    je .generate_member_access
    cmp rcx, AST_ARRAY_ACCESS
    je .generate_array_access
    
    jmp .generate_done

.generate_function:
    call generate_function_bytecode
    jmp .generate_done

.generate_model:
    call generate_model_bytecode
    jmp .generate_done

.generate_block:
    call generate_block_bytecode
    jmp .generate_done

.generate_variable:
    call generate_variable_bytecode
    jmp .generate_done

.generate_assignment:
    call generate_assignment_bytecode
    jmp .generate_done

.generate_return:
    call generate_return_bytecode
    jmp .generate_done

.generate_if:
    call generate_if_bytecode
    jmp .generate_done

.generate_loop:
    call generate_loop_bytecode
    jmp .generate_done

.generate_binary_op:
    call generate_binary_op_bytecode
    jmp .generate_done

.generate_unary_op:
    call generate_unary_op_bytecode
    jmp .generate_done

.generate_literal:
    call generate_literal_bytecode
    jmp .generate_done

.generate_identifier:
    call generate_identifier_bytecode
    jmp .generate_done

.generate_function_call:
    call generate_function_call_bytecode
    jmp .generate_done

.generate_member_access:
    call generate_member_access_bytecode
    jmp .generate_done

.generate_array_access:
    call generate_array_access_bytecode
    jmp .generate_done

.generate_done:
    pop rdx
    pop rcx
    pop rbx
    ret

; Generate bytecode for function definition
generate_function_bytecode:
    push rbx
    push rcx
    push rdx
    
    ; Add function to function table
    mov rbx, [function_count]
    mov [function_table + rbx * 8], rdi
    inc qword [function_count]
    
    ; Generate function prologue
    mov al, OP_CALL
    call bytecode_emit
    
    ; Generate function body
    mov rdi, rbx
    mov rsi, 2  ; Get body child
    call ast_get_child
    cmp rax, 0
    je .function_done
    
    mov rdi, rax
    call generate_node_bytecode

.function_done:
    ; Generate function epilogue
    mov al, OP_RET
    call bytecode_emit
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Generate bytecode for model definition
generate_model_bytecode:
    push rbx
    push rcx
    
    ; Models are compile-time constructs, no runtime bytecode needed
    ; Just register the model type
    
    pop rcx
    pop rbx
    ret

; Generate bytecode for block
generate_block_bytecode:
    push rbx
    push rcx
    push rdx
    
    ; Generate bytecode for each statement in block
    mov rbx, rdi
    mov rcx, 0  ; Child index
    
.block_loop:
    mov rdi, rbx
    mov rsi, rcx
    call ast_get_child
    cmp rax, 0
    je .block_done
    
    mov rdi, rax
    call generate_node_bytecode
    
    inc rcx
    jmp .block_loop

.block_done:
    pop rdx
    pop rcx
    pop rbx
    ret

; Generate bytecode for variable declaration
generate_variable_bytecode:
    push rbx
    push rcx
    push rdx
    
    ; Add variable to variable table
    mov rbx, [variable_count]
    mov [variable_table + rbx * 8], rdi
    inc qword [variable_count]
    
    ; Generate initialization code
    mov rdi, rbx
    mov rsi, 1  ; Get initializer child
    call ast_get_child
    cmp rax, 0
    je .variable_done
    
    mov rdi, rax
    call generate_node_bytecode
    
    ; Store in variable
    mov al, OP_STORE
    call bytecode_emit
    mov rdi, rbx
    call bytecode_emit_imm

.variable_done:
    pop rdx
    pop rcx
    pop rbx
    ret

; Generate bytecode for assignment
generate_assignment_bytecode:
    push rbx
    push rcx
    push rdx
    
    ; Generate right-hand side
    mov rdi, rbx
    mov rsi, 1  ; Get RHS child
    call ast_get_child
    cmp rax, 0
    je .assignment_done
    
    mov rdi, rax
    call generate_node_bytecode
    
    ; Store in variable
    mov al, OP_STORE
    call bytecode_emit
    mov rdi, rbx
    call bytecode_emit_imm

.assignment_done:
    pop rdx
    pop rcx
    pop rbx
    ret

; Generate bytecode for return statement
generate_return_bytecode:
    push rbx
    push rcx
    push rdx
    
    ; Generate return value
    mov rdi, rbx
    mov rsi, 0  ; Get return value child
    call ast_get_child
    cmp rax, 0
    je .return_done
    
    mov rdi, rax
    call generate_node_bytecode

.return_done:
    ; Generate return instruction
    mov al, OP_RET
    call bytecode_emit
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Generate bytecode for if statement
generate_if_bytecode:
    push rbx
    push rcx
    push rdx
    
    ; Generate condition
    mov rdi, rbx
    mov rsi, 0  ; Get condition child
    call ast_get_child
    cmp rax, 0
    je .if_done
    
    mov rdi, rax
    call generate_node_bytecode
    
    ; Generate conditional jump
    mov al, OP_JZ
    call bytecode_emit
    mov rdi, 0  ; Placeholder for jump offset
    call bytecode_emit_imm
    
    ; Generate then block
    mov rdi, rbx
    mov rsi, 1  ; Get then child
    call ast_get_child
    cmp rax, 0
    je .if_done
    
    mov rdi, rax
    call generate_node_bytecode

.if_done:
    pop rdx
    pop rcx
    pop rbx
    ret

; Generate bytecode for loop statement
generate_loop_bytecode:
    push rbx
    push rcx
    push rdx
    
    ; Generate loop body
    mov rdi, rbx
    mov rsi, 0  ; Get body child
    call ast_get_child
    cmp rax, 0
    je .loop_done
    
    mov rdi, rax
    call generate_node_bytecode
    
    ; Generate loop back jump
    mov al, OP_JMP
    call bytecode_emit
    mov rdi, 0  ; Placeholder for jump offset
    call bytecode_emit_imm

.loop_done:
    pop rdx
    pop rcx
    pop rbx
    ret

; Generate bytecode for binary operation
generate_binary_op_bytecode:
    push rbx
    push rcx
    push rdx
    
    ; Generate left operand
    mov rdi, rbx
    mov rsi, 0  ; Get left child
    call ast_get_child
    cmp rax, 0
    je .binary_done
    
    mov rdi, rax
    call generate_node_bytecode
    
    ; Generate right operand
    mov rdi, rbx
    mov rsi, 1  ; Get right child
    call ast_get_child
    cmp rax, 0
    je .binary_done
    
    mov rdi, rax
    call generate_node_bytecode
    
    ; Generate operation
    mov rdi, rbx
    call ast_get_type
    mov rcx, rax
    
    cmp rcx, TOKEN_PLUS
    je .emit_add
    cmp rcx, TOKEN_MINUS
    je .emit_sub
    cmp rcx, TOKEN_MULTIPLY
    je .emit_mul
    cmp rcx, TOKEN_DIVIDE
    je .emit_div
    cmp rcx, TOKEN_GT
    je .emit_gt
    cmp rcx, TOKEN_LT
    je .emit_lt
    cmp rcx, TOKEN_EQ
    je .emit_eq
    cmp rcx, TOKEN_NE
    je .emit_ne
    cmp rcx, TOKEN_AND
    je .emit_and
    cmp rcx, TOKEN_OR
    je .emit_or
    
    jmp .binary_done

.emit_add:
    mov al, OP_ADD
    call bytecode_emit
    jmp .binary_done

.emit_sub:
    mov al, OP_SUB
    call bytecode_emit
    jmp .binary_done

.emit_mul:
    mov al, OP_MUL
    call bytecode_emit
    jmp .binary_done

.emit_div:
    mov al, OP_DIV
    call bytecode_emit
    jmp .binary_done

.emit_gt:
    mov al, OP_GT
    call bytecode_emit
    jmp .binary_done

.emit_lt:
    mov al, OP_LT
    call bytecode_emit
    jmp .binary_done

.emit_eq:
    mov al, OP_EQ
    call bytecode_emit
    jmp .binary_done

.emit_ne:
    mov al, OP_NE
    call bytecode_emit
    jmp .binary_done

.emit_and:
    mov al, OP_AND
    call bytecode_emit
    jmp .binary_done

.emit_or:
    mov al, OP_OR
    call bytecode_emit
    jmp .binary_done

.binary_done:
    pop rdx
    pop rcx
    pop rbx
    ret

; Generate bytecode for unary operation
generate_unary_op_bytecode:
    push rbx
    push rcx
    push rdx
    
    ; Generate operand
    mov rdi, rbx
    mov rsi, 0  ; Get operand child
    call ast_get_child
    cmp rax, 0
    je .unary_done
    
    mov rdi, rax
    call generate_node_bytecode
    
    ; Generate operation
    mov rdi, rbx
    call ast_get_type
    mov rcx, rax
    
    cmp rcx, TOKEN_NOT
    je .emit_not
    cmp rcx, TOKEN_MINUS
    je .emit_neg
    cmp rcx, TOKEN_AMPERSAND
    je .emit_addr_of
    cmp rcx, TOKEN_STAR
    je .emit_deref
    
    jmp .unary_done

.emit_not:
    mov al, OP_NOT
    call bytecode_emit
    jmp .unary_done

.emit_neg:
    mov al, OP_SUB
    call bytecode_emit
    jmp .unary_done

.emit_addr_of:
    mov al, OP_ADDR_OF
    call bytecode_emit
    jmp .unary_done

.emit_deref:
    mov al, OP_DEREF
    call bytecode_emit
    jmp .unary_done

.unary_done:
    pop rdx
    pop rcx
    pop rbx
    ret

; Generate bytecode for literal
generate_literal_bytecode:
    push rbx
    push rcx
    push rdx
    
    ; Get literal value
    mov rdi, rbx
    call ast_get_value
    mov rcx, rax  ; Value pointer
    mov rdx, rdx  ; Value length
    
    ; Generate push immediate
    mov al, OP_PUSH_IMM
    call bytecode_emit
    
    ; Convert string to number if needed
    mov rdi, rcx
    call string_to_number
    mov rdi, rax
    call bytecode_emit_imm
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Generate bytecode for identifier
generate_identifier_bytecode:
    push rbx
    push rcx
    push rdx
    
    ; Get identifier name
    mov rdi, rbx
    call ast_get_value
    mov rcx, rax  ; Name pointer
    
    ; Look up variable
    mov rdi, rcx
    call bytecode_get_variable_id
    mov rdx, rax  ; Variable ID
    
    ; Generate load variable
    mov al, OP_LOAD
    call bytecode_emit
    mov rdi, rdx
    call bytecode_emit_imm
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Generate bytecode for function call
generate_function_call_bytecode:
    push rbx
    push rcx
    push rdx
    
    ; Get function name
    mov rdi, rbx
    call ast_get_value
    mov rcx, rax  ; Name pointer
    
    ; Look up function
    mov rdi, rcx
    call bytecode_get_function_id
    mov rdx, rax  ; Function ID
    
    ; Generate arguments
    mov rdi, rbx
    mov rsi, 0  ; Get arguments child
    call ast_get_child
    cmp rax, 0
    je .call_done
    
    mov rdi, rax
    call generate_node_bytecode

.call_done:
    ; Generate function call
    mov al, OP_CALL
    call bytecode_emit
    mov rdi, rdx
    call bytecode_emit_imm
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Generate bytecode for member access
generate_member_access_bytecode:
    push rbx
    push rcx
    push rdx
    
    ; Generate object
    mov rdi, rbx
    mov rsi, 0  ; Get object child
    call ast_get_child
    cmp rax, 0
    je .member_done
    
    mov rdi, rax
    call generate_node_bytecode
    
    ; Generate field access
    mov al, OP_GET_FIELD
    call bytecode_emit
    mov rdi, rbx
    call ast_get_value
    mov rdi, rax
    call bytecode_emit_imm

.member_done:
    pop rdx
    pop rcx
    pop rbx
    ret

; Generate bytecode for array access
generate_array_access_bytecode:
    push rbx
    push rcx
    push rdx
    
    ; Generate array
    mov rdi, rbx
    mov rsi, 0  ; Get array child
    call ast_get_child
    cmp rax, 0
    je .array_done
    
    mov rdi, rax
    call generate_node_bytecode
    
    ; Generate index
    mov rdi, rbx
    mov rsi, 1  ; Get index child
    call ast_get_child
    cmp rax, 0
    je .array_done
    
    mov rdi, rax
    call generate_node_bytecode
    
    ; Generate array access
    mov al, OP_LOAD
    call bytecode_emit

.array_done:
    pop rdx
    pop rcx
    pop rbx
    ret

; Emit a bytecode instruction
; Input: al = instruction opcode
bytecode_emit:
    push rbx
    push rcx
    
    mov rbx, [bytecode_pos]
    mov rcx, bytecode_buffer
    add rcx, rbx
    mov [rcx], al
    
    inc qword [bytecode_pos]
    inc qword [bytecode_size]
    
    pop rcx
    pop rbx
    ret

; Emit an immediate value
; Input: rdi = immediate value
bytecode_emit_imm:
    push rbx
    push rcx
    push rdx
    
    mov rbx, [bytecode_pos]
    mov rcx, bytecode_buffer
    add rcx, rbx
    mov [rcx], rdi
    
    add qword [bytecode_pos], 8
    add qword [bytecode_size], 8
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Emit a jump instruction
; Input: rdi = jump offset
bytecode_emit_jump:
    push rbx
    push rcx
    push rdx
    
    mov rbx, [bytecode_pos]
    mov rcx, bytecode_buffer
    add rcx, rbx
    mov [rcx], edi  ; 32-bit offset
    
    add qword [bytecode_pos], 4
    add qword [bytecode_size], 4
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Emit a function call
; Input: rdi = function ID
bytecode_emit_call:
    push rbx
    push rcx
    push rdx
    
    mov al, OP_CALL
    call bytecode_emit
    mov rdi, rdi
    call bytecode_emit_imm
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Get function ID by name
; Input: rdi = function name
; Output: rax = function ID or -1 if not found
bytecode_get_function_id:
    push rbx
    push rcx
    push rdx
    
    mov rbx, 0
.find_loop:
    cmp rbx, [function_count]
    jge .not_found
    
    mov rcx, [function_table + rbx * 8]
    cmp rcx, rdi
    je .found
    
    inc rbx
    jmp .find_loop

.found:
    mov rax, rbx
    jmp .return

.not_found:
    mov rax, -1

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Get variable ID by name
; Input: rdi = variable name
; Output: rax = variable ID or -1 if not found
bytecode_get_variable_id:
    push rbx
    push rcx
    push rdx
    
    mov rbx, 0
.find_loop:
    cmp rbx, [variable_count]
    jge .not_found
    
    mov rcx, [variable_table + rbx * 8]
    cmp rcx, rdi
    je .found
    
    inc rbx
    jmp .find_loop

.found:
    mov rax, rbx
    jmp .return

.not_found:
    mov rax, -1

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Get string ID by value
; Input: rdi = string value
; Output: rax = string ID or -1 if not found
bytecode_get_string_id:
    push rbx
    push rcx
    push rdx
    
    mov rbx, 0
.find_loop:
    cmp rbx, [string_count]
    jge .not_found
    
    mov rcx, string_table
    add rcx, rbx
    cmp rcx, rdi
    je .found
    
    inc rbx
    jmp .find_loop

.found:
    mov rax, rbx
    jmp .return

.not_found:
    mov rax, -1

.return:
    pop rdx
    pop rcx
    pop rbx
    ret

; Convert string to number
; Input: rdi = string pointer
; Output: rax = number value
string_to_number:
    push rbx
    push rcx
    push rdx
    
    mov rbx, rdi
    mov rcx, 0  ; Result
    mov rdx, 10 ; Base
    
.convert_loop:
    mov al, [rbx]
    cmp al, 0
    je .convert_done
    
    cmp al, '0'
    jl .convert_done
    cmp al, '9'
    jg .convert_done
    
    sub al, '0'
    movzx rax, al
    imul rcx, rdx
    add rcx, rax
    
    inc rbx
    jmp .convert_loop

.convert_done:
    mov rax, rcx
    pop rdx
    pop rcx
    pop rbx
    ret
