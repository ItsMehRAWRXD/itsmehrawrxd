; machine_code_genesis.asm
; Manual machine code genesis (Phase 0)
; Implements the most primitive compiler possible - direct machine code generation

section .data
    ; === Machine Code Genesis Constants ===
    GENESIS_VERSION      db "Machine Code Genesis v0.1", 0
    GENESIS_INFO         db "Phase 0: Direct machine code generation", 10, 0
    
    ; === Machine Code Templates ===
    ; x86-64 machine code templates
    MACHINE_CODE_NOP     equ 0x90                    ; NOP instruction
    MACHINE_CODE_RET     equ 0xC3                    ; RET instruction
    MACHINE_CODE_PUSH_RBP equ 0x55                   ; PUSH RBP
    MACHINE_CODE_POP_RBP  equ 0x5D                   ; POP RBP
    MACHINE_CODE_MOV_RAX_IMM equ 0xB8                ; MOV RAX, immediate (5 bytes)
    MACHINE_CODE_MOV_RDI_IMM equ 0xBF                ; MOV RDI, immediate (5 bytes)
    MACHINE_CODE_SYSCALL equ 0x050F                  ; SYSCALL (2 bytes)
    MACHINE_CODE_ADD_RAX_RBX equ 0x01D8              ; ADD RAX, RBX (2 bytes)
    MACHINE_CODE_SUB_RAX_RBX equ 0x29D8              ; SUB RAX, RBX (2 bytes)
    MACHINE_CODE_MUL_RBX equ 0xF7E3                  ; MUL RBX (2 bytes)
    MACHINE_CODE_DIV_RBX equ 0xF7F3                  ; DIV RBX (2 bytes)
    MACHINE_CODE_CMP_RAX_RBX equ 0x39D8              ; CMP RAX, RBX (2 bytes)
    MACHINE_CODE_JE_REL8 equ 0x74                    ; JE rel8 (2 bytes)
    MACHINE_CODE_JNE_REL8 equ 0x75                   ; JNE rel8 (2 bytes)
    MACHINE_CODE_JMP_REL8 equ 0xEB                   ; JMP rel8 (2 bytes)
    MACHINE_CODE_CALL_REL32 equ 0xE8                 ; CALL rel32 (5 bytes)
    
    ; === System Call Numbers ===
    SYS_EXIT            equ 60
    SYS_WRITE           equ 1
    SYS_READ            equ 0
    SYS_OPEN            equ 2
    SYS_CLOSE           equ 3
    SYS_MMAP            equ 9
    SYS_MUNMAP          equ 11
    
    ; === Machine Code Buffer ===
    machine_code_buffer resb 4096                    ; 4KB buffer for machine code
    machine_code_pos    resq 1                       ; Current position in buffer
    machine_code_size   resq 1                       ; Total size of generated code
    
    ; === Instruction Counter ===
    instruction_count   resq 1                       ; Number of instructions generated
    
    ; === Label Management ===
    label_table         resq 256                     ; Label address table
    label_count         resq 1                       ; Number of labels
    label_names         resb 256 * 32                ; Label names (256 labels, 32 chars each)
    
    ; === Relocation Table ===
    relocation_table    resq 256                     ; Relocation entries
    relocation_count    resq 1                       ; Number of relocations
    
    ; === Machine Code Generation State ===
    current_function    resq 1                       ; Current function being generated
    stack_depth         resq 1                       ; Current stack depth
    register_usage      resq 1                       ; Register usage bitmap

section .text
    global genesis_init
    global genesis_generate_nop
    global genesis_generate_ret
    global genesis_generate_mov_immediate
    global genesis_generate_add
    global genesis_generate_sub
    global genesis_generate_mul
    global genesis_generate_div
    global genesis_generate_cmp
    global genesis_generate_jump
    global genesis_generate_call
    global genesis_generate_syscall
    global genesis_generate_function_prologue
    global genesis_generate_function_epilogue
    global genesis_generate_program
    global genesis_emit_byte
    global genesis_emit_word
    global genesis_emit_dword
    global genesis_emit_qword
    global genesis_add_label
    global genesis_resolve_labels
    global genesis_add_relocation
    global genesis_resolve_relocations
    global genesis_get_machine_code
    global genesis_get_code_size
    global genesis_disassemble
    global genesis_validate_code

; === Initialize Machine Code Genesis ===
genesis_init:
    push rbp
    mov rbp, rsp
    
    ; Print genesis info
    mov rdi, GENESIS_VERSION
    call print_string
    mov rdi, GENESIS_INFO
    call print_string
    
    ; Initialize state
    mov qword [machine_code_pos], 0
    mov qword [machine_code_size], 0
    mov qword [instruction_count], 0
    mov qword [label_count], 0
    mov qword [relocation_count], 0
    mov qword [current_function], 0
    mov qword [stack_depth], 0
    mov qword [register_usage], 0
    
    ; Clear buffers
    mov rdi, machine_code_buffer
    mov rsi, 4096
    call zero_memory
    
    mov rdi, label_table
    mov rsi, 256 * 8
    call zero_memory
    
    mov rdi, relocation_table
    mov rsi, 256 * 8
    call zero_memory
    
    leave
    ret

; === Generate NOP Instruction ===
genesis_generate_nop:
    push rbp
    mov rbp, rsp
    
    mov rdi, MACHINE_CODE_NOP
    call genesis_emit_byte
    
    inc qword [instruction_count]
    
    leave
    ret

; === Generate RET Instruction ===
genesis_generate_ret:
    push rbp
    mov rbp, rsp
    
    mov rdi, MACHINE_CODE_RET
    call genesis_emit_byte
    
    inc qword [instruction_count]
    
    leave
    ret

; === Generate MOV Immediate Instruction ===
genesis_generate_mov_immediate:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = register (0=RAX, 1=RDI, etc.), rsi = immediate value
    
    cmp rdi, 0
    je .mov_rax
    cmp rdi, 1
    je .mov_rdi
    jmp .done
    
.mov_rax:
    mov rdi, MACHINE_CODE_MOV_RAX_IMM
    call genesis_emit_byte
    mov rdi, rsi
    call genesis_emit_dword
    jmp .done
    
.mov_rdi:
    mov rdi, MACHINE_CODE_MOV_RDI_IMM
    call genesis_emit_byte
    mov rdi, rsi
    call genesis_emit_dword
    jmp .done
    
.done:
    inc qword [instruction_count]
    
    leave
    ret

; === Generate ADD Instruction ===
genesis_generate_add:
    push rbp
    mov rbp, rsp
    
    mov rdi, MACHINE_CODE_ADD_RAX_RBX
    call genesis_emit_word
    
    inc qword [instruction_count]
    
    leave
    ret

; === Generate SUB Instruction ===
genesis_generate_sub:
    push rbp
    mov rbp, rsp
    
    mov rdi, MACHINE_CODE_SUB_RAX_RBX
    call genesis_emit_word
    
    inc qword [instruction_count]
    
    leave
    ret

; === Generate MUL Instruction ===
genesis_generate_mul:
    push rbp
    mov rbp, rsp
    
    mov rdi, MACHINE_CODE_MUL_RBX
    call genesis_emit_word
    
    inc qword [instruction_count]
    
    leave
    ret

; === Generate DIV Instruction ===
genesis_generate_div:
    push rbp
    mov rbp, rsp
    
    mov rdi, MACHINE_CODE_DIV_RBX
    call genesis_emit_word
    
    inc qword [instruction_count]
    
    leave
    ret

; === Generate CMP Instruction ===
genesis_generate_cmp:
    push rbp
    mov rbp, rsp
    
    mov rdi, MACHINE_CODE_CMP_RAX_RBX
    call genesis_emit_word
    
    inc qword [instruction_count]
    
    leave
    ret

; === Generate Jump Instruction ===
genesis_generate_jump:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = jump type (0=JE, 1=JNE, 2=JMP), rsi = target address
    
    cmp rdi, 0
    je .je_jump
    cmp rdi, 1
    je .jne_jump
    cmp rdi, 2
    je .jmp_jump
    jmp .done
    
.je_jump:
    mov rdi, MACHINE_CODE_JE_REL8
    call genesis_emit_byte
    ; Calculate relative offset (simplified)
    mov rdi, 0
    call genesis_emit_byte
    jmp .done
    
.jne_jump:
    mov rdi, MACHINE_CODE_JNE_REL8
    call genesis_emit_byte
    ; Calculate relative offset (simplified)
    mov rdi, 0
    call genesis_emit_byte
    jmp .done
    
.jmp_jump:
    mov rdi, MACHINE_CODE_JMP_REL8
    call genesis_emit_byte
    ; Calculate relative offset (simplified)
    mov rdi, 0
    call genesis_emit_byte
    jmp .done
    
.done:
    inc qword [instruction_count]
    
    leave
    ret

; === Generate CALL Instruction ===
genesis_generate_call:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = target address
    
    mov rsi, MACHINE_CODE_CALL_REL32
    call genesis_emit_byte
    ; Calculate relative offset (simplified)
    mov rdi, 0
    call genesis_emit_dword
    
    inc qword [instruction_count]
    
    leave
    ret

; === Generate SYSCALL Instruction ===
genesis_generate_syscall:
    push rbp
    mov rbp, rsp
    
    mov rdi, MACHINE_CODE_SYSCALL
    call genesis_emit_word
    
    inc qword [instruction_count]
    
    leave
    ret

; === Generate Function Prologue ===
genesis_generate_function_prologue:
    push rbp
    mov rbp, rsp
    
    ; Generate PUSH RBP
    mov rdi, MACHINE_CODE_PUSH_RBP
    call genesis_emit_byte
    
    ; Generate MOV RBP, RSP (simplified)
    mov rdi, 0x89
    call genesis_emit_byte
    mov rdi, 0xE5
    call genesis_emit_byte
    
    inc qword [stack_depth]
    inc qword [instruction_count]
    
    leave
    ret

; === Generate Function Epilogue ===
genesis_generate_function_epilogue:
    push rbp
    mov rbp, rsp
    
    ; Generate POP RBP
    mov rdi, MACHINE_CODE_POP_RBP
    call genesis_emit_byte
    
    ; Generate RET
    mov rdi, MACHINE_CODE_RET
    call genesis_emit_byte
    
    dec qword [stack_depth]
    add qword [instruction_count], 2
    
    leave
    ret

; === Generate Complete Program ===
genesis_generate_program:
    push rbp
    mov rbp, rsp
    
    ; Generate a simple program that exits with code 0
    
    ; Function prologue
    call genesis_generate_function_prologue
    
    ; MOV RAX, 60 (sys_exit)
    mov rdi, 0  ; RAX
    mov rsi, 60
    call genesis_generate_mov_immediate
    
    ; MOV RDI, 0 (exit code)
    mov rdi, 1  ; RDI
    mov rsi, 0
    call genesis_generate_mov_immediate
    
    ; SYSCALL
    call genesis_generate_syscall
    
    ; Function epilogue
    call genesis_generate_function_epilogue
    
    ; Update code size
    mov rax, [machine_code_pos]
    mov [machine_code_size], rax
    
    leave
    ret

; === Emit Byte ===
genesis_emit_byte:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = byte value
    mov rax, [machine_code_pos]
    mov rbx, machine_code_buffer
    mov [rbx + rax], dil
    inc qword [machine_code_pos]
    
    leave
    ret

; === Emit Word ===
genesis_emit_word:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = word value
    mov rax, [machine_code_pos]
    mov rbx, machine_code_buffer
    mov [rbx + rax], di
    add qword [machine_code_pos], 2
    
    leave
    ret

; === Emit DWORD ===
genesis_emit_dword:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = dword value
    mov rax, [machine_code_pos]
    mov rbx, machine_code_buffer
    mov [rbx + rax], edi
    add qword [machine_code_pos], 4
    
    leave
    ret

; === Emit QWORD ===
genesis_emit_qword:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = qword value
    mov rax, [machine_code_pos]
    mov rbx, machine_code_buffer
    mov [rbx + rax], rdi
    add qword [machine_code_pos], 8
    
    leave
    ret

; === Add Label ===
genesis_add_label:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = label name, rsi = address
    
    mov rax, [label_count]
    mov rbx, label_table
    mov [rbx + rax * 8], rsi
    
    ; Store label name (simplified)
    mov rcx, label_names
    mov rdx, rax
    imul rdx, 32
    add rcx, rdx
    ; Copy name (simplified - just store address)
    mov [rcx], rdi
    
    inc qword [label_count]
    
    leave
    ret

; === Resolve Labels ===
genesis_resolve_labels:
    push rbp
    mov rbp, rsp
    
    ; Resolve all label references
    ; This is a simplified implementation
    
    mov rax, [label_count]
    mov rbx, [relocation_count]
    
    ; For now, just mark as resolved
    mov qword [relocation_count], 0
    
    leave
    ret

; === Add Relocation ===
genesis_add_relocation:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = address, rsi = type, rdx = target
    
    mov rax, [relocation_count]
    mov rbx, relocation_table
    mov [rbx + rax * 8], rdi
    
    inc qword [relocation_count]
    
    leave
    ret

; === Resolve Relocations ===
genesis_resolve_relocations:
    push rbp
    mov rbp, rsp
    
    ; Resolve all relocation entries
    ; This is a simplified implementation
    
    mov qword [relocation_count], 0
    
    leave
    ret

; === Get Machine Code ===
genesis_get_machine_code:
    push rbp
    mov rbp, rsp
    
    mov rax, machine_code_buffer
    
    leave
    ret

; === Get Code Size ===
genesis_get_code_size:
    push rbp
    mov rbp, rsp
    
    mov rax, [machine_code_size]
    
    leave
    ret

; === Disassemble Code ===
genesis_disassemble:
    push rbp
    mov rbp, rsp
    
    ; Simple disassembler for generated code
    mov rbx, machine_code_buffer
    mov rcx, [machine_code_size]
    mov rdx, 0
    
.disassemble_loop:
    cmp rdx, rcx
    jge .disassemble_done
    
    mov al, [rbx + rdx]
    
    ; Simple instruction recognition
    cmp al, 0x90  ; NOP
    je .nop_instruction
    cmp al, 0xC3  ; RET
    je .ret_instruction
    cmp al, 0x55  ; PUSH RBP
    je .push_rbp_instruction
    cmp al, 0x5D  ; POP RBP
    je .pop_rbp_instruction
    cmp al, 0xB8  ; MOV RAX, immediate
    je .mov_rax_instruction
    cmp al, 0xBF  ; MOV RDI, immediate
    je .mov_rdi_instruction
    cmp al, 0x0F  ; SYSCALL
    je .syscall_instruction
    
    ; Unknown instruction
    jmp .next_byte
    
.nop_instruction:
    mov rdi, "NOP"
    call print_string
    jmp .next_byte
    
.ret_instruction:
    mov rdi, "RET"
    call print_string
    jmp .next_byte
    
.push_rbp_instruction:
    mov rdi, "PUSH RBP"
    call print_string
    jmp .next_byte
    
.pop_rbp_instruction:
    mov rdi, "POP RBP"
    call print_string
    jmp .next_byte
    
.mov_rax_instruction:
    mov rdi, "MOV RAX, "
    call print_string
    ; Print immediate value (simplified)
    add rdx, 4  ; Skip immediate bytes
    jmp .next_byte
    
.mov_rdi_instruction:
    mov rdi, "MOV RDI, "
    call print_string
    ; Print immediate value (simplified)
    add rdx, 4  ; Skip immediate bytes
    jmp .next_byte
    
.syscall_instruction:
    mov rdi, "SYSCALL"
    call print_string
    inc rdx  ; Skip second byte of SYSCALL
    jmp .next_byte
    
.next_byte:
    inc rdx
    jmp .disassemble_loop
    
.disassemble_done:
    leave
    ret

; === Validate Code ===
genesis_validate_code:
    push rbp
    mov rbp, rsp
    
    ; Basic code validation
    mov rax, [machine_code_size]
    cmp rax, 0
    je .validation_error
    
    mov rax, [instruction_count]
    cmp rax, 0
    je .validation_error
    
    ; Check for basic instruction patterns
    mov rbx, machine_code_buffer
    mov al, [rbx]
    
    ; Should start with function prologue or valid instruction
    cmp al, 0x55  ; PUSH RBP
    je .validation_ok
    cmp al, 0x90  ; NOP
    je .validation_ok
    cmp al, 0xC3  ; RET
    je .validation_ok
    
    ; Validation failed
    jmp .validation_error
    
.validation_ok:
    mov rax, 1
    jmp .done
    
.validation_error:
    mov rax, 0
    
.done:
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

; === Machine Code Genesis Demo ===
genesis_demo:
    push rbp
    mov rbp, rsp
    
    ; Initialize genesis
    call genesis_init
    
    ; Generate a simple program
    call genesis_generate_program
    
    ; Validate the generated code
    call genesis_validate_code
    cmp rax, 1
    jne .demo_error
    
    ; Disassemble the code
    call genesis_disassemble
    
    ; Get code size
    call genesis_get_code_size
    mov rdi, rax
    ; Print size (simplified)
    
    jmp .demo_done
    
.demo_error:
    mov rdi, "Error: Code validation failed"
    call print_string
    
.demo_done:
    leave
    ret
