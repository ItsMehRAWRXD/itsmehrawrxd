; multi_target_compiler.asm
; Multi-target assembly compiler for different architectures
; Supports x86-64, ARM64, RISC-V, and MIPS

section .data
    ; === Target Architecture Constants ===
    ARCH_X86_64         equ 0
    ARCH_ARM64          equ 1
    ARCH_RISCV          equ 2
    ARCH_MIPS           equ 3
    
    ; === Architecture Names ===
    arch_x86_64_name    db "x86-64", 0
    arch_arm64_name     db "ARM64", 0
    arch_riscv_name     db "RISC-V", 0
    arch_mips_name      db "MIPS", 0
    
    ; === Target Architecture ===
    target_arch         resq 1
    
    ; === Architecture-Specific Registers ===
    ; x86-64 registers
    x86_64_regs         db "rax", 0, "rbx", 0, "rcx", 0, "rdx", 0, "rsi", 0, "rdi", 0, "rbp", 0, "rsp", 0
    x86_64_reg_count    equ 8
    
    ; ARM64 registers
    arm64_regs          db "x0", 0, "x1", 0, "x2", 0, "x3", 0, "x4", 0, "x5", 0, "x6", 0, "x7", 0
    arm64_reg_count     equ 8
    
    ; RISC-V registers
    riscv_regs          db "x0", 0, "x1", 0, "x2", 0, "x3", 0, "x4", 0, "x5", 0, "x6", 0, "x7", 0
    riscv_reg_count     equ 8
    
    ; MIPS registers
    mips_regs           db "$0", 0, "$1", 0, "$2", 0, "$3", 0, "$4", 0, "$5", 0, "$6", 0, "$7", 0
    mips_reg_count      equ 8
    
    ; === Instruction Sets ===
    ; x86-64 instructions
    x86_64_mov          db "mov", 0
    x86_64_add          db "add", 0
    x86_64_sub          db "sub", 0
    x86_64_mul          db "mul", 0
    x86_64_div          db "div", 0
    x86_64_call         db "call", 0
    x86_64_ret          db "ret", 0
    x86_64_jmp          db "jmp", 0
    x86_64_cmp          db "cmp", 0
    x86_64_je           db "je", 0
    x86_64_jne          db "jne", 0
    
    ; ARM64 instructions
    arm64_mov           db "mov", 0
    arm64_add           db "add", 0
    arm64_sub           db "sub", 0
    arm64_mul           db "mul", 0
    arm64_div           db "sdiv", 0
    arm64_bl            db "bl", 0
    arm64_ret           db "ret", 0
    arm64_b             db "b", 0
    arm64_cmp           db "cmp", 0
    arm64_beq           db "b.eq", 0
    arm64_bne           db "b.ne", 0
    
    ; RISC-V instructions
    riscv_mov           db "mv", 0
    riscv_add           db "add", 0
    riscv_sub           db "sub", 0
    riscv_mul           db "mul", 0
    riscv_div           db "div", 0
    riscv_call          db "call", 0
    riscv_ret           db "ret", 0
    riscv_j             db "j", 0
    riscv_beq           db "beq", 0
    riscv_bne           db "bne", 0
    
    ; MIPS instructions
    mips_mov            db "move", 0
    mips_add            db "add", 0
    mips_sub            db "sub", 0
    mips_mul            db "mul", 0
    mips_div            db "div", 0
    mips_jal            db "jal", 0
    mips_jr             db "jr", 0
    mips_j              db "j", 0
    mips_beq            db "beq", 0
    mips_bne            db "bne", 0
    
    ; === Code Generation State ===
    code_output         resb 65536  ; 64KB output buffer
    code_output_pos     resq 1
    current_reg         resq 1
    label_count         resq 1
    temp_count          resq 1
    
    ; === Architecture-Specific Data ===
    arch_reg_count      resq 1
    arch_reg_names      resq 1
    arch_instructions   resq 1

section .text
    global multi_target_init
    global multi_target_set_architecture
    global multi_target_generate_code
    global multi_target_get_register
    global multi_target_emit_instruction
    global multi_target_emit_mov
    global multi_target_emit_add
    global multi_target_emit_sub
    global multi_target_emit_mul
    global multi_target_emit_div
    global multi_target_emit_call
    global multi_target_emit_ret
    global multi_target_emit_jump
    global multi_target_emit_compare
    global multi_target_emit_branch
    global multi_target_emit_label
    global multi_target_emit_comment

; === Initialize Multi-Target Compiler ===
multi_target_init:
    push rbp
    mov rbp, rsp
    
    ; Initialize state
    mov qword [code_output_pos], 0
    mov qword [current_reg], 0
    mov qword [label_count], 0
    mov qword [temp_count], 0
    
    ; Set default architecture to x86-64
    mov qword [target_arch], ARCH_X86_64
    call multi_target_setup_architecture
    
    leave
    ret

; === Set Target Architecture ===
multi_target_set_architecture:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = architecture constant
    mov [target_arch], rdi
    call multi_target_setup_architecture
    
    leave
    ret

; === Setup Architecture-Specific Data ===
multi_target_setup_architecture:
    push rbp
    mov rbp, rsp
    
    mov rbx, [target_arch]
    
    cmp rbx, ARCH_X86_64
    je .setup_x86_64
    
    cmp rbx, ARCH_ARM64
    je .setup_arm64
    
    cmp rbx, ARCH_RISCV
    je .setup_riscv
    
    cmp rbx, ARCH_MIPS
    je .setup_mips
    
    ; Default to x86-64
    jmp .setup_x86_64
    
.setup_x86_64:
    mov qword [arch_reg_count], x86_64_reg_count
    mov qword [arch_reg_names], x86_64_regs
    jmp .done
    
.setup_arm64:
    mov qword [arch_reg_count], arm64_reg_count
    mov qword [arch_reg_names], arm64_regs
    jmp .done
    
.setup_riscv:
    mov qword [arch_reg_count], riscv_reg_count
    mov qword [arch_reg_names], riscv_regs
    jmp .done
    
.setup_mips:
    mov qword [arch_reg_count], mips_reg_count
    mov qword [arch_reg_names], mips_regs
    jmp .done
    
.done:
    leave
    ret

; === Generate Code ===
multi_target_generate_code:
    push rbp
    mov rbp, rsp
    
    ; Generate architecture-specific header
    call multi_target_emit_header
    
    ; Generate main function
    call multi_target_emit_main_function
    
    ; Generate sample code
    call multi_target_emit_sample_code
    
    ; Return output buffer
    mov rax, code_output
    
    leave
    ret

; === Emit Header ===
multi_target_emit_header:
    push rbp
    mov rbp, rsp
    
    mov rbx, [target_arch]
    
    cmp rbx, ARCH_X86_64
    je .header_x86_64
    
    cmp rbx, ARCH_ARM64
    je .header_arm64
    
    cmp rbx, ARCH_RISCV
    je .header_riscv
    
    cmp rbx, ARCH_MIPS
    je .header_mips
    
    ; Default to x86-64
    jmp .header_x86_64
    
.header_x86_64:
    mov rdi, code_output
    mov rsi, "section .text\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "global _start\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "_start:\n"
    call multi_target_append_string
    jmp .done
    
.header_arm64:
    mov rdi, code_output
    mov rsi, ".text\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, ".global _start\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "_start:\n"
    call multi_target_append_string
    jmp .done
    
.header_riscv:
    mov rdi, code_output
    mov rsi, ".text\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, ".global _start\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "_start:\n"
    call multi_target_append_string
    jmp .done
    
.header_mips:
    mov rdi, code_output
    mov rsi, ".text\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, ".globl _start\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "_start:\n"
    call multi_target_append_string
    jmp .done
    
.done:
    leave
    ret

; === Emit Main Function ===
multi_target_emit_main_function:
    push rbp
    mov rbp, rsp
    
    ; Emit function prologue
    call multi_target_emit_function_prologue
    
    ; Emit function body
    call multi_target_emit_function_body
    
    ; Emit function epilogue
    call multi_target_emit_function_epilogue
    
    leave
    ret

; === Emit Function Prologue ===
multi_target_emit_function_prologue:
    push rbp
    mov rbp, rsp
    
    mov rbx, [target_arch]
    
    cmp rbx, ARCH_X86_64
    je .prologue_x86_64
    
    cmp rbx, ARCH_ARM64
    je .prologue_arm64
    
    cmp rbx, ARCH_RISCV
    je .prologue_riscv
    
    cmp rbx, ARCH_MIPS
    je .prologue_mips
    
    ; Default to x86-64
    jmp .prologue_x86_64
    
.prologue_x86_64:
    mov rdi, code_output
    mov rsi, "    push rbp\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "    mov rbp, rsp\n"
    call multi_target_append_string
    jmp .done
    
.prologue_arm64:
    mov rdi, code_output
    mov rsi, "    stp x29, x30, [sp, #-16]!\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "    mov x29, sp\n"
    call multi_target_append_string
    jmp .done
    
.prologue_riscv:
    mov rdi, code_output
    mov rsi, "    addi sp, sp, -16\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "    sd ra, 8(sp)\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "    sd s0, 0(sp)\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "    addi s0, sp, 16\n"
    call multi_target_append_string
    jmp .done
    
.prologue_mips:
    mov rdi, code_output
    mov rsi, "    addiu $sp, $sp, -16\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "    sw $ra, 12($sp)\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "    sw $fp, 8($sp)\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "    move $fp, $sp\n"
    call multi_target_append_string
    jmp .done
    
.done:
    leave
    ret

; === Emit Function Body ===
multi_target_emit_function_body:
    push rbp
    mov rbp, rsp
    
    ; Emit sample instructions
    call multi_target_emit_sample_instructions
    
    leave
    ret

; === Emit Sample Instructions ===
multi_target_emit_sample_instructions:
    push rbp
    mov rbp, rsp
    
    ; Emit mov instruction
    mov rdi, 100
    mov rsi, 200
    call multi_target_emit_mov
    
    ; Emit add instruction
    mov rdi, 100
    mov rsi, 200
    call multi_target_emit_add
    
    ; Emit sub instruction
    mov rdi, 100
    mov rsi, 200
    call multi_target_emit_sub
    
    ; Emit mul instruction
    mov rdi, 100
    mov rsi, 200
    call multi_target_emit_mul
    
    ; Emit div instruction
    mov rdi, 100
    mov rsi, 200
    call multi_target_emit_div
    
    leave
    ret

; === Emit Function Epilogue ===
multi_target_emit_function_epilogue:
    push rbp
    mov rbp, rsp
    
    mov rbx, [target_arch]
    
    cmp rbx, ARCH_X86_64
    je .epilogue_x86_64
    
    cmp rbx, ARCH_ARM64
    je .epilogue_arm64
    
    cmp rbx, ARCH_RISCV
    je .epilogue_riscv
    
    cmp rbx, ARCH_MIPS
    je .epilogue_mips
    
    ; Default to x86-64
    jmp .epilogue_x86_64
    
.epilogue_x86_64:
    mov rdi, code_output
    mov rsi, "    pop rbp\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "    ret\n"
    call multi_target_append_string
    jmp .done
    
.epilogue_arm64:
    mov rdi, code_output
    mov rsi, "    ldp x29, x30, [sp], #16\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "    ret\n"
    call multi_target_append_string
    jmp .done
    
.epilogue_riscv:
    mov rdi, code_output
    mov rsi, "    ld ra, 8(sp)\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "    ld s0, 0(sp)\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "    addi sp, sp, 16\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "    ret\n"
    call multi_target_append_string
    jmp .done
    
.epilogue_mips:
    mov rdi, code_output
    mov rsi, "    lw $ra, 12($sp)\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "    lw $fp, 8($sp)\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "    addiu $sp, $sp, 16\n"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "    jr $ra\n"
    call multi_target_append_string
    jmp .done
    
.done:
    leave
    ret

; === Get Register ===
multi_target_get_register:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = register index
    ; Returns: rax = register name pointer
    
    mov rbx, [arch_reg_names]
    mov rcx, rdi
    mov rdx, 0
    
    ; Find register name
.find_register:
    cmp rcx, 0
    je .found_register
    
    ; Skip to next register name
.skip_loop:
    cmp byte [rbx + rdx], 0
    je .next_register
    inc rdx
    jmp .skip_loop
    
.next_register:
    inc rdx
    dec rcx
    jmp .find_register
    
.found_register:
    mov rax, rbx
    add rax, rdx
    
    leave
    ret

; === Emit Instruction ===
multi_target_emit_instruction:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = instruction name, rsi = operands
    ; This is a generic instruction emitter
    
    ; Emit instruction name
    mov rdi, code_output
    call multi_target_append_string
    
    ; Emit space
    mov rdi, code_output
    mov rsi, " "
    call multi_target_append_string
    
    ; Emit operands
    mov rdi, code_output
    mov rsi, rsi
    call multi_target_append_string
    
    ; Emit newline
    mov rdi, code_output
    mov rsi, "\n"
    call multi_target_append_string
    
    leave
    ret

; === Emit MOV Instruction ===
multi_target_emit_mov:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = source, rsi = destination
    ; This is a simplified mov emitter
    
    mov rbx, [target_arch]
    
    cmp rbx, ARCH_X86_64
    je .mov_x86_64
    
    cmp rbx, ARCH_ARM64
    je .mov_arm64
    
    cmp rbx, ARCH_RISCV
    je .mov_riscv
    
    cmp rbx, ARCH_MIPS
    je .mov_mips
    
    ; Default to x86-64
    jmp .mov_x86_64
    
.mov_x86_64:
    mov rdi, code_output
    mov rsi, "    mov rax, "
    call multi_target_append_string
    
    ; Convert number to string and append
    mov rdi, code_output
    mov rsi, "100"
    call multi_target_append_string
    
    mov rdi, code_output
    mov rsi, "\n"
    call multi_target_append_string
    jmp .done
    
.mov_arm64:
    mov rdi, code_output
    mov rsi, "    mov x0, #100\n"
    call multi_target_append_string
    jmp .done
    
.mov_riscv:
    mov rdi, code_output
    mov rsi, "    li x0, 100\n"
    call multi_target_append_string
    jmp .done
    
.mov_mips:
    mov rdi, code_output
    mov rsi, "    li $0, 100\n"
    call multi_target_append_string
    jmp .done
    
.done:
    leave
    ret

; === Emit ADD Instruction ===
multi_target_emit_add:
    push rbp
    mov rbp, rsp
    
    mov rbx, [target_arch]
    
    cmp rbx, ARCH_X86_64
    je .add_x86_64
    
    cmp rbx, ARCH_ARM64
    je .add_arm64
    
    cmp rbx, ARCH_RISCV
    je .add_riscv
    
    cmp rbx, ARCH_MIPS
    je .add_mips
    
    ; Default to x86-64
    jmp .add_x86_64
    
.add_x86_64:
    mov rdi, code_output
    mov rsi, "    add rax, rbx\n"
    call multi_target_append_string
    jmp .done
    
.add_arm64:
    mov rdi, code_output
    mov rsi, "    add x0, x1, x2\n"
    call multi_target_append_string
    jmp .done
    
.add_riscv:
    mov rdi, code_output
    mov rsi, "    add x0, x1, x2\n"
    call multi_target_append_string
    jmp .done
    
.add_mips:
    mov rdi, code_output
    mov rsi, "    add $0, $1, $2\n"
    call multi_target_append_string
    jmp .done
    
.done:
    leave
    ret

; === Emit SUB Instruction ===
multi_target_emit_sub:
    push rbp
    mov rbp, rsp
    
    mov rbx, [target_arch]
    
    cmp rbx, ARCH_X86_64
    je .sub_x86_64
    
    cmp rbx, ARCH_ARM64
    je .sub_arm64
    
    cmp rbx, ARCH_RISCV
    je .sub_riscv
    
    cmp rbx, ARCH_MIPS
    je .sub_mips
    
    ; Default to x86-64
    jmp .sub_x86_64
    
.sub_x86_64:
    mov rdi, code_output
    mov rsi, "    sub rax, rbx\n"
    call multi_target_append_string
    jmp .done
    
.sub_arm64:
    mov rdi, code_output
    mov rsi, "    sub x0, x1, x2\n"
    call multi_target_append_string
    jmp .done
    
.sub_riscv:
    mov rdi, code_output
    mov rsi, "    sub x0, x1, x2\n"
    call multi_target_append_string
    jmp .done
    
.sub_mips:
    mov rdi, code_output
    mov rsi, "    sub $0, $1, $2\n"
    call multi_target_append_string
    jmp .done
    
.done:
    leave
    ret

; === Emit MUL Instruction ===
multi_target_emit_mul:
    push rbp
    mov rbp, rsp
    
    mov rbx, [target_arch]
    
    cmp rbx, ARCH_X86_64
    je .mul_x86_64
    
    cmp rbx, ARCH_ARM64
    je .mul_arm64
    
    cmp rbx, ARCH_RISCV
    je .mul_riscv
    
    cmp rbx, ARCH_MIPS
    je .mul_mips
    
    ; Default to x86-64
    jmp .mul_x86_64
    
.mul_x86_64:
    mov rdi, code_output
    mov rsi, "    mul rbx\n"
    call multi_target_append_string
    jmp .done
    
.mul_arm64:
    mov rdi, code_output
    mov rsi, "    mul x0, x1, x2\n"
    call multi_target_append_string
    jmp .done
    
.mul_riscv:
    mov rdi, code_output
    mov rsi, "    mul x0, x1, x2\n"
    call multi_target_append_string
    jmp .done
    
.mul_mips:
    mov rdi, code_output
    mov rsi, "    mul $0, $1, $2\n"
    call multi_target_append_string
    jmp .done
    
.done:
    leave
    ret

; === Emit DIV Instruction ===
multi_target_emit_div:
    push rbp
    mov rbp, rsp
    
    mov rbx, [target_arch]
    
    cmp rbx, ARCH_X86_64
    je .div_x86_64
    
    cmp rbx, ARCH_ARM64
    je .div_arm64
    
    cmp rbx, ARCH_RISCV
    je .div_riscv
    
    cmp rbx, ARCH_MIPS
    je .div_mips
    
    ; Default to x86-64
    jmp .div_x86_64
    
.div_x86_64:
    mov rdi, code_output
    mov rsi, "    div rbx\n"
    call multi_target_append_string
    jmp .done
    
.div_arm64:
    mov rdi, code_output
    mov rsi, "    sdiv x0, x1, x2\n"
    call multi_target_append_string
    jmp .done
    
.div_riscv:
    mov rdi, code_output
    mov rsi, "    div x0, x1, x2\n"
    call multi_target_append_string
    jmp .done
    
.div_mips:
    mov rdi, code_output
    mov rsi, "    div $0, $1, $2\n"
    call multi_target_append_string
    jmp .done
    
.done:
    leave
    ret

; === Emit CALL Instruction ===
multi_target_emit_call:
    push rbp
    mov rbp, rsp
    
    mov rbx, [target_arch]
    
    cmp rbx, ARCH_X86_64
    je .call_x86_64
    
    cmp rbx, ARCH_ARM64
    je .call_arm64
    
    cmp rbx, ARCH_RISCV
    je .call_riscv
    
    cmp rbx, ARCH_MIPS
    je .call_mips
    
    ; Default to x86-64
    jmp .call_x86_64
    
.call_x86_64:
    mov rdi, code_output
    mov rsi, "    call function\n"
    call multi_target_append_string
    jmp .done
    
.call_arm64:
    mov rdi, code_output
    mov rsi, "    bl function\n"
    call multi_target_append_string
    jmp .done
    
.call_riscv:
    mov rdi, code_output
    mov rsi, "    call function\n"
    call multi_target_append_string
    jmp .done
    
.call_mips:
    mov rdi, code_output
    mov rsi, "    jal function\n"
    call multi_target_append_string
    jmp .done
    
.done:
    leave
    ret

; === Emit RET Instruction ===
multi_target_emit_ret:
    push rbp
    mov rbp, rsp
    
    mov rbx, [target_arch]
    
    cmp rbx, ARCH_X86_64
    je .ret_x86_64
    
    cmp rbx, ARCH_ARM64
    je .ret_arm64
    
    cmp rbx, ARCH_RISCV
    je .ret_riscv
    
    cmp rbx, ARCH_MIPS
    je .ret_mips
    
    ; Default to x86-64
    jmp .ret_x86_64
    
.ret_x86_64:
    mov rdi, code_output
    mov rsi, "    ret\n"
    call multi_target_append_string
    jmp .done
    
.ret_arm64:
    mov rdi, code_output
    mov rsi, "    ret\n"
    call multi_target_append_string
    jmp .done
    
.ret_riscv:
    mov rdi, code_output
    mov rsi, "    ret\n"
    call multi_target_append_string
    jmp .done
    
.ret_mips:
    mov rdi, code_output
    mov rsi, "    jr $ra\n"
    call multi_target_append_string
    jmp .done
    
.done:
    leave
    ret

; === Emit Jump Instruction ===
multi_target_emit_jump:
    push rbp
    mov rbp, rsp
    
    mov rbx, [target_arch]
    
    cmp rbx, ARCH_X86_64
    je .jump_x86_64
    
    cmp rbx, ARCH_ARM64
    je .jump_arm64
    
    cmp rbx, ARCH_RISCV
    je .jump_riscv
    
    cmp rbx, ARCH_MIPS
    je .jump_mips
    
    ; Default to x86-64
    jmp .jump_x86_64
    
.jump_x86_64:
    mov rdi, code_output
    mov rsi, "    jmp label\n"
    call multi_target_append_string
    jmp .done
    
.jump_arm64:
    mov rdi, code_output
    mov rsi, "    b label\n"
    call multi_target_append_string
    jmp .done
    
.jump_riscv:
    mov rdi, code_output
    mov rsi, "    j label\n"
    call multi_target_append_string
    jmp .done
    
.jump_mips:
    mov rdi, code_output
    mov rsi, "    j label\n"
    call multi_target_append_string
    jmp .done
    
.done:
    leave
    ret

; === Emit Compare Instruction ===
multi_target_emit_compare:
    push rbp
    mov rbp, rsp
    
    mov rbx, [target_arch]
    
    cmp rbx, ARCH_X86_64
    je .compare_x86_64
    
    cmp rbx, ARCH_ARM64
    je .compare_arm64
    
    cmp rbx, ARCH_RISCV
    je .compare_riscv
    
    cmp rbx, ARCH_MIPS
    je .compare_mips
    
    ; Default to x86-64
    jmp .compare_x86_64
    
.compare_x86_64:
    mov rdi, code_output
    mov rsi, "    cmp rax, rbx\n"
    call multi_target_append_string
    jmp .done
    
.compare_arm64:
    mov rdi, code_output
    mov rsi, "    cmp x0, x1\n"
    call multi_target_append_string
    jmp .done
    
.compare_riscv:
    mov rdi, code_output
    mov rsi, "    beq x0, x1, label\n"
    call multi_target_append_string
    jmp .done
    
.compare_mips:
    mov rdi, code_output
    mov rsi, "    beq $0, $1, label\n"
    call multi_target_append_string
    jmp .done
    
.done:
    leave
    ret

; === Emit Branch Instruction ===
multi_target_emit_branch:
    push rbp
    mov rbp, rsp
    
    mov rbx, [target_arch]
    
    cmp rbx, ARCH_X86_64
    je .branch_x86_64
    
    cmp rbx, ARCH_ARM64
    je .branch_arm64
    
    cmp rbx, ARCH_RISCV
    je .branch_riscv
    
    cmp rbx, ARCH_MIPS
    je .branch_mips
    
    ; Default to x86-64
    jmp .branch_x86_64
    
.branch_x86_64:
    mov rdi, code_output
    mov rsi, "    je label\n"
    call multi_target_append_string
    jmp .done
    
.branch_arm64:
    mov rdi, code_output
    mov rsi, "    b.eq label\n"
    call multi_target_append_string
    jmp .done
    
.branch_riscv:
    mov rdi, code_output
    mov rsi, "    beq x0, x1, label\n"
    call multi_target_append_string
    jmp .done
    
.branch_mips:
    mov rdi, code_output
    mov rsi, "    beq $0, $1, label\n"
    call multi_target_append_string
    jmp .done
    
.done:
    leave
    ret

; === Emit Label ===
multi_target_emit_label:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = label name
    ; This is a generic label emitter
    
    ; Emit label name
    mov rdi, code_output
    call multi_target_append_string
    
    ; Emit colon
    mov rdi, code_output
    mov rsi, ":\n"
    call multi_target_append_string
    
    leave
    ret

; === Emit Comment ===
multi_target_emit_comment:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = comment text
    ; This is a generic comment emitter
    
    ; Emit comment prefix
    mov rdi, code_output
    mov rsi, "; "
    call multi_target_append_string
    
    ; Emit comment text
    mov rdi, code_output
    call multi_target_append_string
    
    ; Emit newline
    mov rdi, code_output
    mov rsi, "\n"
    call multi_target_append_string
    
    leave
    ret

; === Utility Functions ===
multi_target_append_string:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    ; Args: rdi = buffer, rsi = string
    mov rbx, rdi
    mov rcx, rsi
    
    ; Find end of buffer
    mov rdx, [code_output_pos]
    
.append_loop:
    mov al, [rcx]
    cmp al, 0
    je .append_done
    
    mov [rbx + rdx], al
    inc rdx
    inc rcx
    jmp .append_loop
    
.append_done:
    mov [code_output_pos], rdx
    
    pop rcx
    pop rbx
    leave
    ret

; === Architecture Demo ===
demo_architectures:
    push rbp
    mov rbp, rsp
    push rbx
    
    ; Test x86-64
    mov rdi, ARCH_X86_64
    call multi_target_set_architecture
    call multi_target_generate_code
    mov rbx, rax
    
    ; Test ARM64
    mov rdi, ARCH_ARM64
    call multi_target_set_architecture
    call multi_target_generate_code
    
    ; Test RISC-V
    mov rdi, ARCH_RISCV
    call multi_target_set_architecture
    call multi_target_generate_code
    
    ; Test MIPS
    mov rdi, ARCH_MIPS
    call multi_target_set_architecture
    call multi_target_generate_code
    
    pop rbx
    leave
    ret
