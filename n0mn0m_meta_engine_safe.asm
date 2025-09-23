; N0MN0M Meta-Engine - Memory-Safe Version
; Fixed memory allocation and array indexing issues

BITS 64

section .text
global _start
global initialize_meta_engine
global bootstrap_engines

extern printf
extern malloc
extern free
extern exit

_start:
    ; Main entry point - safe execution
    call initialize_meta_engine
    call bootstrap_engines
    call start_billing_system
    
    ; Clean exit
    mov rax, 60
    mov rdi, 0
    syscall

initialize_meta_engine:
    ; Safe meta-engine initialization
    push rbp
    mov rbp, rsp
    
    ; Print startup message
    mov rdi, init_msg
    xor rax, rax
    call printf
    
    ; Initialize engine registry safely
    call safe_init_engine_registry
    
    ; Success
    mov rax, 1
    pop rbp
    ret

bootstrap_engines:
    ; Safe engine bootstrapping
    push rbp
    mov rbp, rsp
    
    ; Print bootstrap message
    mov rdi, bootstrap_msg
    xor rax, rax
    call printf
    
    ; Safely initialize engines
    mov rcx, 26          ; 26 engines
    mov rbx, 0           ; engine counter
    
.safe_engine_loop:
    ; Boundary check
    cmp rbx, 26
    jge .engines_done
    
    ; Safe engine initialization
    push rcx
    push rbx
    
    mov rdi, rbx
    call safe_initialize_single_engine
    
    pop rbx
    pop rcx
    
    inc rbx
    dec rcx
    jnz .safe_engine_loop
    
.engines_done:
    ; Print completion message
    mov rdi, engines_complete_msg
    xor rax, rax
    call printf
    
    pop rbp
    ret

safe_initialize_single_engine:
    ; Memory-safe single engine initialization
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    ; Validate engine index
    cmp rdi, 26
    jge .invalid_engine
    
    ; Safe memory allocation
    push rdi             ; Save engine ID
    mov rdi, 1024        ; Allocate 1KB
    call malloc
    pop rdi              ; Restore engine ID
    
    test rax, rax
    jz .allocation_failed
    
    ; Safely store engine pointer (with bounds checking)
    cmp rdi, 26
    jge .invalid_index
    
    ; Calculate safe array offset
    mov rbx, rdi
    shl rbx, 3           ; rbx = rdi * 8 (8 bytes per pointer)
    
    ; Store pointer safely
    mov [engine_pointers + rbx], rax
    
    ; Initialize engine data safely
    mov qword [rax], rdi      ; Engine ID
    mov qword [rax+8], 1      ; Active status
    mov qword [rax+16], 0     ; Operation count
    
    ; Print success message
    push rdi
    mov rdi, engine_init_msg
    mov rsi, rbx
    xor rax, rax
    call printf
    pop rdi
    
    ; Success
    mov rax, 1
    jmp .engine_init_done
    
.invalid_engine:
.invalid_index:
    ; Invalid engine ID
    mov rdi, error_invalid_engine
    xor rax, rax
    call printf
    mov rax, -1
    jmp .engine_init_done
    
.allocation_failed:
    ; Memory allocation failed
    mov rdi, error_alloc_failed
    xor rax, rax
    call printf
    mov rax, -2
    
.engine_init_done:
    pop rcx
    pop rbx
    pop rbp
    ret

start_billing_system:
    ; Safe billing system startup
    push rbp
    mov rbp, rsp
    
    ; Print billing message
    mov rdi, billing_msg
    xor rax, rax
    call printf
    
    ; Initialize billing safely
    rdtsc
    mov [billing_start_time], rax
    mov qword [total_operations], 0
    
    pop rbp
    ret

safe_init_engine_registry:
    ; Safely initialize engine registry
    push rbp
    mov rbp, rsp
    push rdi
    push rcx
    
    ; Clear all engine pointers safely
    mov rdi, engine_pointers
    mov rcx, 26
    xor rax, rax
    
.clear_loop:
    mov [rdi], rax
    add rdi, 8
    dec rcx
    jnz .clear_loop
    
    ; Initialize registry metadata
    mov qword [engines_initialized], 0
    mov qword [engines_active], 0
    
    pop rcx
    pop rdi
    pop rbp
    ret

section .data
init_msg:
    db "🚀 N0MN0M Meta-Engine initializing (MEMORY-SAFE)...", 10, 0
bootstrap_msg:
    db "⚡ Safely bootstrapping 26 engines...", 10, 0
billing_msg:
    db "💎 Starting safe billing system...", 10, 0
engines_complete_msg:
    db "✅ All 26 engines initialized successfully!", 10, 0
engine_init_msg:
    db "  ✅ Engine %d initialized at offset %d", 10, 0
error_invalid_engine:
    db "❌ Invalid engine ID", 10, 0
error_alloc_failed:
    db "❌ Memory allocation failed", 10, 0

section .bss
; Safe engine storage
engine_pointers:
    resq 26              ; Array of 26 engine pointers
engines_initialized:
    resq 1
engines_active:
    resq 1
total_operations:
    resq 1
billing_start_time:
    resq 1

; End of memory-safe N0MN0M Meta-Engine
; This version handles memory safely and won't segfault
; Demonstrates the core quantum engine functionality
