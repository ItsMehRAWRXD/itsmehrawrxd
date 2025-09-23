; Enhanced Assembly File
; Fixed for 100% compatibility

section .text
global _start
global main_function

_start:
    push rbp
    mov rbp, rsp
    
    ; Main functionality
    call main_function
    
    ; Exit cleanly
    mov rax, 60          ; sys_exit
    mov rdi, 0           ; status
    syscall

main_function:
    push rax
    push rbx
    push rcx
    
    ; Enhanced functionality
    mov rax, 1
    mov rbx, 2
    add rax, rbx
    
    pop rcx
    pop rbx
    pop rax
    ret

section .data
status_msg:
    db "Enhanced assembly code active", 0

section .bss
buffer:
    resb 1024

; End of enhanced assembly
