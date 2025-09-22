; reverser_syscalls.asm
; Platform-specific syscall mappings for cross-platform support

section .data
    ; Linux syscalls (x86-64)
    linux_syscall_table:
        dq 0    ; read
        dq 1    ; write
        dq 2    ; open
        dq 3    ; close
        dq 9    ; mmap
        dq 11   ; munmap
        dq 39   ; getpid
        dq 60   ; exit
        dq 102  ; getuid
    
    ; Windows syscalls (approximate mappings)
    windows_syscall_table:
        dq 0x0003  ; NtReadFile
        dq 0x0008  ; NtWriteFile
        dq 0x0033  ; NtOpenFile
        dq 0x000F  ; NtClose
        dq 0x0027  ; NtMapViewOfSection
        dq 0x002A  ; NtUnmapViewOfSection
        dq 0x0039  ; NtCurrentTeb
        dq 0x002C  ; NtTerminateProcess
        dq 0x003C  ; NtOpenProcessToken
    
    ; macOS syscalls
    macos_syscall_table:
        dq 0x2000003  ; read
        dq 0x2000004  ; write
        dq 0x2000005  ; open
        dq 0x2000006  ; close
        dq 0x20000C5  ; mmap
        dq 0x2000049  ; munmap
        dq 0x2000014  ; getpid
        dq 0x2000001  ; exit
        dq 0x2000018  ; getuid

section .text
    global get_syscall_number
    global cross_platform_syscall

; Get syscall number for current platform
; Input: rdi = syscall index
get_syscall_number:
    push rbx
    push rcx
    
    call platform_get_syscall_table
    mov rbx, rax
    mov rax, [rbx + rdi * 8]
    
    pop rcx
    pop rbx
    ret

; Cross-platform syscall wrapper
; Input: rdi = syscall index, rsi = arg1, rdx = arg2, rcx = arg3
cross_platform_syscall:
    push rbx
    push r8
    push r9
    
    ; Get syscall number
    push rsi
    push rdx
    push rcx
    call get_syscall_number
    pop rcx
    pop rdx
    pop rsi
    
    ; Make syscall
    mov rbx, rax
    mov rax, rbx
    syscall
    
    pop r9
    pop r8
    pop rbx
    ret
