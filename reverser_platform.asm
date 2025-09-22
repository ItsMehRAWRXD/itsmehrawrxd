; reverser_platform.asm
; Cross-platform support for Reverser compiler
; Supports Mac, Linux, Windows, iOS, and Android

section .data
    ; Platform constants
    PLATFORM_LINUX   equ 0
    PLATFORM_WINDOWS equ 1
    PLATFORM_MACOS   equ 2
    PLATFORM_IOS     equ 3
    PLATFORM_ANDROID equ 4
    
    ; Architecture constants
    ARCH_X86_64      equ 0
    ARCH_ARM64       equ 1
    ARCH_ARM32       equ 2
    
    ; Current platform detection
    current_platform resq 1
    current_arch     resq 1
    
    ; Platform-specific strings
    platform_linux   db "linux", 0
    platform_windows db "windows", 0
    platform_macos   db "macos", 0
    platform_ios     db "ios", 0
    platform_android db "android", 0

section .text
    global platform_init
    global platform_detect
    global platform_get_os
    global platform_get_arch
    global platform_is_unix
    global platform_is_windows
    global platform_is_mobile
    global platform_get_syscall_table
    global platform_get_abi_info

; Initialize platform detection
platform_init:
    push rbx
    push rcx
    push rdx
    
    ; Detect current platform
    call platform_detect
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Detect current platform and architecture
platform_detect:
    push rbx
    push rcx
    push rdx
    
    ; Detect OS
    mov rax, 0  ; sys_uname
    mov rdi, rsp
    sub rsp, 400
    syscall
    
    ; Check sysname field (first 65 bytes)
    mov rbx, rsp
    mov rcx, 0
    
    ; Compare with known OS strings
    mov rdi, rbx
    mov rsi, platform_linux
    call strcmp
    cmp rax, 0
    je .detected_linux
    
    mov rdi, rbx
    mov rsi, platform_windows
    call strcmp
    cmp rax, 0
    je .detected_windows
    
    mov rdi, rbx
    mov rsi, platform_macos
    call strcmp
    cmp rax, 0
    je .detected_macos
    
    mov rdi, rbx
    mov rsi, platform_ios
    call strcmp
    cmp rax, 0
    je .detected_ios
    
    mov rdi, rbx
    mov rsi, platform_android
    call strcmp
    cmp rax, 0
    je .detected_android
    
    ; Default to Linux
    mov qword [current_platform], PLATFORM_LINUX
    jmp .detect_arch

.detected_linux:
    mov qword [current_platform], PLATFORM_LINUX
    jmp .detect_arch

.detected_windows:
    mov qword [current_platform], PLATFORM_WINDOWS
    jmp .detect_arch

.detected_macos:
    mov qword [current_platform], PLATFORM_MACOS
    jmp .detect_arch

.detected_ios:
    mov qword [current_platform], PLATFORM_IOS
    jmp .detect_arch

.detected_android:
    mov qword [current_platform], PLATFORM_ANDROID
    jmp .detect_arch

.detect_arch:
    ; Detect architecture
    mov rax, 0x01  ; sys_getpid
    syscall
    
    ; Check if we're on x86-64
    mov rbx, 0x40000000
    and rbx, rax
    cmp rbx, 0
    jne .detected_x86_64
    
    ; Check if we're on ARM64
    mov rbx, 0x80000000
    and rbx, rax
    cmp rbx, 0
    jne .detected_arm64
    
    ; Default to x86-64
    mov qword [current_arch], ARCH_X86_64
    jmp .detect_done

.detected_x86_64:
    mov qword [current_arch], ARCH_X86_64
    jmp .detect_done

.detected_arm64:
    mov qword [current_arch], ARCH_ARM64
    jmp .detect_done

.detect_done:
    add rsp, 400
    pop rdx
    pop rcx
    pop rbx
    ret

; Get current OS
; Output: rax = platform constant
platform_get_os:
    mov rax, [current_platform]
    ret

; Get current architecture
; Output: rax = architecture constant
platform_get_arch:
    mov rax, [current_arch]
    ret

; Check if platform is Unix-like
; Output: rax = 1 if Unix-like, 0 if not
platform_is_unix:
    mov rax, [current_platform]
    cmp rax, PLATFORM_WINDOWS
    je .not_unix
    
    mov rax, 1
    jmp .return

.not_unix:
    mov rax, 0

.return:
    ret

; Check if platform is Windows
; Output: rax = 1 if Windows, 0 if not
platform_is_windows:
    mov rax, [current_platform]
    cmp rax, PLATFORM_WINDOWS
    je .is_windows
    
    mov rax, 0
    jmp .return

.is_windows:
    mov rax, 1

.return:
    ret

; Check if platform is mobile
; Output: rax = 1 if mobile, 0 if not
platform_is_mobile:
    mov rax, [current_platform]
    cmp rax, PLATFORM_IOS
    je .is_mobile
    cmp rax, PLATFORM_ANDROID
    je .is_mobile
    
    mov rax, 0
    jmp .return

.is_mobile:
    mov rax, 1

.return:
    ret

; Get platform-specific syscall table
; Output: rax = pointer to syscall table
platform_get_syscall_table:
    mov rax, [current_platform]
    cmp rax, PLATFORM_LINUX
    je .linux_syscalls
    cmp rax, PLATFORM_WINDOWS
    je .windows_syscalls
    cmp rax, PLATFORM_MACOS
    je .macos_syscalls
    cmp rax, PLATFORM_IOS
    je .ios_syscalls
    cmp rax, PLATFORM_ANDROID
    je .android_syscalls
    
    ; Default to Linux
    jmp .linux_syscalls

.linux_syscalls:
    mov rax, linux_syscall_table
    jmp .return

.windows_syscalls:
    mov rax, windows_syscall_table
    jmp .return

.macos_syscalls:
    mov rax, macos_syscall_table
    jmp .return

.ios_syscalls:
    mov rax, ios_syscall_table
    jmp .return

.android_syscalls:
    mov rax, android_syscall_table
    jmp .return

.return:
    ret

; Get platform-specific ABI information
; Output: rax = pointer to ABI info
platform_get_abi_info:
    mov rax, [current_platform]
    mov rbx, [current_arch]
    
    ; Combine platform and architecture
    shl rax, 8
    or rax, rbx
    
    ; Look up ABI info
    cmp rax, (PLATFORM_LINUX << 8) | ARCH_X86_64
    je .linux_x86_64_abi
    cmp rax, (PLATFORM_LINUX << 8) | ARCH_ARM64
    je .linux_arm64_abi
    cmp rax, (PLATFORM_WINDOWS << 8) | ARCH_X86_64
    je .windows_x86_64_abi
    cmp rax, (PLATFORM_MACOS << 8) | ARCH_X86_64
    je .macos_x86_64_abi
    cmp rax, (PLATFORM_MACOS << 8) | ARCH_ARM64
    je .macos_arm64_abi
    cmp rax, (PLATFORM_IOS << 8) | ARCH_ARM64
    je .ios_arm64_abi
    cmp rax, (PLATFORM_ANDROID << 8) | ARCH_ARM64
    je .android_arm64_abi
    
    ; Default to Linux x86-64
    jmp .linux_x86_64_abi

.linux_x86_64_abi:
    mov rax, linux_x86_64_abi_info
    jmp .return

.linux_arm64_abi:
    mov rax, linux_arm64_abi_info
    jmp .return

.windows_x86_64_abi:
    mov rax, windows_x86_64_abi_info
    jmp .return

.macos_x86_64_abi:
    mov rax, macos_x86_64_abi_info
    jmp .return

.macos_arm64_abi:
    mov rax, macos_arm64_abi_info
    jmp .return

.ios_arm64_abi:
    mov rax, ios_arm64_abi_info
    jmp .return

.android_arm64_abi:
    mov rax, android_arm64_abi_info
    jmp .return

.return:
    ret

; String comparison function
; Input: rdi = string1, rsi = string2
; Output: rax = 0 if equal, non-zero if different
strcmp:
    push rbx
    push rcx
    push rdx
    
    mov rbx, rdi
    mov rcx, rsi
    
.cmp_loop:
    mov al, [rbx]
    mov dl, [rcx]
    cmp al, dl
    jne .not_equal
    cmp al, 0
    je .equal
    inc rbx
    inc rcx
    jmp .cmp_loop

.equal:
    xor rax, rax
    jmp .return

.not_equal:
    mov rax, 1

.return:
    pop rdx
    pop rcx
    pop rbx
    ret
