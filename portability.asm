; portability.asm - Cross-OS system call macros and runtime detection
; The foundation of god-tier cross-platform assembly programming

section .data
    ; OS detection strings
    os_name_linux_str       db "Linux", 0
    os_name_macos_str       db "Darwin", 0
    os_name_windows_str     db "Windows", 0
    
    ; Runtime detection results
    detected_os_id          dq 0  ; 0=Unknown, 1=Linux, 2=macOS, 3=Windows
    syscall_table_ptr       dq 0  ; Pointer to OS-specific syscall table
    feature_flags           dq 0  ; Bitfield of detected features
    
    ; Feature flags
    FEATURE_NETWORK         equ 0x01
    FEATURE_MMAP            equ 0x02
    FEATURE_THREADS         equ 0x04
    FEATURE_AVX             equ 0x08
    FEATURE_SSE4            equ 0x10
    
    ; Error messages
    unsupported_os_error    db "Unsupported operating system detected", 10, 0
    feature_probe_error     db "Feature detection failed", 10, 0

section .bss
    uname_buffer            resb 1024  ; Buffer for uname syscall
    cpu_info_buffer         resb 512   ; Buffer for CPU feature detection
    jit_code_buffer         resb 4096  ; Buffer for JIT-generated code

section .text
    global probe_os_and_features
    global get_syscall_table
    global detect_cpu_features
    global jit_optimize_code

; === Generic System Call Macros ===
%macro SYS_OPEN 3  ; path, flags, mode
    %ifdef __linux__
        mov rax, 2      ; Linux 'open' syscall
        mov rdi, %1
        mov rsi, %2
        mov rdx, %3
        syscall
    %endif
    %ifdef __MACH__
        mov rax, 0x2000002 ; macOS 'open' syscall
        mov rdi, %1
        mov rsi, %2
        mov rdx, %3
        syscall
    %endif
    %ifdef __WINDOWS__
        ; Windows syscall (would need different approach)
        ; This is conceptual - Windows syscalls are more complex
        mov rax, 0x00000000  ; Placeholder
        mov rcx, %1
        mov rdx, %2
        mov r8, %3
        syscall
    %endif
%endmacro

%macro SYS_WRITE 3 ; fd, buffer, count
    %ifdef __linux__
        mov rax, 1      ; Linux 'write' syscall
        mov rdi, %1
        mov rsi, %2
        mov rdx, %3
        syscall
    %endif
    %ifdef __MACH__
        mov rax, 0x2000004 ; macOS 'write' syscall
        mov rdi, %1
        mov rsi, %2
        mov rdx, %3
        syscall
    %endif
    %ifdef __WINDOWS__
        mov rax, 0x00000001  ; Placeholder
        mov rcx, %1
        mov rdx, %2
        mov r8, %3
        syscall
    %endif
%endmacro

%macro SYS_ALLOC 1 ; size
    %ifdef __linux__
        mov rax, 9      ; Linux 'mmap' syscall
        mov rdi, 0      ; addr
        mov rsi, %1
        mov rdx, 3      ; prot (RW)
        mov r10, 34     ; flags (PRIVATE|ANON)
        mov r8, -1      ; fd
        mov r9, 0       ; offset
        syscall
    %endif
    %ifdef __MACH__
        mov rax, 0x2000009 ; macOS 'mmap' syscall
        mov rdi, 0
        mov rsi, %1
        mov rdx, 3
        mov r10, 34
        mov r8, -1
        mov r9, 0
        syscall
    %endif
    %ifdef __WINDOWS__
        ; Windows VirtualAlloc equivalent
        mov rax, 0x00000002  ; Placeholder
        mov rcx, 0
        mov rdx, %1
        mov r8, 0x1000  ; MEM_COMMIT
        mov r9, 0x04    ; PAGE_READWRITE
        syscall
    %endif
%endmacro

%macro NET_CONNECT 2 ; host, port
    %ifdef __linux__
        ; Linux socket syscalls
        mov rax, 41     ; socket
        mov rdi, 2      ; AF_INET
        mov rsi, 1      ; SOCK_STREAM
        mov rdx, 0      ; protocol
        syscall
        mov rbx, rax    ; save socket fd
        
        ; connect syscall would follow
        mov rax, 42     ; connect
        mov rdi, rbx
        ; ... setup sockaddr structure ...
        syscall
    %endif
    %ifdef __MACH__
        ; macOS socket syscalls (similar to Linux)
        mov rax, 0x2000061  ; socket
        mov rdi, 2
        mov rsi, 1
        mov rdx, 0
        syscall
        mov rbx, rax
        
        mov rax, 0x2000062  ; connect
        mov rdi, rbx
        ; ... setup sockaddr structure ...
        syscall
    %endif
%endmacro

; === Runtime OS Detection ===
probe_os_and_features:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    push rdx
    
    ; Try to detect OS using uname syscall
    call detect_os_via_uname
    cmp rax, 0
    jl .fallback_detection
    
    ; OS detected successfully, now probe features
    call detect_cpu_features
    call detect_network_support
    call detect_memory_features
    
    pop rdx
    pop rcx
    pop rbx
    leave
    ret

.fallback_detection:
    ; Fallback to compile-time detection
    %ifdef __linux__
        mov qword [detected_os_id], 1
        mov qword [syscall_table_ptr], linux_syscall_table
    %endif
    %ifdef __MACH__
        mov qword [detected_os_id], 2
        mov qword [syscall_table_ptr], macos_syscall_table
    %endif
    %ifdef __WINDOWS__
        mov qword [detected_os_id], 3
        mov qword [syscall_table_ptr], windows_syscall_table
    %endif
    
    pop rdx
    pop rcx
    pop rbx
    leave
    ret

; Detect OS using uname syscall
detect_os_via_uname:
    push rbp
    mov rbp, rsp
    
    %ifdef __linux__
        mov rax, 63     ; uname syscall
        mov rdi, uname_buffer
        syscall
        cmp rax, 0
        jl .error
        
        ; Check sysname field (first 65 bytes)
        mov rdi, uname_buffer
        mov rsi, os_name_linux_str
        call string_compare
        cmp rax, 1
        je .is_linux
        
        mov rsi, os_name_macos_str
        call string_compare
        cmp rax, 1
        je .is_macos
        
        jmp .unknown
    %endif
    
    %ifdef __MACH__
        mov rax, 0x20000A5  ; uname syscall on macOS
        mov rdi, uname_buffer
        syscall
        cmp rax, 0
        jl .error
        
        mov rdi, uname_buffer
        mov rsi, os_name_macos_str
        call string_compare
        cmp rax, 1
        je .is_macos
        
        mov rsi, os_name_linux_str
        call string_compare
        cmp rax, 1
        je .is_linux
        
        jmp .unknown
    %endif
    
.is_linux:
    mov qword [detected_os_id], 1
    mov qword [syscall_table_ptr], linux_syscall_table
    mov rax, 1
    leave
    ret

.is_macos:
    mov qword [detected_os_id], 2
    mov qword [syscall_table_ptr], macos_syscall_table
    mov rax, 1
    leave
    ret

.unknown:
    mov qword [detected_os_id], 0
    mov rax, -1
    leave
    ret

.error:
    mov rax, -1
    leave
    ret

; Detect CPU features for optimization
detect_cpu_features:
    push rbp
    mov rbp, rsp
    
    ; Use CPUID to detect features
    mov rax, 1
    cpuid
    
    ; Check for SSE4.2
    test ecx, 0x100000
    jz .no_sse4
    or qword [feature_flags], FEATURE_SSE4

.no_sse4:
    ; Check for AVX
    test ecx, 0x10000000
    jz .no_avx
    or qword [feature_flags], FEATURE_AVX

.no_avx:
    ; Check for threading support
    test edx, 0x10000000
    jz .no_threads
    or qword [feature_flags], FEATURE_THREADS

.no_threads:
    leave
    ret

; Detect network support
detect_network_support:
    push rbp
    mov rbp, rsp
    
    ; Try to create a socket to test network support
    %ifdef __linux__
        mov rax, 41     ; socket syscall
        mov rdi, 2      ; AF_INET
        mov rsi, 1      ; SOCK_STREAM
        mov rdx, 0      ; protocol
        syscall
        cmp rax, 0
        jl .no_network
        mov rdi, rax
        mov rax, 3      ; close syscall
        syscall
        or qword [feature_flags], FEATURE_NETWORK
    %endif
    
    %ifdef __MACH__
        mov rax, 0x2000061  ; socket syscall
        mov rdi, 2
        mov rsi, 1
        mov rdx, 0
        syscall
        cmp rax, 0
        jl .no_network
        mov rdi, rax
        mov rax, 0x2000006  ; close syscall
        syscall
        or qword [feature_flags], FEATURE_NETWORK
    %endif
    
.no_network:
    leave
    ret

; Detect memory management features
detect_memory_features:
    push rbp
    mov rbp, rsp
    
    ; Test mmap functionality
    mov rdi, 4096       ; 4KB test allocation
    call test_mmap
    cmp rax, 0
    jl .no_mmap
    or qword [feature_flags], FEATURE_MMAP
    
    ; Free the test allocation
    mov rdi, rax
    mov rsi, 4096
    call test_munmap

.no_mmap:
    leave
    ret

; Test mmap functionality
test_mmap:
    %ifdef __linux__
        mov rax, 9      ; mmap syscall
        mov rdi, 0      ; addr
        mov rsi, rdi    ; size (from parameter)
        mov rdx, 3      ; prot (RW)
        mov r10, 34     ; flags (PRIVATE|ANON)
        mov r8, -1      ; fd
        mov r9, 0       ; offset
        syscall
    %endif
    %ifdef __MACH__
        mov rax, 0x2000009
        mov rdi, 0
        mov rsi, rdi
        mov rdx, 3
        mov r10, 34
        mov r8, -1
        mov r9, 0
        syscall
    %endif
    ret

; Test munmap functionality
test_munmap:
    %ifdef __linux__
        mov rax, 11     ; munmap syscall
        ; rdi and rsi already set from parameters
        syscall
    %endif
    %ifdef __MACH__
        mov rax, 0x2000049  ; munmap syscall
        syscall
    %endif
    ret

; Get the appropriate syscall table for current OS
get_syscall_table:
    mov rax, [syscall_table_ptr]
    ret

; JIT code optimization based on detected features
jit_optimize_code:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    push rdx
    
    ; Allocate executable memory for JIT code
    mov rdi, 4096
    call allocate_executable_memory
    mov rbx, rax        ; rbx = JIT code buffer
    
    ; Generate optimized code based on features
    mov rcx, [feature_flags]
    
    ; Check for AVX support
    test rcx, FEATURE_AVX
    jz .no_avx_opt
    call generate_avx_optimized_code
    jmp .continue_opt

.no_avx_opt:
    ; Check for SSE4 support
    test rcx, FEATURE_SSE4
    jz .no_sse4_opt
    call generate_sse4_optimized_code
    jmp .continue_opt

.no_sse4_opt:
    ; Generate standard optimized code
    call generate_standard_optimized_code

.continue_opt:
    ; Check for threading support
    test rcx, FEATURE_THREADS
    jz .no_thread_opt
    call generate_threaded_code

.no_thread_opt:
    ; Store JIT code buffer for later use
    mov [jit_code_buffer], rbx
    
    pop rdx
    pop rcx
    pop rbx
    leave
    ret

; Allocate executable memory for JIT code
allocate_executable_memory:
    %ifdef __linux__
        mov rax, 9      ; mmap syscall
        mov rdi, 0      ; addr
        mov rsi, rdi    ; size (from parameter)
        mov rdx, 7      ; prot (RWX)
        mov r10, 34     ; flags (PRIVATE|ANON)
        mov r8, -1      ; fd
        mov r9, 0       ; offset
        syscall
    %endif
    %ifdef __MACH__
        mov rax, 0x2000009
        mov rdi, 0
        mov rsi, rdi
        mov rdx, 7      ; prot (RWX)
        mov r10, 34
        mov r8, -1
        mov r9, 0
        syscall
    %endif
    ret

; Generate AVX-optimized code
generate_avx_optimized_code:
    ; This would generate AVX instructions for vectorized operations
    ; For template processing, this could vectorize string operations
    ret

; Generate SSE4-optimized code
generate_sse4_optimized_code:
    ; This would generate SSE4 instructions for optimized operations
    ret

; Generate standard optimized code
generate_standard_optimized_code:
    ; This would generate standard x86-64 optimized code
    ret

; Generate threaded code
generate_threaded_code:
    ; This would generate code that can utilize multiple threads
    ret

; String comparison utility
string_compare:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    mov rbx, rdi        ; rbx = string 1
    mov rcx, rsi        ; rcx = string 2
    
.compare_loop:
    mov al, [rbx]
    mov dl, [rcx]
    cmp al, dl
    jne .not_equal
    cmp al, 0
    je .equal
    inc rbx
    inc rcx
    jmp .compare_loop

.equal:
    mov rax, 1
    jmp .done

.not_equal:
    mov rax, 0

.done:
    pop rcx
    pop rbx
    leave
    ret

; === OS-Specific Syscall Tables ===
section .rodata
linux_syscall_table:
    dq 2       ; SYS_OPEN
    dq 1       ; SYS_WRITE
    dq 9       ; SYS_MMAP
    dq 11      ; SYS_MUNMAP
    dq 41      ; SYS_SOCKET
    dq 42      ; SYS_CONNECT
    dq 60      ; SYS_EXIT

macos_syscall_table:
    dq 0x2000002   ; SYS_OPEN
    dq 0x2000004   ; SYS_WRITE
    dq 0x2000009   ; SYS_MMAP
    dq 0x2000049   ; SYS_MUNMAP
    dq 0x2000061   ; SYS_SOCKET
    dq 0x2000062   ; SYS_CONNECT
    dq 0x2000001   ; SYS_EXIT

windows_syscall_table:
    dq 0x00000000  ; SYS_OPEN (placeholder)
    dq 0x00000001  ; SYS_WRITE (placeholder)
    dq 0x00000002  ; SYS_ALLOC (placeholder)
    dq 0x00000003  ; SYS_FREE (placeholder)
    dq 0x00000004  ; SYS_SOCKET (placeholder)
    dq 0x00000005  ; SYS_CONNECT (placeholder)
    dq 0x00000006  ; SYS_EXIT (placeholder)
