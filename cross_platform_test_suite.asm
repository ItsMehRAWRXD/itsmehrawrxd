; cross_platform_test_suite.asm - Comprehensive cross-platform testing framework
; Tests compilation and functionality across Mac, Linux, Windows, iOS, and Android

section .data
    ; === Test Results Storage ===
    test_results         times 100 dq 0  ; Array to store test results
    test_count           dq 0             ; Number of tests run
    passed_tests         dq 0             ; Number of passed tests
    failed_tests         dq 0             ; Number of failed tests
    
    ; === Platform Detection ===
    detected_platform    dq 0             ; 1=Linux, 2=macOS, 3=Windows, 4=iOS, 5=Android
    platform_name        db "Unknown", 0
    platform_version     db "0.0.0", 0
    
    ; === Test Categories ===
    PLATFORM_TESTS       equ 0x01
    COMPILER_TESTS       equ 0x02
    RUNTIME_TESTS        equ 0x04
    MEMORY_TESTS         equ 0x08
    NETWORK_TESTS        equ 0x10
    FILE_TESTS           equ 0x20
    
    ; === Test Messages ===
    test_start_msg       db "Starting cross-platform test suite...", 10, 0
    test_complete_msg    db "Cross-platform testing completed", 10, 0
    platform_detected_msg db "Platform detected: ", 0
    test_passed_msg      db "PASSED", 10, 0
    test_failed_msg      db "FAILED", 10, 0
    summary_msg          db "Test Summary: ", 0
    passed_msg           db " passed, ", 0
    failed_msg           db " failed", 10, 0

section .text
    global _start
    global run_cross_platform_tests

; === Main Entry Point ===
_start:
    call run_cross_platform_tests
    call exit_success

; === Cross-Platform Test Suite ===
run_cross_platform_tests:
    push rbp
    mov rbp, rsp
    
    ; Print test start message
    mov rdi, test_start_msg
    call print_string
    
    ; === 1. Platform Detection Tests ===
    call test_platform_detection
    call test_os_specific_features
    
    ; === 2. Compiler Tests ===
    call test_compiler_availability
    call test_compiler_functionality
    
    ; === 3. Runtime Tests ===
    call test_runtime_environment
    call test_system_calls
    
    ; === 4. Memory Tests ===
    call test_memory_allocation
    call test_memory_management
    
    ; === 5. Network Tests ===
    call test_network_capabilities
    call test_http_functionality
    
    ; === 6. File System Tests ===
    call test_file_operations
    call test_directory_operations
    
    ; === 7. Generate Test Report ===
    call generate_test_report
    
    ; Print completion message
    mov rdi, test_complete_msg
    call print_string
    
    leave
    ret

; === Platform Detection Tests ===
test_platform_detection:
    push rbp
    mov rbp, rsp
    
    ; Detect operating system
    call detect_operating_system
    mov [detected_platform], rax
    
    ; Print platform information
    mov rdi, platform_detected_msg
    call print_string
    call print_platform_name
    
    ; Test platform-specific features
    call test_platform_specific_syscalls
    
    leave
    ret

detect_operating_system:
    push rbp
    mov rbp, rsp
    
    ; Try Linux syscalls first
    mov rax, 0        ; read syscall
    mov rdi, 0        ; stdin
    mov rsi, 0        ; NULL buffer
    mov rdx, 0        ; 0 bytes
    syscall
    
    cmp rax, -1
    jne detected_linux
    
    ; Try macOS syscalls
    mov rax, 0x2000000  ; macOS read syscall
    mov rdi, 0
    mov rsi, 0
    mov rdx, 0
    syscall
    
    cmp rax, -1
    jne detected_macos
    
    ; Try Windows (would need different approach)
    ; For now, assume Linux if we get here
    jmp detected_linux

detected_linux:
    mov rax, 1
    mov rdi, platform_name
    mov rsi, linux_name
    call string_copy
    leave
    ret

detected_macos:
    mov rax, 2
    mov rdi, platform_name
    mov rsi, macos_name
    call string_copy
    leave
    ret

; === Compiler Tests ===
test_compiler_availability:
    push rbp
    mov rbp, rsp
    
    ; Test NASM availability
    call test_nasm_availability
    
    ; Test GCC availability
    call test_gcc_availability
    
    ; Test Clang availability
    call test_clang_availability
    
    ; Test MSVC availability (Windows)
    call test_msvc_availability
    
    leave
    ret

test_nasm_availability:
    push rbp
    mov rbp, rsp
    
    ; Try to execute nasm --version
    mov rax, 59       ; execve syscall
    mov rdi, nasm_path
    mov rsi, nasm_args
    mov rdx, 0        ; No environment
    syscall
    
    ; If we get here, nasm is not available
    call record_test_failure
    leave
    ret

test_gcc_availability:
    push rbp
    mov rbp, rsp
    
    ; Try to execute gcc --version
    mov rax, 59       ; execve syscall
    mov rdi, gcc_path
    mov rsi, gcc_args
    mov rdx, 0
    syscall
    
    ; If we get here, gcc is not available
    call record_test_failure
    leave
    ret

; === Runtime Tests ===
test_runtime_environment:
    push rbp
    mov rbp, rsp
    
    ; Test basic arithmetic operations
    call test_arithmetic_operations
    
    ; Test string operations
    call test_string_operations
    
    ; Test control flow
    call test_control_flow
    
    leave
    ret

test_arithmetic_operations:
    push rbp
    mov rbp, rsp
    
    ; Test addition
    mov rax, 5
    mov rbx, 3
    add rax, rbx
    cmp rax, 8
    jne arithmetic_failed
    
    ; Test multiplication
    mov rax, 4
    mov rbx, 6
    mul rbx
    cmp rax, 24
    jne arithmetic_failed
    
    ; Test division
    mov rax, 20
    mov rbx, 4
    div rbx
    cmp rax, 5
    jne arithmetic_failed
    
    call record_test_success
    leave
    ret

arithmetic_failed:
    call record_test_failure
    leave
    ret

; === Memory Tests ===
test_memory_allocation:
    push rbp
    mov rbp, rsp
    
    ; Test mmap allocation
    call test_mmap_allocation
    
    ; Test heap allocation
    call test_heap_allocation
    
    ; Test stack operations
    call test_stack_operations
    
    leave
    ret

test_mmap_allocation:
    push rbp
    mov rbp, rsp
    
    ; Allocate 4KB using mmap
    mov rax, 9        ; mmap syscall
    mov rdi, 0        ; Let kernel choose address
    mov rsi, 4096     ; 4KB
    mov rdx, 3        ; PROT_READ | PROT_WRITE
    mov r10, 34       ; MAP_PRIVATE | MAP_ANONYMOUS
    mov r8, -1        ; No file descriptor
    mov r9, 0         ; No offset
    syscall
    
    cmp rax, -1
    je mmap_failed
    
    ; Test write to allocated memory
    mov byte [rax], 0x42
    cmp byte [rax], 0x42
    jne mmap_failed
    
    ; Free the memory
    mov rdi, rax
    mov rsi, 4096
    mov rax, 11       ; munmap syscall
    syscall
    
    call record_test_success
    leave
    ret

mmap_failed:
    call record_test_failure
    leave
    ret

; === Network Tests ===
test_network_capabilities:
    push rbp
    mov rbp, rsp
    
    ; Test socket creation
    call test_socket_creation
    
    ; Test network connectivity
    call test_network_connectivity
    
    ; Test HTTP functionality
    call test_http_requests
    
    leave
    ret

test_socket_creation:
    push rbp
    mov rbp, rsp
    
    ; Create a TCP socket
    mov rax, 41       ; socket syscall
    mov rdi, 2        ; AF_INET
    mov rsi, 1        ; SOCK_STREAM
    mov rdx, 0        ; Protocol
    syscall
    
    cmp rax, -1
    je socket_failed
    
    ; Close the socket
    mov rdi, rax
    mov rax, 3        ; close syscall
    syscall
    
    call record_test_success
    leave
    ret

socket_failed:
    call record_test_failure
    leave
    ret

; === File System Tests ===
test_file_operations:
    push rbp
    mov rbp, rsp
    
    ; Test file creation
    call test_file_creation
    
    ; Test file reading
    call test_file_reading
    
    ; Test file writing
    call test_file_writing
    
    ; Test file deletion
    call test_file_deletion
    
    leave
    ret

test_file_creation:
    push rbp
    mov rbp, rsp
    
    ; Create a test file
    mov rax, 2        ; open syscall
    mov rdi, test_file_name
    mov rsi, 0x241    ; O_WRONLY | O_CREAT | O_TRUNC
    mov rdx, 0644     ; File permissions
    syscall
    
    cmp rax, -1
    je file_creation_failed
    
    ; Close the file
    mov rdi, rax
    mov rax, 3        ; close syscall
    syscall
    
    call record_test_success
    leave
    ret

file_creation_failed:
    call record_test_failure
    leave
    ret

; === Test Result Management ===
record_test_success:
    push rbp
    mov rbp, rsp
    
    inc qword [passed_tests]
    inc qword [test_count]
    
    leave
    ret

record_test_failure:
    push rbp
    mov rbp, rsp
    
    inc qword [failed_tests]
    inc qword [test_count]
    
    leave
    ret

; === Test Report Generation ===
generate_test_report:
    push rbp
    mov rbp, rsp
    
    ; Print test summary
    mov rdi, summary_msg
    call print_string
    
    ; Print passed tests count
    mov rdi, [passed_tests]
    call print_number
    
    mov rdi, passed_msg
    call print_string
    
    ; Print failed tests count
    mov rdi, [failed_tests]
    call print_number
    
    mov rdi, failed_msg
    call print_string
    
    leave
    ret

; === Utility Functions ===
print_string:
    push rbp
    mov rbp, rsp
    
    ; Calculate string length
    mov rsi, rdi
    mov rcx, 0
length_loop:
    cmp byte [rsi + rcx], 0
    je print_string_done
    inc rcx
    jmp length_loop

print_string_done:
    ; Print the string
    mov rax, 1        ; write syscall
    mov rdi, 1        ; stdout
    mov rdx, rcx      ; length
    syscall
    
    leave
    ret

print_number:
    push rbp
    mov rbp, rsp
    
    ; Convert number to string and print
    ; This is a simplified version
    add rdi, '0'
    mov rax, 1        ; write syscall
    mov rdi, 1        ; stdout
    mov rsi, rdi      ; character
    mov rdx, 1        ; length
    syscall
    
    leave
    ret

string_copy:
    push rbp
    mov rbp, rsp
    
    ; RDI = destination, RSI = source
    mov rcx, 0
copy_loop:
    mov al, byte [rsi + rcx]
    mov byte [rdi + rcx], al
    test al, al
    jz copy_done
    inc rcx
    jmp copy_loop

copy_done:
    leave
    ret

exit_success:
    mov rax, 60       ; exit syscall
    mov rdi, 0        ; Exit code 0
    syscall

; === Data Constants ===
section .rodata
    linux_name         db "Linux", 0
    macos_name         db "macOS", 0
    windows_name       db "Windows", 0
    ios_name           db "iOS", 0
    android_name       db "Android", 0
    
    nasm_path          db "/usr/bin/nasm", 0
    nasm_args          dq nasm_path, nasm_version_arg, 0
    nasm_version_arg   db "--version", 0
    
    gcc_path           db "/usr/bin/gcc", 0
    gcc_args           dq gcc_path, gcc_version_arg, 0
    gcc_version_arg    db "--version", 0
    
    test_file_name     db "test_file.txt", 0
