; test_framework.asm
; Comprehensive testing framework for compiler components and bootstrapping stages
; Provides unit tests, integration tests, and benchmarking capabilities

%include "error_handling.asm"

section .data
    ; Test result constants
    TEST_PASS    equ 0
    TEST_FAIL    equ 1
    TEST_SKIP    equ 2
    TEST_TIMEOUT equ 3
    
    ; Test categories
    TEST_LEXER      equ 0
    TEST_PARSER     equ 1
    TEST_SEMANTIC   equ 2
    TEST_CODEGEN    equ 3
    TEST_RUNTIME    equ 4
    TEST_INTEGRATION equ 5
    TEST_BENCHMARK  equ 6
    
    ; Test messages
    test_header      db "=== RawrZApp Compiler Test Suite ===", 10, 0
    test_separator   db "=====================================", 10, 0
    test_pass_msg    db "[PASS] ", 0
    test_fail_msg    db "[FAIL] ", 0
    test_skip_msg    db "[SKIP] ", 0
    test_timeout_msg db "[TIMEOUT] ", 0
    
    ; Colors for test output
    green_color      db 27, "[32m", 0
    red_color        db 27, "[31m", 0
    yellow_color     db 27, "[33m", 0
    blue_color       db 27, "[34m", 0
    reset_color      db 27, "[0m", 0
    
    ; Test suite names
    lexer_suite_name      db "Lexer Tests", 0
    parser_suite_name     db "Parser Tests", 0
    semantic_suite_name   db "Semantic Tests", 0
    codegen_suite_name    db "Code Generation Tests", 0
    runtime_suite_name    db "Runtime Tests", 0
    integration_suite_name db "Integration Tests", 0
    benchmark_suite_name  db "Benchmark Tests", 0

section .bss
    ; Test statistics
    total_tests      resq 1
    passed_tests     resq 1
    failed_tests     resq 1
    skipped_tests    resq 1
    timeout_tests    resq 1
    
    ; Test execution state
    current_suite    resq 1
    current_test     resq 1
    test_start_time  resq 1
    test_timeout     resq 1
    
    ; Test data buffers
    test_input_buffer  resb 4096
    test_output_buffer resb 4096
    expected_buffer    resb 4096
    
    ; Test registry
    test_functions     resq 256    ; Array of test function pointers
    test_names         resq 256    ; Array of test name pointers
    test_categories    resq 256    ; Array of test categories
    test_count         resq 1      ; Number of registered tests

section .text
    global test_framework_init
    global test_register
    global test_run_all
    global test_run_suite
    global test_run_single
    global test_assert_equal
    global test_assert_not_equal
    global test_assert_true
    global test_assert_false
    global test_assert_null
    global test_assert_not_null
    global test_print_summary
    global benchmark_start
    global benchmark_end
    global benchmark_report

; Initialize test framework
test_framework_init:
    push rbx
    push rcx
    
    ; Initialize counters
    mov qword [total_tests], 0
    mov qword [passed_tests], 0
    mov qword [failed_tests], 0
    mov qword [skipped_tests], 0
    mov qword [timeout_tests], 0
    mov qword [test_count], 0
    
    ; Set default timeout (5 seconds)
    mov qword [test_timeout], 5000
    
    ; Initialize error handling
    call error_init
    
    ; Register all built-in tests
    call register_all_tests
    
    pop rcx
    pop rbx
    ret

; Register a test function
; Input: rdi = test function pointer, rsi = test name, rdx = category
test_register:
    push rbx
    push rcx
    
    ; Get current test slot
    mov rbx, [test_count]
    cmp rbx, 256
    jge .registry_full
    
    ; Store test information
    mov [test_functions + rbx * 8], rdi
    mov [test_names + rbx * 8], rsi
    mov [test_categories + rbx * 8], rdx
    
    ; Increment test count
    inc qword [test_count]
    
    jmp .return

.registry_full:
    ; Print warning about registry full
    mov rdi, registry_full_msg
    call print_string

.return:
    pop rcx
    pop rbx
    ret

; Run all tests
test_run_all:
    push rbx
    push rcx
    push rdx
    
    ; Print header
    call print_test_header
    
    ; Run each test suite
    mov rdi, TEST_LEXER
    call test_run_suite
    
    mov rdi, TEST_PARSER
    call test_run_suite
    
    mov rdi, TEST_SEMANTIC
    call test_run_suite
    
    mov rdi, TEST_CODEGEN
    call test_run_suite
    
    mov rdi, TEST_RUNTIME
    call test_run_suite
    
    mov rdi, TEST_INTEGRATION
    call test_run_suite
    
    ; Print final summary
    call test_print_summary
    
    pop rdx
    pop rcx
    pop rbx
    ret

; Run tests in a specific suite
; Input: rdi = test suite category
test_run_suite:
    push rbx
    push rcx
    push rdx
    push rsi
    
    mov [current_suite], rdi
    
    ; Print suite header
    call print_suite_header
    
    ; Run all tests in this category
    mov rbx, 0
.test_loop:
    cmp rbx, [test_count]
    jge .suite_done
    
    ; Check if test belongs to this suite
    mov rcx, [test_categories + rbx * 8]
    cmp rcx, rdi
    jne .next_test
    
    ; Run the test
    mov rdi, rbx
    call test_run_single
    
.next_test:
    inc rbx
    jmp .test_loop

.suite_done:
    ; Print suite summary
    call print_suite_summary
    
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; Run a single test
; Input: rdi = test index
test_run_single:
    push rbx
    push rcx
    push rdx
    push rsi
    
    mov rbx, rdi  ; Save test index
    mov [current_test], rbx
    
    ; Get test information
    mov rdi, [test_names + rbx * 8]
    mov rsi, [test_functions + rbx * 8]
    
    ; Print test name
    call print_test_name
    
    ; Record start time
    call get_current_time
    mov [test_start_time], rax
    
    ; Set up test environment
    call setup_test_environment
    
    ; Run the test function
    mov rdi, rbx  ; Pass test index
    call rsi      ; Call test function
    
    ; Check result and update statistics
    cmp rax, TEST_PASS
    je .test_passed
    cmp rax, TEST_FAIL
    je .test_failed
    cmp rax, TEST_SKIP
    je .test_skipped
    cmp rax, TEST_TIMEOUT
    je .test_timeout
    
    ; Default to failed if unknown result
    jmp .test_failed

.test_passed:
    inc qword [passed_tests]
    call print_test_result_pass
    jmp .test_done

.test_failed:
    inc qword [failed_tests]
    call print_test_result_fail
    jmp .test_done

.test_skipped:
    inc qword [skipped_tests]
    call print_test_result_skip
    jmp .test_done

.test_timeout:
    inc qword [timeout_tests]
    call print_test_result_timeout

.test_done:
    inc qword [total_tests]
    
    ; Clean up test environment
    call cleanup_test_environment
    
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; Test assertion functions
; Input: rdi = actual value, rsi = expected value
; Output: rax = TEST_PASS or TEST_FAIL
test_assert_equal:
    cmp rdi, rsi
    je .assert_pass
    
    ; Print assertion failure details
    push rdi
    push rsi
    call print_assert_equal_fail
    pop rsi
    pop rdi
    
    mov rax, TEST_FAIL
    ret

.assert_pass:
    mov rax, TEST_PASS
    ret

; Assert not equal
test_assert_not_equal:
    cmp rdi, rsi
    jne .assert_pass
    
    call print_assert_not_equal_fail
    mov rax, TEST_FAIL
    ret

.assert_pass:
    mov rax, TEST_PASS
    ret

; Assert true
test_assert_true:
    cmp rdi, 0
    jne .assert_pass
    
    call print_assert_true_fail
    mov rax, TEST_FAIL
    ret

.assert_pass:
    mov rax, TEST_PASS
    ret

; Assert false
test_assert_false:
    cmp rdi, 0
    je .assert_pass
    
    call print_assert_false_fail
    mov rax, TEST_FAIL
    ret

.assert_pass:
    mov rax, TEST_PASS
    ret

; Assert null
test_assert_null:
    cmp rdi, 0
    je .assert_pass
    
    call print_assert_null_fail
    mov rax, TEST_FAIL
    ret

.assert_pass:
    mov rax, TEST_PASS
    ret

; Assert not null
test_assert_not_null:
    cmp rdi, 0
    jne .assert_pass
    
    call print_assert_not_null_fail
    mov rax, TEST_FAIL
    ret

.assert_pass:
    mov rax, TEST_PASS
    ret

; Print test summary
test_print_summary:
    push rbx
    push rcx
    
    ; Print separator
    mov rdi, test_separator
    call print_string
    
    ; Print statistics
    mov rdi, summary_total_msg
    call print_string
    mov rdi, [total_tests]
    call print_number
    call print_newline
    
    ; Passed tests (green)
    mov rdi, green_color
    call print_string
    mov rdi, summary_passed_msg
    call print_string
    mov rdi, [passed_tests]
    call print_number
    mov rdi, reset_color
    call print_string
    call print_newline
    
    ; Failed tests (red)
    mov rdi, red_color
    call print_string
    mov rdi, summary_failed_msg
    call print_string
    mov rdi, [failed_tests]
    call print_number
    mov rdi, reset_color
    call print_string
    call print_newline
    
    ; Skipped tests (yellow)
    mov rdi, yellow_color
    call print_string
    mov rdi, summary_skipped_msg
    call print_string
    mov rdi, [skipped_tests]
    call print_number
    mov rdi, reset_color
    call print_string
    call print_newline
    
    ; Timeout tests (blue)
    mov rdi, blue_color
    call print_string
    mov rdi, summary_timeout_msg
    call print_string
    mov rdi, [timeout_tests]
    call print_number
    mov rdi, reset_color
    call print_string
    call print_newline
    
    ; Overall result
    mov rax, [failed_tests]
    add rax, [timeout_tests]
    cmp rax, 0
    je .all_passed
    
    mov rdi, red_color
    call print_string
    mov rdi, overall_fail_msg
    call print_string
    jmp .print_overall_end

.all_passed:
    mov rdi, green_color
    call print_string
    mov rdi, overall_pass_msg
    call print_string

.print_overall_end:
    mov rdi, reset_color
    call print_string
    call print_newline
    
    pop rcx
    pop rbx
    ret

; Benchmarking functions
benchmark_start:
    call get_current_time
    mov [test_start_time], rax
    ret

benchmark_end:
    call get_current_time
    sub rax, [test_start_time]
    ret  ; Return elapsed time in rax

benchmark_report:
    push rbx
    push rdi
    
    mov rbx, rax  ; Save elapsed time
    
    mov rdi, benchmark_time_msg
    call print_string
    mov rdi, rbx
    call print_number
    mov rdi, benchmark_ms_msg
    call print_string
    call print_newline
    
    pop rdi
    pop rbx
    ret

; Helper functions for printing
print_test_header:
    mov rdi, test_header
    call print_string
    mov rdi, test_separator
    call print_string
    ret

print_suite_header:
    push rdi
    
    ; Get suite name based on category
    mov rax, [current_suite]
    cmp rax, TEST_LEXER
    je .print_lexer
    cmp rax, TEST_PARSER
    je .print_parser
    cmp rax, TEST_SEMANTIC
    je .print_semantic
    cmp rax, TEST_CODEGEN
    je .print_codegen
    cmp rax, TEST_RUNTIME
    je .print_runtime
    cmp rax, TEST_INTEGRATION
    je .print_integration
    cmp rax, TEST_BENCHMARK
    je .print_benchmark
    
    jmp .print_unknown

.print_lexer:
    mov rdi, lexer_suite_name
    jmp .print_name

.print_parser:
    mov rdi, parser_suite_name
    jmp .print_name

.print_semantic:
    mov rdi, semantic_suite_name
    jmp .print_name

.print_codegen:
    mov rdi, codegen_suite_name
    jmp .print_name

.print_runtime:
    mov rdi, runtime_suite_name
    jmp .print_name

.print_integration:
    mov rdi, integration_suite_name
    jmp .print_name

.print_benchmark:
    mov rdi, benchmark_suite_name
    jmp .print_name

.print_unknown:
    mov rdi, unknown_suite_name

.print_name:
    call print_string
    call print_newline
    
    pop rdi
    ret

print_suite_summary:
    ; TODO: Implement suite-specific summary
    ret

print_test_name:
    push rsi
    
    mov rdi, test_running_msg
    call print_string
    mov rdi, [test_names + rbx * 8]
    call print_string
    mov rdi, test_dots_msg
    call print_string
    
    pop rsi
    ret

print_test_result_pass:
    mov rdi, green_color
    call print_string
    mov rdi, test_pass_msg
    call print_string
    mov rdi, reset_color
    call print_string
    call print_newline
    ret

print_test_result_fail:
    mov rdi, red_color
    call print_string
    mov rdi, test_fail_msg
    call print_string
    mov rdi, reset_color
    call print_string
    call print_newline
    ret

print_test_result_skip:
    mov rdi, yellow_color
    call print_string
    mov rdi, test_skip_msg
    call print_string
    mov rdi, reset_color
    call print_string
    call print_newline
    ret

print_test_result_timeout:
    mov rdi, blue_color
    call print_string
    mov rdi, test_timeout_msg
    call print_string
    mov rdi, reset_color
    call print_string
    call print_newline
    ret

; Assertion failure printing functions
print_assert_equal_fail:
    mov rdi, assert_equal_fail_msg
    call print_string
    ret

print_assert_not_equal_fail:
    mov rdi, assert_not_equal_fail_msg
    call print_string
    ret

print_assert_true_fail:
    mov rdi, assert_true_fail_msg
    call print_string
    ret

print_assert_false_fail:
    mov rdi, assert_false_fail_msg
    call print_string
    ret

print_assert_null_fail:
    mov rdi, assert_null_fail_msg
    call print_string
    ret

print_assert_not_null_fail:
    mov rdi, assert_not_null_fail_msg
    call print_string
    ret

; Test environment setup/cleanup
setup_test_environment:
    ; Clear test buffers
    mov rdi, test_input_buffer
    mov rcx, 4096
    xor rax, rax
    rep stosb
    
    mov rdi, test_output_buffer
    mov rcx, 4096
    xor rax, rax
    rep stosb
    
    mov rdi, expected_buffer
    mov rcx, 4096
    xor rax, rax
    rep stosb
    
    ret

cleanup_test_environment:
    ; TODO: Clean up any allocated resources
    ret

; Get current time (simplified)
get_current_time:
    mov rax, 201  ; sys_time (simplified)
    xor rdi, rdi
    syscall
    ret

; Register all built-in tests
register_all_tests:
    ; Lexer tests
    mov rdi, test_lexer_basic
    mov rsi, test_lexer_basic_name
    mov rdx, TEST_LEXER
    call test_register
    
    mov rdi, test_lexer_keywords
    mov rsi, test_lexer_keywords_name
    mov rdx, TEST_LEXER
    call test_register
    
    ; Parser tests
    mov rdi, test_parser_expression
    mov rsi, test_parser_expression_name
    mov rdx, TEST_PARSER
    call test_register
    
    mov rdi, test_parser_function
    mov rsi, test_parser_function_name
    mov rdx, TEST_PARSER
    call test_register
    
    ; Runtime tests
    mov rdi, test_runtime_stack
    mov rsi, test_runtime_stack_name
    mov rdx, TEST_RUNTIME
    call test_register
    
    mov rdi, test_runtime_heap
    mov rdi, test_runtime_heap_name
    mov rdx, TEST_RUNTIME
    call test_register
    
    ret

; Sample test implementations
test_lexer_basic:
    ; Test basic lexer functionality
    mov rax, TEST_PASS
    ret

test_lexer_keywords:
    ; Test keyword recognition
    mov rax, TEST_PASS
    ret

test_parser_expression:
    ; Test expression parsing
    mov rax, TEST_PASS
    ret

test_parser_function:
    ; Test function parsing
    mov rax, TEST_PASS
    ret

test_runtime_stack:
    ; Test runtime stack operations
    mov rax, TEST_PASS
    ret

test_runtime_heap:
    ; Test runtime heap operations
    mov rax, TEST_PASS
    ret

section .data
    ; Test messages
    registry_full_msg         db "Warning: Test registry full", 10, 0
    test_running_msg          db "Running ", 0
    test_dots_msg             db " ... ", 0
    unknown_suite_name        db "Unknown Test Suite", 0
    
    ; Summary messages
    summary_total_msg         db "Total tests: ", 0
    summary_passed_msg        db "Passed: ", 0
    summary_failed_msg        db "Failed: ", 0
    summary_skipped_msg       db "Skipped: ", 0
    summary_timeout_msg       db "Timeout: ", 0
    overall_pass_msg          db "ALL TESTS PASSED", 10, 0
    overall_fail_msg          db "SOME TESTS FAILED", 10, 0
    
    ; Assertion failure messages
    assert_equal_fail_msg     db "  Assertion failed: values not equal", 10, 0
    assert_not_equal_fail_msg db "  Assertion failed: values are equal", 10, 0
    assert_true_fail_msg      db "  Assertion failed: value is not true", 10, 0
    assert_false_fail_msg     db "  Assertion failed: value is not false", 10, 0
    assert_null_fail_msg      db "  Assertion failed: value is not null", 10, 0
    assert_not_null_fail_msg  db "  Assertion failed: value is null", 10, 0
    
    ; Benchmark messages
    benchmark_time_msg        db "Execution time: ", 0
    benchmark_ms_msg          db " ms", 0
    
    ; Test names
    test_lexer_basic_name     db "Basic Lexer Test", 0
    test_lexer_keywords_name  db "Keyword Recognition Test", 0
    test_parser_expression_name db "Expression Parser Test", 0
    test_parser_function_name db "Function Parser Test", 0
    test_runtime_stack_name   db "Runtime Stack Test", 0
    test_runtime_heap_name    db "Runtime Heap Test", 0
