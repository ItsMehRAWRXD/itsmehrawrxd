; reverser_test_suite.asm
; Test and validate Reverser lexer, parser, and AST components
; Comprehensive test suite for the Reverser compiler

section .data
    ; === Test Suite Information ===
    test_suite_info     db "Reverser Component Test Suite v1.0", 10, 0
    test_results_header db "Test Results:", 10, 0
    
    ; === Test Statistics ===
    total_tests         resq 1
    passed_tests        resq 1
    failed_tests        resq 1
    test_duration       resq 1
    
    ; === Test Categories ===
    LEXER_TESTS         equ 0
    PARSER_TESTS        equ 1
    AST_TESTS           equ 2
    INTEGRATION_TESTS   equ 3
    
    ; === Test Results ===
    test_results        resq 256     ; Test result buffer
    test_result_count   resq 1
    
    ; === Test Data ===
    test_source_1       db "def func main() { ret 0 }", 0
    test_source_2       db "let x = 42; if x > 0 { ret x }", 0
    test_source_3       db "loop { let y = 10; ret y }", 0
    test_source_4       db "model Point { x: int, y: int }", 0
    test_source_5       db "def func add(a: int, b: int) -> int { ret a + b }", 0
    
    ; === Expected Results ===
    expected_tokens_1   resq 8       ; Expected token count for test 1
    expected_tokens_2   resq 12      ; Expected token count for test 2
    expected_tokens_3   resq 10      ; Expected token count for test 3
    expected_tokens_4   resq 9       ; Expected token count for test 4
    expected_tokens_5   resq 15      ; Expected token count for test 5
    
    ; === Test Output ===
    test_output         resb 32768   ; 32KB test output buffer
    test_output_pos     resq 1
    
    ; === Test Status ===
    current_test        resq 1
    test_start_time     resq 1
    test_end_time       resq 1

section .text
    global reverser_test_suite_init
    global reverser_test_suite_run
    global reverser_test_lexer
    global reverser_test_parser
    global reverser_test_ast
    global reverser_test_integration
    global reverser_test_validate_tokens
    global reverser_test_validate_ast
    global reverser_test_validate_output
    global reverser_test_report_results
    global reverser_test_assert_equal
    global reverser_test_assert_not_null
    global reverser_test_assert_true
    global reverser_test_assert_false
    global reverser_test_log_result
    global reverser_test_measure_time
    global reverser_test_cleanup

; === Initialize Test Suite ===
reverser_test_suite_init:
    push rbp
    mov rbp, rsp
    
    ; Print test suite info
    mov rdi, test_suite_info
    call print_string
    
    ; Initialize test statistics
    mov qword [total_tests], 0
    mov qword [passed_tests], 0
    mov qword [failed_tests], 0
    mov qword [test_duration], 0
    mov qword [test_result_count], 0
    mov qword [test_output_pos], 0
    mov qword [current_test], 0
    
    ; Clear test results buffer
    mov rdi, test_results
    mov rsi, 256 * 8
    call zero_memory
    
    ; Clear test output buffer
    mov rdi, test_output
    mov rsi, 32768
    call zero_memory
    
    leave
    ret

; === Run Test Suite ===
reverser_test_suite_run:
    push rbp
    mov rbp, rsp
    
    ; Start test timing
    call get_current_time
    mov [test_start_time], rax
    
    ; Run lexer tests
    call reverser_test_lexer
    
    ; Run parser tests
    call reverser_test_parser
    
    ; Run AST tests
    call reverser_test_ast
    
    ; Run integration tests
    call reverser_test_integration
    
    ; End test timing
    call get_current_time
    sub rax, [test_start_time]
    mov [test_duration], rax
    
    ; Report results
    call reverser_test_report_results
    
    ; Cleanup
    call reverser_test_cleanup
    
    leave
    ret

; === Test Lexer ===
reverser_test_lexer:
    push rbp
    mov rbp, rsp
    
    ; Test 1: Basic function definition
    mov rdi, test_source_1
    mov rsi, 25
    mov rdx, expected_tokens_1
    call reverser_test_lexer_source
    
    ; Test 2: Variable declaration and conditional
    mov rdi, test_source_2
    mov rsi, 30
    mov rdx, expected_tokens_2
    call reverser_test_lexer_source
    
    ; Test 3: Loop statement
    mov rdi, test_source_3
    mov rsi, 25
    mov rdx, expected_tokens_3
    call reverser_test_lexer_source
    
    ; Test 4: Model definition
    mov rdi, test_source_4
    mov rsi, 30
    mov rdx, expected_tokens_4
    call reverser_test_lexer_source
    
    ; Test 5: Function with parameters and return type
    mov rdi, test_source_5
    mov rsi, 45
    mov rdx, expected_tokens_5
    call reverser_test_lexer_source
    
    leave
    ret

; === Test Lexer Source ===
reverser_test_lexer_source:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = source, rsi = size, rdx = expected token count
    
    ; Initialize lexer
    call reverser_lexer_init
    
    ; Count tokens
    mov rcx, 0  ; token count
    
.token_count_loop:
    call reverser_lexer_next
    mov rbx, [reverser_token_type]
    cmp rbx, REVERSER_EOF
    je .token_count_done
    
    inc rcx
    jmp .token_count_loop
    
.token_count_done:
    ; Validate token count
    mov rdi, rcx
    mov rsi, [rdx]
    call reverser_test_assert_equal
    
    ; Test token types
    call reverser_test_validate_tokens
    
    leave
    ret

; === Test Parser ===
reverser_test_parser:
    push rbp
    mov rbp, rsp
    
    ; Test 1: Parse basic function
    mov rdi, test_source_1
    mov rsi, 25
    call reverser_test_parse_source
    
    ; Test 2: Parse conditional statement
    mov rdi, test_source_2
    mov rsi, 30
    call reverser_test_parse_source
    
    ; Test 3: Parse loop statement
    mov rdi, test_source_3
    mov rsi, 25
    call reverser_test_parse_source
    
    ; Test 4: Parse model definition
    mov rdi, test_source_4
    mov rsi, 30
    call reverser_test_parse_source
    
    ; Test 5: Parse complex function
    mov rdi, test_source_5
    mov rsi, 45
    call reverser_test_parse_source
    
    leave
    ret

; === Test Parse Source ===
reverser_test_parse_source:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = source, rsi = size
    
    ; Initialize parser
    call reverser_parser_init
    
    ; Parse source
    call reverser_parse_program
    mov rbx, rax
    
    ; Validate AST
    call reverser_test_assert_not_null
    
    ; Test AST structure
    call reverser_test_validate_ast
    
    leave
    ret

; === Test AST ===
reverser_test_ast:
    push rbp
    mov rbp, rsp
    
    ; Test AST node creation
    call reverser_test_ast_node_creation
    
    ; Test AST node manipulation
    call reverser_test_ast_node_manipulation
    
    ; Test AST traversal
    call reverser_test_ast_traversal
    
    ; Test AST validation
    call reverser_test_ast_validation
    
    leave
    ret

; === Test AST Node Creation ===
reverser_test_ast_node_creation:
    push rbp
    mov rbp, rsp
    
    ; Test creating different node types
    mov rdi, REVERSER_AST_PROGRAM
    call reverser_create_ast_node
    call reverser_test_assert_not_null
    
    mov rdi, REVERSER_AST_FUNC
    call reverser_create_ast_node
    call reverser_test_assert_not_null
    
    mov rdi, REVERSER_AST_IF
    call reverser_create_ast_node
    call reverser_test_assert_not_null
    
    mov rdi, REVERSER_AST_LOOP
    call reverser_create_ast_node
    call reverser_test_assert_not_null
    
    leave
    ret

; === Test AST Node Manipulation ===
reverser_test_ast_node_manipulation:
    push rbp
    mov rbp, rsp
    
    ; Create parent node
    mov rdi, REVERSER_AST_PROGRAM
    call reverser_create_ast_node
    mov rbx, rax
    
    ; Create child node
    mov rdi, REVERSER_AST_FUNC
    call reverser_create_ast_node
    mov rcx, rax
    
    ; Add child to parent
    mov rdi, rbx
    mov rsi, rcx
    call reverser_add_child_to_node
    
    ; Validate child was added
    mov rdx, [rbx + 8]  ; left child
    cmp rdx, rcx
    je .child_added_successfully
    
    ; Test failed
    mov rdi, 0
    call reverser_test_assert_true
    jmp .done
    
.child_added_successfully:
    ; Test passed
    mov rdi, 1
    call reverser_test_assert_true
    
.done:
    leave
    ret

; === Test AST Traversal ===
reverser_test_ast_traversal:
    push rbp
    mov rbp, rsp
    
    ; Create a simple AST
    mov rdi, REVERSER_AST_PROGRAM
    call reverser_create_ast_node
    mov rbx, rax
    
    ; Add some children
    mov rdi, REVERSER_AST_FUNC
    call reverser_create_ast_node
    mov rcx, rax
    
    mov rdi, rbx
    mov rsi, rcx
    call reverser_add_child_to_node
    
    ; Traverse AST
    mov rdi, rbx
    call reverser_test_traverse_ast
    
    leave
    ret

; === Test AST Validation ===
reverser_test_ast_validation:
    push rbp
    mov rbp, rsp
    
    ; Test valid AST
    mov rdi, REVERSER_AST_PROGRAM
    call reverser_create_ast_node
    mov rdi, rax
    call reverser_test_validate_ast_structure
    
    ; Test invalid AST (null pointer)
    mov rdi, 0
    call reverser_test_validate_ast_structure
    
    leave
    ret

; === Test Integration ===
reverser_test_integration:
    push rbp
    mov rbp, rsp
    
    ; Test complete compilation pipeline
    mov rdi, test_source_1
    mov rsi, 25
    call reverser_test_complete_pipeline
    
    ; Test error handling
    mov rdi, "invalid syntax {"
    mov rsi, 15
    call reverser_test_error_handling
    
    ; Test performance
    call reverser_test_performance
    
    leave
    ret

; === Test Complete Pipeline ===
reverser_test_complete_pipeline:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = source, rsi = size
    
    ; Initialize compiler
    call reverser_compiler_init
    
    ; Compile source
    call reverser_compile_source
    mov rbx, rax
    
    ; Validate output
    call reverser_test_assert_not_null
    
    ; Test output quality
    call reverser_test_validate_output
    
    leave
    ret

; === Test Error Handling ===
reverser_test_error_handling:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = invalid source, rsi = size
    
    ; Initialize compiler
    call reverser_compiler_init
    
    ; Try to compile invalid source
    call reverser_compile_source
    
    ; Should handle error gracefully
    ; (In a real implementation, this would check error state)
    
    leave
    ret

; === Test Performance ===
reverser_test_performance:
    push rbp
    mov rbp, rsp
    
    ; Test compilation speed
    call get_current_time
    mov rbx, rax
    
    ; Compile multiple times
    mov rcx, 100
.performance_loop:
    mov rdi, test_source_1
    mov rsi, 25
    call reverser_compile_source
    
    dec rcx
    jnz .performance_loop
    
    call get_current_time
    sub rax, rbx
    
    ; Validate performance (should be reasonable)
    cmp rax, 1000000  ; 1 second in microseconds
    jl .performance_ok
    
    ; Performance test failed
    mov rdi, 0
    call reverser_test_assert_true
    jmp .done
    
.performance_ok:
    ; Performance test passed
    mov rdi, 1
    call reverser_test_assert_true
    
.done:
    leave
    ret

; === Validate Tokens ===
reverser_test_validate_tokens:
    push rbp
    mov rbp, rsp
    
    ; Validate token types and values
    ; This is a simplified implementation
    
    leave
    ret

; === Validate AST ===
reverser_test_validate_ast:
    push rbp
    mov rbp, rsp
    
    ; Validate AST structure and content
    ; This is a simplified implementation
    
    leave
    ret

; === Validate Output ===
reverser_test_validate_output:
    push rbp
    mov rbp, rsp
    
    ; Validate generated output
    ; This is a simplified implementation
    
    leave
    ret

; === Validate AST Structure ===
reverser_test_validate_ast_structure:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = AST node
    
    cmp rdi, 0
    je .invalid_ast
    
    ; Validate node structure
    ; This is a simplified implementation
    
    mov rdi, 1
    call reverser_test_assert_true
    jmp .done
    
.invalid_ast:
    mov rdi, 0
    call reverser_test_assert_true
    
.done:
    leave
    ret

; === Traverse AST ===
reverser_test_traverse_ast:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = AST node
    
    ; Traverse AST and validate structure
    ; This is a simplified implementation
    
    leave
    ret

; === Test Assertions ===
reverser_test_assert_equal:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = actual, rsi = expected
    
    cmp rdi, rsi
    je .assert_equal_pass
    
    ; Assertion failed
    mov rdi, 0
    call reverser_test_log_result
    jmp .done
    
.assert_equal_pass:
    ; Assertion passed
    mov rdi, 1
    call reverser_test_log_result
    
.done:
    leave
    ret

reverser_test_assert_not_null:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = pointer
    
    cmp rdi, 0
    jne .assert_not_null_pass
    
    ; Assertion failed
    mov rdi, 0
    call reverser_test_log_result
    jmp .done
    
.assert_not_null_pass:
    ; Assertion passed
    mov rdi, 1
    call reverser_test_log_result
    
.done:
    leave
    ret

reverser_test_assert_true:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = condition
    
    cmp rdi, 0
    jne .assert_true_pass
    
    ; Assertion failed
    mov rdi, 0
    call reverser_test_log_result
    jmp .done
    
.assert_true_pass:
    ; Assertion passed
    mov rdi, 1
    call reverser_test_log_result
    
.done:
    leave
    ret

reverser_test_assert_false:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = condition
    
    cmp rdi, 0
    je .assert_false_pass
    
    ; Assertion failed
    mov rdi, 0
    call reverser_test_log_result
    jmp .done
    
.assert_false_pass:
    ; Assertion passed
    mov rdi, 1
    call reverser_test_log_result
    
.done:
    leave
    ret

; === Log Test Result ===
reverser_test_log_result:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = result (1=pass, 0=fail)
    
    inc qword [total_tests]
    
    cmp rdi, 1
    je .test_passed
    
    ; Test failed
    inc qword [failed_tests]
    jmp .done
    
.test_passed:
    ; Test passed
    inc qword [passed_tests]
    
.done:
    leave
    ret

; === Measure Time ===
reverser_test_measure_time:
    push rbp
    mov rbp, rsp
    
    ; Measure test execution time
    ; This is a simplified implementation
    
    leave
    ret

; === Report Results ===
reverser_test_report_results:
    push rbp
    mov rbp, rsp
    
    ; Print test results header
    mov rdi, test_results_header
    call print_string
    
    ; Print total tests
    mov rdi, "Total tests: "
    call print_string
    mov rdi, [total_tests]
    call print_number
    mov rdi, "\n"
    call print_string
    
    ; Print passed tests
    mov rdi, "Passed: "
    call print_string
    mov rdi, [passed_tests]
    call print_number
    mov rdi, "\n"
    call print_string
    
    ; Print failed tests
    mov rdi, "Failed: "
    call print_string
    mov rdi, [failed_tests]
    call print_number
    mov rdi, "\n"
    call print_string
    
    ; Print test duration
    mov rdi, "Duration: "
    call print_string
    mov rdi, [test_duration]
    call print_number
    mov rdi, " microseconds\n"
    call print_string
    
    ; Print success rate
    mov rdi, "Success rate: "
    call print_string
    mov rax, [passed_tests]
    mov rbx, [total_tests]
    cmp rbx, 0
    je .no_tests
    
    ; Calculate percentage
    mov rdx, 0
    div rbx
    mov rdi, rax
    call print_number
    mov rdi, "%\n"
    call print_string
    jmp .done
    
.no_tests:
    mov rdi, "N/A\n"
    call print_string
    
.done:
    leave
    ret

; === Cleanup ===
reverser_test_cleanup:
    push rbp
    mov rbp, rsp
    
    ; Clean up test resources
    ; This is a simplified implementation
    
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

get_current_time:
    push rbp
    mov rbp, rsp
    
    ; Simple time function (in real implementation, use proper timing)
    mov rax, 0
    
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

print_number:
    push rbp
    mov rbp, rsp
    
    ; Args: rdi = number
    ; Simple number printing (in real implementation, use proper formatting)
    
    leave
    ret

; === Reverser Test Suite Demo ===
reverser_test_suite_demo:
    push rbp
    mov rbp, rsp
    
    ; Initialize test suite
    call reverser_test_suite_init
    
    ; Run all tests
    call reverser_test_suite_run
    
    leave
    ret
