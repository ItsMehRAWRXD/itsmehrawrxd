#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Test framework for Eon compiler
typedef struct {
    char *name;
    char *source;
    char *expected_output;
    int should_fail;
} TestCase;

// Test cases
TestCase test_cases[] = {
    {
        "Basic Arithmetic",
        "def main() { let x = 5; let y = 10; let result = x + y; ret result; }",
        "mov rax, 15",
        0
    },
    {
        "Function Call",
        "def add(a, b) { ret a + b; } def main() { let result = add(5, 3); ret result; }",
        "call add",
        0
    },
    {
        "If Statement",
        "def main() { let x = 10; if (x > 5) { ret 1; } else { ret 0; } }",
        "cmp rax, 5",
        0
    },
    {
        "Variable Declaration",
        "def main() { let x = 42; ret x; }",
        "mov rax, 42",
        0
    },
    {
        "Return Statement",
        "def main() { ret 100; }",
        "mov rax, 100",
        0
    },
    {
        "Undefined Variable",
        "def main() { let x = undefined_var; ret x; }",
        NULL,
        1
    },
    {
        "Type Mismatch",
        "def main() { let x = 5; let y = \"hello\"; let result = x + y; ret result; }",
        NULL,
        1
    }
};

int num_tests = sizeof(test_cases) / sizeof(test_cases[0]);

// Test runner
int run_test(TestCase *test) {
    printf("Running test: %s\n", test->name);
    
    // Write test source to temporary file
    FILE *src_file = fopen("test_temp.eon", "w");
    if (!src_file) {
        printf("Error: Cannot create temporary source file\n");
        return 0;
    }
    fprintf(src_file, "%s", test->source);
    fclose(src_file);
    
    // Run the compiler
    char command[256];
    snprintf(command, sizeof(command), "bin\\eon.exe test_temp.eon");
    int result = system(command);
    
    if (test->should_fail) {
        if (result != 0) {
            printf("✓ Test passed (expected failure)\n");
            remove("test_temp.eon");
            return 1;
        } else {
            printf("✗ Test failed (should have failed but didn't)\n");
            remove("test_temp.eon");
            return 0;
        }
    }
    
    if (result != 0) {
        printf("✗ Test failed (compilation error)\n");
        remove("test_temp.eon");
        return 0;
    }
    
    // Check if assembly file was generated
    FILE *asm_file = fopen("output.s", "r");
    if (!asm_file) {
        printf("✗ Test failed (no assembly output)\n");
        remove("test_temp.eon");
        return 0;
    }
    
    // Read assembly content
    char asm_content[4096];
    size_t bytes_read = fread(asm_content, 1, sizeof(asm_content) - 1, asm_file);
    asm_content[bytes_read] = '\0';
    fclose(asm_file);
    
    // Check for expected output
    if (test->expected_output && strstr(asm_content, test->expected_output)) {
        printf("✓ Test passed\n");
        remove("test_temp.eon");
        remove("output.s");
        return 1;
    } else if (test->expected_output) {
        printf("✗ Test failed (expected output not found)\n");
        printf("Expected: %s\n", test->expected_output);
        printf("Generated assembly:\n%s\n", asm_content);
        remove("test_temp.eon");
        remove("output.s");
        return 0;
    } else {
        printf("✓ Test passed (no specific output check)\n");
        remove("test_temp.eon");
        remove("output.s");
        return 1;
    }
}

int main() {
    printf("Eon Compiler Test Suite\n");
    printf("======================\n\n");
    
    int passed = 0;
    int total = num_tests;
    
    for (int i = 0; i < num_tests; i++) {
        if (run_test(&test_cases[i])) {
            passed++;
        }
        printf("\n");
    }
    
    printf("Test Results: %d/%d tests passed\n", passed, total);
    
    if (passed == total) {
        printf("🎉 All tests passed!\n");
        return 0;
    } else {
        printf("❌ Some tests failed\n");
        return 1;
    }
}
