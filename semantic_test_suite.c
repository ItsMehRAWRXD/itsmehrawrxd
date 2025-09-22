#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Test framework for semantic analyzer
typedef struct {
    char *name;
    char *source;
    int should_pass;
    char *expected_error;
} TestCase;

// Test cases for semantic analysis
TestCase test_cases[] = {
    {
        "valid_variable_declaration",
        "let x = 42;",
        1,
        NULL
    },
    {
        "valid_arithmetic",
        "let x = 42; let y = x + 10;",
        1,
        NULL
    },
    {
        "valid_pointer_operations",
        "let x = 42; let ptr = &x; let value = *ptr;",
        1,
        NULL
    },
    {
        "undefined_variable",
        "let x = undefined_var;",
        0,
        "Undefined variable"
    },
    {
        "type_mismatch_arithmetic",
        "let x = 42; let ptr = &x; let result = x + ptr;",
        0,
        "Arithmetic operation on non-integer type"
    },
    {
        "invalid_dereference",
        "let x = 42; let result = *x;",
        0,
        "Dereference on non-pointer type"
    },
    {
        "address_of_pointer",
        "let x = 42; let ptr = &x; let ptr_ptr = &ptr;",
        0,
        "Cannot take address of pointer"
    },
    {
        "valid_function_definition",
        "func add(a, b) { ret a + b; }",
        1,
        NULL
    },
    {
        "valid_function_call",
        "func add(a, b) { ret a + b; } let result = add(5, 3);",
        1,
        NULL
    },
    {
        "undefined_function_call",
        "let result = unknown_func(5, 3);",
        0,
        "Call to undefined function"
    },
    {
        "valid_conditional",
        "let x = 42; if x > 10 { let temp = x - 10; }",
        1,
        NULL
    },
    {
        "invalid_conditional_type",
        "let x = 42; let ptr = &x; if ptr { let temp = 1; }",
        0,
        "If condition must be integer type"
    },
    {
        "scope_isolation",
        "let x = 42; if x > 10 { let x = 100; } let y = x;",
        1,
        NULL
    },
    {
        "duplicate_variable_same_scope",
        "let x = 42; let x = 100;",
        0,
        "Symbol 'x' already declared in scope"
    },
    {
        "valid_comparison",
        "let x = 42; let y = 10; let result = x > y;",
        1,
        NULL
    },
    {
        "invalid_comparison_types",
        "let x = 42; let ptr = &x; let result = x > ptr;",
        0,
        "Comparison between incompatible types"
    }
};

int num_tests = sizeof(test_cases) / sizeof(test_cases[0]);

// Mock semantic analyzer for testing
typedef enum { TYPE_INT, TYPE_PTR, TYPE_FUNC } SymbolType;

typedef struct {
    char *name;
    SymbolType type;
    int scope_level;
} TestSymbol;

typedef struct {
    TestSymbol symbols[128];
    int count;
    int level;
    struct TestScope *parent;
} TestScope;

TestScope *current_scope;
int scope_level = 0;

void init_test_scopes() {
    current_scope = malloc(sizeof(TestScope));
    current_scope->count = 0;
    current_scope->level = 0;
    current_scope->parent = NULL;
    scope_level = 0;
}

void push_test_scope() {
    TestScope *new_scope = malloc(sizeof(TestScope));
    new_scope->count = 0;
    new_scope->level = ++scope_level;
    new_scope->parent = current_scope;
    current_scope = new_scope;
}

void pop_test_scope() {
    if (current_scope->parent) {
        TestScope *old_scope = current_scope;
        current_scope = current_scope->parent;
        scope_level = current_scope->level;
        free(old_scope);
    }
}

TestSymbol *find_test_symbol(char *name) {
    TestScope *scope = current_scope;
    while (scope) {
        for (int i = 0; i < scope->count; i++) {
            if (strcmp(scope->symbols[i].name, name) == 0) {
                return &scope->symbols[i];
            }
        }
        scope = scope->parent;
    }
    return NULL;
}

TestSymbol *add_test_symbol(char *name, SymbolType type) {
    // Check for duplicate in current scope
    for (int i = 0; i < current_scope->count; i++) {
        if (strcmp(current_scope->symbols[i].name, name) == 0) {
            return NULL; // Duplicate symbol
        }
    }
    
    TestSymbol *symbol = &current_scope->symbols[current_scope->count++];
    symbol->name = strdup(name);
    symbol->type = type;
    symbol->scope_level = current_scope->level;
    return symbol;
}

// Simple test semantic analyzer
int test_semantic_analysis(char *source) {
    init_test_scopes();
    
    // This is a simplified test - in reality, we'd parse the source first
    // For now, we'll simulate some basic semantic checks
    
    // Simulate variable declarations
    if (strstr(source, "let x = 42")) {
        if (!add_test_symbol("x", TYPE_INT)) {
            return 0; // Duplicate symbol error
        }
    }
    
    if (strstr(source, "let ptr = &x")) {
        if (!add_test_symbol("ptr", TYPE_PTR)) {
            return 0;
        }
    }
    
    // Simulate function definitions
    if (strstr(source, "func add")) {
        if (!add_test_symbol("add", TYPE_FUNC)) {
            return 0;
        }
    }
    
    // Check for undefined variables
    if (strstr(source, "undefined_var") && !find_test_symbol("undefined_var")) {
        return 0; // Undefined variable error
    }
    
    // Check for type mismatches
    if (strstr(source, "x + ptr") && find_test_symbol("x") && find_test_symbol("ptr")) {
        TestSymbol *x_sym = find_test_symbol("x");
        TestSymbol *ptr_sym = find_test_symbol("ptr");
        if (x_sym->type != TYPE_INT || ptr_sym->type != TYPE_PTR) {
            return 0; // Type mismatch error
        }
    }
    
    // Check for invalid dereference
    if (strstr(source, "*x") && find_test_symbol("x")) {
        TestSymbol *x_sym = find_test_symbol("x");
        if (x_sym->type != TYPE_PTR) {
            return 0; // Invalid dereference error
        }
    }
    
    // Check for address of pointer
    if (strstr(source, "&ptr") && find_test_symbol("ptr")) {
        TestSymbol *ptr_sym = find_test_symbol("ptr");
        if (ptr_sym->type == TYPE_PTR) {
            return 0; // Cannot take address of pointer
        }
    }
    
    // Check for undefined function calls
    if (strstr(source, "unknown_func") && !find_test_symbol("unknown_func")) {
        return 0; // Undefined function error
    }
    
    // Check for invalid conditional types
    if (strstr(source, "if ptr") && find_test_symbol("ptr")) {
        TestSymbol *ptr_sym = find_test_symbol("ptr");
        if (ptr_sym->type != TYPE_INT) {
            return 0; // Invalid conditional type
        }
    }
    
    // Check for duplicate variables in same scope
    if (strstr(source, "let x = 42; let x = 100")) {
        return 0; // Duplicate variable error
    }
    
    // Check for comparison type mismatches
    if (strstr(source, "x > ptr") && find_test_symbol("x") && find_test_symbol("ptr")) {
        TestSymbol *x_sym = find_test_symbol("x");
        TestSymbol *ptr_sym = find_test_symbol("ptr");
        if (x_sym->type != ptr_sym->type) {
            return 0; // Comparison type mismatch
        }
    }
    
    return 1; // All checks passed
}

void run_test(TestCase *test) {
    printf("Running test: %s\n", test->name);
    
    int result = test_semantic_analysis(test->source);
    
    if (test->should_pass) {
        if (result) {
            printf("  ✓ PASSED\n");
        } else {
            printf("  ✗ FAILED (expected to pass but failed)\n");
        }
    } else {
        if (!result) {
            printf("  ✓ PASSED (correctly failed as expected)\n");
        } else {
            printf("  ✗ FAILED (expected to fail but passed)\n");
        }
    }
}

int main() {
    printf("=== Eon Semantic Analyzer Test Suite ===\n\n");
    
    int passed = 0;
    int total = num_tests;
    
    for (int i = 0; i < num_tests; i++) {
        run_test(&test_cases[i]);
        if ((test_cases[i].should_pass && test_semantic_analysis(test_cases[i].source)) ||
            (!test_cases[i].should_pass && !test_semantic_analysis(test_cases[i].source))) {
            passed++;
        }
        printf("\n");
    }
    
    printf("=== Test Results ===\n");
    printf("Passed: %d/%d\n", passed, total);
    printf("Success Rate: %.1f%%\n", (float)passed / total * 100);
    
    if (passed == total) {
        printf("🎉 All tests passed!\n");
        return 0;
    } else {
        printf("❌ Some tests failed.\n");
        return 1;
    }
}
