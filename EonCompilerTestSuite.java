/**
 * EonCompilerTestSuite.java - Comprehensive test suite for the Java Eon Compiler
 * Tests all features, optimizations, and edge cases
 */

import java.io.*;
import java.util.*;
import java.nio.file.*;

public class EonCompilerTestSuite {
    
    private static class TestResult {
        public String testName;
        public boolean passed;
        public String errorMessage;
        public long executionTime;
        
        public TestResult(String testName, boolean passed, String errorMessage, long executionTime) {
            this.testName = testName;
            this.passed = passed;
            this.errorMessage = errorMessage;
            this.executionTime = executionTime;
        }
        
        @Override
        public String toString() {
            return String.format("%s: %s (%dms) %s", 
                testName, passed ? "PASS" : "FAIL", executionTime, 
                errorMessage != null ? "- " + errorMessage : "");
        }
    }
    
    private List<TestResult> testResults;
    private int passedTests;
    private int failedTests;
    
    public EonCompilerTestSuite() {
        this.testResults = new ArrayList<>();
        this.passedTests = 0;
        this.failedTests = 0;
    }
    
    public void runAllTests() {
        System.out.println("=== Eon Compiler Test Suite ===");
        System.out.println("Running comprehensive tests...\n");
        
        // Basic functionality tests
        runBasicTests();
        
        // Advanced feature tests
        runAdvancedTests();
        
        // Error handling tests
        runErrorHandlingTests();
        
        // Performance tests
        runPerformanceTests();
        
        // Integration tests
        runIntegrationTests();
        
        // Generate test report
        generateTestReport();
    }
    
    private void runBasicTests() {
        System.out.println("--- Basic Functionality Tests ---");
        
        // Test 1: Simple arithmetic
        runTest("Simple Arithmetic", () -> {
            String source = "let x = 5 + 3;";
            EonCompilerEnhanced compiler = new EonCompilerEnhanced(source);
            String output = compiler.compile();
            return output != null && output.contains("mov");
        });
        
        // Test 2: Variable declaration
        runTest("Variable Declaration", () -> {
            String source = "let y = 42;";
            EonCompilerEnhanced compiler = new EonCompilerEnhanced(source);
            String output = compiler.compile();
            return output != null;
        });
        
        // Test 3: Function definition
        runTest("Function Definition", () -> {
            String source = "def func add(a, b) { return a + b; }";
            EonCompilerEnhanced compiler = new EonCompilerEnhanced(source);
            String output = compiler.compile();
            return output != null && output.contains("add:");
        });
        
        // Test 4: If statement
        runTest("If Statement", () -> {
            String source = "if (x > 0) { let y = 1; }";
            EonCompilerEnhanced compiler = new EonCompilerEnhanced(source);
            String output = compiler.compile();
            return output != null;
        });
        
        // Test 5: While loop
        runTest("While Loop", () -> {
            String source = "while (x > 0) { x = x - 1; }";
            EonCompilerEnhanced compiler = new EonCompilerEnhanced(source);
            String output = compiler.compile();
            return output != null;
        });
    }
    
    private void runAdvancedTests() {
        System.out.println("\n--- Advanced Feature Tests ---");
        
        // Test 1: Memory management
        runTest("Memory Allocation", () -> {
            String source = "let ptr = alloc(100);";
            EonCompilerEnhanced compiler = new EonCompilerEnhanced(source);
            String output = compiler.compile();
            return output != null;
        });
        
        // Test 2: Pointer operations
        runTest("Pointer Operations", () -> {
            String source = "let ptr = &x; let val = *ptr;";
            EonCompilerEnhanced compiler = new EonCompilerEnhanced(source);
            String output = compiler.compile();
            return output != null;
        });
        
        // Test 3: Struct definition
        runTest("Struct Definition", () -> {
            String source = "struct Point { x: int; y: int; }";
            EonCompilerEnhanced compiler = new EonCompilerEnhanced(source);
            String output = compiler.compile();
            return output != null;
        });
        
        // Test 4: Concurrency features
        runTest("Concurrency Features", () -> {
            String source = "spawn { let x = 1; }";
            EonCompilerEnhanced compiler = new EonCompilerEnhanced(source);
            String output = compiler.compile();
            return output != null;
        });
        
        // Test 5: Error handling
        runTest("Error Handling", () -> {
            String source = "try { let x = 1 / 0; } catch { let y = 0; }";
            EonCompilerEnhanced compiler = new EonCompilerEnhanced(source);
            String output = compiler.compile();
            return output != null;
        });
    }
    
    private void runErrorHandlingTests() {
        System.out.println("\n--- Error Handling Tests ---");
        
        // Test 1: Syntax error
        runTest("Syntax Error Handling", () -> {
            String source = "let x = ;"; // Missing value
            try {
                EonCompilerEnhanced compiler = new EonCompilerEnhanced(source);
                String output = compiler.compile();
                return output == null; // Should fail gracefully
            } catch (Exception e) {
                return true; // Expected to throw exception
            }
        });
        
        // Test 2: Undefined variable
        runTest("Undefined Variable", () -> {
            String source = "let y = undefined_var;";
            try {
                EonCompilerEnhanced compiler = new EonCompilerEnhanced(source);
                String output = compiler.compile();
                return output == null; // Should fail gracefully
            } catch (Exception e) {
                return true; // Expected to throw exception
            }
        });
        
        // Test 3: Type mismatch
        runTest("Type Mismatch", () -> {
            String source = "let x = \"string\" + 42;";
            try {
                EonCompilerEnhanced compiler = new EonCompilerEnhanced(source);
                String output = compiler.compile();
                return output == null; // Should fail gracefully
            } catch (Exception e) {
                return true; // Expected to throw exception
            }
        });
    }
    
    private void runPerformanceTests() {
        System.out.println("\n--- Performance Tests ---");
        
        // Test 1: Large program compilation
        runTest("Large Program Compilation", () -> {
            StringBuilder source = new StringBuilder();
            for (int i = 0; i < 1000; i++) {
                source.append("let var").append(i).append(" = ").append(i).append(";\n");
            }
            
            long startTime = System.currentTimeMillis();
            EonCompilerEnhanced compiler = new EonCompilerEnhanced(source.toString());
            String output = compiler.compile();
            long endTime = System.currentTimeMillis();
            
            return output != null && (endTime - startTime) < 5000; // Should complete in under 5 seconds
        });
        
        // Test 2: Complex expression parsing
        runTest("Complex Expression Parsing", () -> {
            String source = "let result = (a + b) * (c - d) / (e + f) % (g - h);";
            long startTime = System.currentTimeMillis();
            EonCompilerEnhanced compiler = new EonCompilerEnhanced(source);
            String output = compiler.compile();
            long endTime = System.currentTimeMillis();
            
            return output != null && (endTime - startTime) < 1000; // Should complete in under 1 second
        });
        
        // Test 3: Memory usage
        runTest("Memory Usage", () -> {
            Runtime runtime = Runtime.getRuntime();
            long beforeMemory = runtime.totalMemory() - runtime.freeMemory();
            
            String source = "let x = 42; let y = 24; let z = x + y;";
            EonCompilerEnhanced compiler = new EonCompilerEnhanced(source);
            String output = compiler.compile();
            
            long afterMemory = runtime.totalMemory() - runtime.freeMemory();
            long memoryUsed = afterMemory - beforeMemory;
            
            return output != null && memoryUsed < 10 * 1024 * 1024; // Should use less than 10MB
        });
    }
    
    private void runIntegrationTests() {
        System.out.println("\n--- Integration Tests ---");
        
        // Test 1: File I/O integration
        runTest("File I/O Integration", () -> {
            try {
                String testSource = "let x = 42;";
                Files.write(Paths.get("test_input.eon"), testSource.getBytes());
                
                EonCompilerEnhanced compiler = new EonCompilerEnhanced(testSource);
                String output = compiler.compile();
                
                if (output != null) {
                    Files.write(Paths.get("test_output.asm"), output.getBytes());
                    return Files.exists(Paths.get("test_output.asm"));
                }
                return false;
            } catch (IOException e) {
                return false;
            }
        });
        
        // Test 2: Multi-backend compilation
        runTest("Multi-Backend Compilation", () -> {
            String source = "let x = 42;";
            EonCompilerEnhanced compiler = new EonCompilerEnhanced(source);
            String output = compiler.compile();
            
            // Test that output contains expected assembly
            return output != null && 
                   output.contains("section .text") && 
                   output.contains("global _start");
        });
        
        // Test 3: Standard library integration
        runTest("Standard Library Integration", () -> {
            String source = "let result = sin(3.14159);";
            EonCompilerEnhanced compiler = new EonCompilerEnhanced(source);
            String output = compiler.compile();
            
            return output != null;
        });
    }
    
    private void runTest(String testName, TestFunction testFunction) {
        long startTime = System.currentTimeMillis();
        boolean passed = false;
        String errorMessage = null;
        
        try {
            passed = testFunction.execute();
        } catch (Exception e) {
            errorMessage = e.getMessage();
            passed = false;
        }
        
        long endTime = System.currentTimeMillis();
        long executionTime = endTime - startTime;
        
        TestResult result = new TestResult(testName, passed, errorMessage, executionTime);
        testResults.add(result);
        
        if (passed) {
            passedTests++;
            System.out.println("✓ " + result);
        } else {
            failedTests++;
            System.out.println("✗ " + result);
        }
    }
    
    private void generateTestReport() {
        System.out.println("\n=== Test Report ===");
        System.out.println("Total Tests: " + (passedTests + failedTests));
        System.out.println("Passed: " + passedTests);
        System.out.println("Failed: " + failedTests);
        System.out.println("Success Rate: " + String.format("%.1f%%", 
            (double) passedTests / (passedTests + failedTests) * 100));
        
        if (failedTests > 0) {
            System.out.println("\nFailed Tests:");
            for (TestResult result : testResults) {
                if (!result.passed) {
                    System.out.println("  - " + result.testName + ": " + result.errorMessage);
                }
            }
        }
        
        System.out.println("\nPerformance Summary:");
        long totalTime = testResults.stream().mapToLong(r -> r.executionTime).sum();
        System.out.println("Total Execution Time: " + totalTime + "ms");
        System.out.println("Average Test Time: " + (totalTime / testResults.size()) + "ms");
        
        // Write detailed report to file
        try {
            StringBuilder report = new StringBuilder();
            report.append("Eon Compiler Test Report\n");
            report.append("=======================\n\n");
            report.append("Generated: ").append(new Date()).append("\n\n");
            
            for (TestResult result : testResults) {
                report.append(result.toString()).append("\n");
            }
            
            Files.write(Paths.get("test_report.txt"), report.toString().getBytes());
            System.out.println("\nDetailed report written to test_report.txt");
        } catch (IOException e) {
            System.err.println("Failed to write test report: " + e.getMessage());
        }
    }
    
    @FunctionalInterface
    private interface TestFunction {
        boolean execute() throws Exception;
    }
    
    public static void main(String[] args) {
        EonCompilerTestSuite testSuite = new EonCompilerTestSuite();
        testSuite.runAllTests();
    }
}
