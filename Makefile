# Makefile for Eon Compiler with Semantic Analysis

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g
TARGET = eon_compiler_semantic
TEST_TARGET = semantic_test_suite
TEST_SOURCE = test_semantic.eon

# Default target
all: $(TARGET) $(TEST_TARGET)

# Compile the semantic analyzer
$(TARGET): eon_compiler_semantic.c
	$(CC) $(CFLAGS) -o $(TARGET) eon_compiler_semantic.c

# Compile the test suite
$(TEST_TARGET): semantic_test_suite.c
	$(CC) $(CFLAGS) -o $(TEST_TARGET) semantic_test_suite.c

# Run the test suite
test: $(TEST_TARGET)
	./$(TEST_TARGET)

# Test the semantic analyzer with sample code
test-semantic: $(TARGET)
	./$(TARGET) $(TEST_SOURCE)

# Clean build artifacts
clean:
	rm -f $(TARGET) $(TEST_TARGET) *.o

# Run all tests
test-all: test test-semantic

# Install dependencies (if needed)
install-deps:
	@echo "Installing dependencies..."
	@echo "Make sure you have gcc installed"

# Show help
help:
	@echo "Available targets:"
	@echo "  all          - Build both compiler and test suite"
	@echo "  $(TARGET)     - Build the semantic analyzer"
	@echo "  $(TEST_TARGET) - Build the test suite"
	@echo "  test         - Run the test suite"
	@echo "  test-semantic - Test the semantic analyzer with sample code"
	@echo "  test-all     - Run all tests"
	@echo "  clean        - Remove build artifacts"
	@echo "  install-deps - Install dependencies"
	@echo "  help         - Show this help message"

.PHONY: all test test-semantic test-all clean install-deps help