# Java Eon Compiler Documentation

## Overview

The Java Eon Compiler is a comprehensive implementation of the Eon programming language compiler written in Java. It provides a complete toolchain for compiling Eon source code to assembly language, with support for advanced features including memory management, concurrency, and multiple backend targets.

## Features

### Core Language Features
- **Variables and Constants**: `let` and `const` declarations
- **Functions**: Function definitions with parameters and return types
- **Control Flow**: `if/else`, `while`, `for` loops
- **Data Types**: Primitive types (int, float, bool, char) and complex types
- **Operators**: Arithmetic, logical, bitwise, and comparison operators
- **Memory Management**: Manual memory allocation with `alloc` and `free`
- **Pointers**: Pointer arithmetic and dereferencing
- **Structs**: User-defined data structures
- **Error Handling**: `try/catch/finally` blocks

### Advanced Features
- **Concurrency**: `spawn` for creating threads, mutex support
- **Generics**: Generic types and functions
- **Modules**: Import/export system
- **Pattern Matching**: `match` expressions with `case` statements
- **Standard Library**: Built-in functions for math, strings, and memory

### Compiler Features
- **Multiple Backends**: X86-64, ARM64, LLVM, C, JavaScript
- **Optimizations**: Dead code elimination, constant folding, variable inlining
- **Error Reporting**: Detailed error messages with suggestions
- **IDE Support**: Syntax highlighting and code completion
- **Performance**: Optimized parsing and code generation

## Architecture

### Components

1. **Lexer**: Tokenizes source code into tokens
2. **Parser**: Builds Abstract Syntax Tree (AST) from tokens
3. **Semantic Analyzer**: Performs type checking and symbol resolution
4. **Optimizer**: Applies various optimizations to the AST
5. **Code Generator**: Generates target code from optimized AST
6. **Error Handler**: Provides detailed error reporting

### Class Structure

```
EonCompilerEnhanced
├── Token (enum and class)
├── AstNode (AST representation)
├── Symbol (symbol table entry)
├── Scope (scope management)
└── Main compilation methods

EonCompilerEnhancements
├── CompilerError (error reporting)
├── TypeInfo (type system)
├── OptimizationEngine (optimizations)
├── MultiBackendCodeGenerator (code generation)
├── StandardLibrary (built-in functions)
└── IDESupport (IDE features)
```

## Usage

### Basic Compilation

```java
// Create compiler instance
String sourceCode = "let x = 42;";
EonCompilerEnhanced compiler = new EonCompilerEnhanced(sourceCode);

// Compile to assembly
String assemblyCode = compiler.compile();

// Write to file
Files.write(Paths.get("output.asm"), assemblyCode.getBytes());
```

### Command Line Usage

```bash
# Compile Java compiler
javac EonCompilerEnhanced.java

# Run compiler
java EonCompilerEnhanced input.eon

# Output will be written to out.asm
```

### Advanced Usage

```java
// Use enhanced features
EonCompilerEnhancements.MultiBackendCodeGenerator generator = 
    new EonCompilerEnhancements.MultiBackendCodeGenerator();

// Generate for different backends
String x86Code = generator.generateCode(ast, BackendType.X86_64);
String llvmCode = generator.generateCode(ast, BackendType.LLVM);
String cCode = generator.generateCode(ast, BackendType.C);
```

## Language Syntax

### Variable Declarations

```eon
let x = 42;                    // Mutable variable
const PI = 3.14159;           // Immutable constant
let ptr: *int = alloc(4);     // Pointer with type annotation
```

### Function Definitions

```eon
def func add(a: int, b: int) -> int {
    return a + b;
}

def func factorial(n: int) -> int {
    if (n <= 1) {
        return 1;
    }
    return n * factorial(n - 1);
}
```

### Control Flow

```eon
// If statement
if (x > 0) {
    let y = 1;
} else {
    let y = -1;
}

// While loop
while (x > 0) {
    x = x - 1;
}

// For loop
for (let i = 0; i < 10; i = i + 1) {
    print(i);
}
```

### Memory Management

```eon
// Allocate memory
let buffer = alloc(100);
let array = alloc(10 * sizeof(int));

// Free memory
free(buffer);
free(array);

// Pointer operations
let ptr = &x;        // Address of
let value = *ptr;    // Dereference
```

### Structs

```eon
struct Point {
    x: int;
    y: int;
}

let p: Point;
p.x = 10;
p.y = 20;
```

### Concurrency

```eon
// Spawn a thread
spawn {
    let x = 42;
    print(x);
}

// Mutex operations
let mutex = mutex();
lock(mutex);
// Critical section
unlock(mutex);
```

### Error Handling

```eon
try {
    let result = divide(a, b);
} catch (DivisionByZero) {
    print("Division by zero error");
} finally {
    cleanup();
}
```

### Pattern Matching

```eon
match (value) {
    case 0 => print("Zero");
    case 1 => print("One");
    default => print("Other");
}
```

## Standard Library

### Math Functions
- `sin(x: float) -> float`
- `cos(x: float) -> float`
- `sqrt(x: float) -> float`
- `pow(x: float, y: float) -> float`

### String Functions
- `strlen(s: *char) -> int`
- `strcpy(dest: *char, src: *char) -> *char`
- `strcat(dest: *char, src: *char) -> *char`

### Memory Functions
- `malloc(size: int) -> *void`
- `free(ptr: *void) -> void`
- `memset(ptr: *void, value: int, size: int) -> *void`

## Optimization Features

### Dead Code Elimination
Removes unreachable code and unused variables.

### Constant Folding
Evaluates constant expressions at compile time.

### Variable Inlining
Replaces variable references with their values when beneficial.

### Loop Optimization
Optimizes loop structures for better performance.

## Error Reporting

The compiler provides detailed error messages with:
- Error type (syntax, semantic, type, runtime)
- Line and column information
- Helpful suggestions
- Context information

Example error message:
```
SEMANTIC_ERROR at line 5, column 10: Undefined variable 'x'
Suggestion: Declare the variable with 'let x = value;' or check spelling
```

## IDE Support

### Syntax Highlighting
- Keywords highlighted in blue
- Operators highlighted in red
- Strings and numbers in different colors

### Code Completion
- Keyword completion
- Function signature completion
- Variable name completion

### Error Highlighting
- Real-time error detection
- Inline error messages
- Quick fix suggestions

## Performance

### Compilation Speed
- Small programs (< 100 lines): < 100ms
- Medium programs (100-1000 lines): < 1s
- Large programs (> 1000 lines): < 5s

### Memory Usage
- Typical memory usage: < 50MB
- Peak memory usage: < 100MB
- Garbage collection optimized

### Generated Code Quality
- Optimized assembly output
- Efficient register usage
- Minimal instruction count

## Testing

The compiler includes a comprehensive test suite:

```bash
# Run all tests
javac EonCompilerTestSuite.java
java EonCompilerTestSuite

# Test categories:
# - Basic functionality tests
# - Advanced feature tests
# - Error handling tests
# - Performance tests
# - Integration tests
```

## Building and Installation

### Prerequisites
- Java 8 or higher
- NASM (for assembly output)
- GCC (for linking)

### Build Steps

```bash
# Compile the compiler
javac EonCompilerEnhanced.java
javac EonCompilerEnhancements.java
javac EonCompilerTestSuite.java

# Run tests
java EonCompilerTestSuite

# Compile a sample program
echo "let x = 42;" > sample.eon
java EonCompilerEnhanced sample.eon

# Assemble and link
nasm -f elf64 out.asm
gcc out.o -o sample
./sample
```

## Contributing

### Development Setup
1. Clone the repository
2. Set up Java development environment
3. Run the test suite
4. Make changes and test thoroughly

### Code Style
- Follow Java naming conventions
- Add comprehensive comments
- Write unit tests for new features
- Update documentation

### Testing
- All new features must have tests
- Maintain 100% test coverage
- Performance tests for optimizations
- Integration tests for new backends

## License

This project is licensed under the MIT License. See LICENSE file for details.

## Support

For questions, issues, or contributions:
- Create an issue on GitHub
- Join the discussion forum
- Check the documentation wiki
- Contact the maintainers

## Changelog

### Version 2.0
- Added multiple backend support
- Implemented advanced optimizations
- Enhanced error reporting
- Added IDE support features
- Comprehensive test suite

### Version 1.0
- Basic language features
- Single backend (x86-64)
- Simple error reporting
- Basic test coverage
