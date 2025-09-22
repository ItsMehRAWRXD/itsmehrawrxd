# EON Compiler

A complete, self-hosted compiler for the EON programming language, written in C and targeting x86-64 assembly.

## Features

- **Complete Language Support**: Variables, functions, structs, pointers, memory allocation
- **Control Flow**: if/else statements, for/while loops
- **Type System**: Built-in types with struct support
- **Memory Management**: Pointer operations and dynamic allocation
- **Optimization**: Basic optimizations and dead code elimination
- **Error Handling**: Comprehensive error reporting and recovery

## Language Syntax

### Variables and Types
```eon
let x = 5;           // Integer variable
let y = x + 10;      // Expression assignment
```

### Functions
```eon
def add(a, b) {
    ret a + b;
}

def main() {
    let result = add(5, 3);
    ret result;
}
```

### Control Flow
```eon
def factorial(n) {
    if (n > 1) {
        ret n * factorial(n - 1);
    } else {
        ret 1;
    }
}
```

### Loops
```eon
def sum_array(arr, len) {
    let sum = 0;
    for (let i = 0; i < len; i = i + 1) {
        sum = sum + arr[i];
    }
    ret sum;
}
```

### Structs
```eon
struct Point {
    x: int;
    y: int;
}

def main() {
    let p = Point { x: 5, y: 10 };
    ret p.x + p.y;
}
```

### Pointers and Memory
```eon
def allocate_int(value) {
    let ptr = alloc(8);  // Allocate 8 bytes
    *ptr = value;        // Dereference and assign
    ret ptr;
}
```

## Building

### Prerequisites
- GCC compiler
- NASM assembler
- Make

### Compilation
```bash
# Build the compiler
make

# Run tests
make test

# Run example
make example
```

### Manual Build
```bash
# Create directories
mkdir -p obj bin

# Compile source files
gcc -Wall -Wextra -std=c99 -g -Iinclude -c src/lexer.c -o obj/lexer.o
gcc -Wall -Wextra -std=c99 -g -Iinclude -c src/parser.c -o obj/parser.o
gcc -Wall -Wextra -std=c99 -g -Iinclude -c src/symtab.c -o obj/symtab.o
gcc -Wall -Wextra -std=c99 -g -Iinclude -c src/codegen.c -o obj/codegen.o
gcc -Wall -Wextra -std=c99 -g -Iinclude -c src/main.c -o obj/main.o

# Link the compiler
gcc obj/*.o -o bin/eon
```

## Usage

### Compile EON Code
```bash
# Compile EON source to assembly
./bin/eon examples/hello.eon

# Assemble and link
nasm -f elf64 out.asm
gcc out.o -o hello
./hello
```

### Example Workflow
```bash
# 1. Write EON code
echo "def main() { let x = 5; ret x; }" > test.eon

# 2. Compile to assembly
./bin/eon test.eon

# 3. Assemble to object file
nasm -f elf64 out.asm

# 4. Link to executable
gcc out.o -o test

# 5. Run the program
./test
echo $?  # Should print 5
```

## Project Structure

```
eon_compiler/
├── include/
│   └── compiler.h          # Main header file
├── src/
│   ├── lexer.c             # Tokenizer implementation
│   ├── parser.c            # Parser implementation
│   ├── symtab.c            # Symbol table management
│   ├── codegen.c           # Code generator
│   └── main.c              # Main entry point
├── examples/
│   ├── hello.eon           # Hello world example
│   ├── fibonacci.eon       # Fibonacci example
│   └── structs.eon         # Struct example
├── Makefile                # Build configuration
└── README.md               # This file
```

## Architecture

### Lexer (lexer.c)
- Tokenizes source code into tokens
- Handles keywords, identifiers, numbers, operators
- Supports comments and whitespace

### Parser (parser.c)
- Recursive descent parser
- Builds Abstract Syntax Tree (AST)
- Handles operator precedence and associativity

### Symbol Table (symtab.c)
- Manages variable and function declarations
- Supports nested scopes
- Type checking and validation

### Code Generator (codegen.c)
- Generates x86-64 assembly code
- Handles function calls and returns
- Manages stack frames and local variables

## Language Features

### Data Types
- **int**: 64-bit integers
- **void**: No return value
- **struct**: User-defined composite types
- **pointers**: Memory addresses

### Operators
- **Arithmetic**: +, -, *, /
- **Comparison**: >, <, ==, !=
- **Assignment**: =
- **Address**: &, *

### Control Structures
- **Conditionals**: if/else
- **Loops**: for, while
- **Functions**: def/ret
- **Blocks**: { }

### Memory Management
- **Stack allocation**: Local variables
- **Heap allocation**: alloc() function
- **Pointer operations**: Dereference, address-of

## Error Handling

The compiler provides comprehensive error reporting:
- **Lexical errors**: Invalid tokens, unterminated strings
- **Syntax errors**: Missing semicolons, mismatched braces
- **Semantic errors**: Undefined variables, type mismatches
- **Code generation errors**: Invalid assembly generation

## Optimization

Basic optimizations implemented:
- **Constant folding**: Evaluate constant expressions
- **Dead code elimination**: Remove unreachable code
- **Register allocation**: Efficient use of CPU registers
- **Stack optimization**: Minimize stack usage

## Testing

Run the test suite:
```bash
make test
```

The test suite includes:
- Basic arithmetic operations
- Function calls and returns
- Control flow statements
- Struct operations
- Pointer operations

## Examples

### Hello World
```eon
def main() {
    let message = "Hello, World!";
    ret 0;
}
```

### Fibonacci Sequence
```eon
def fibonacci(n) {
    if (n <= 1) {
        ret n;
    } else {
        ret fibonacci(n - 1) + fibonacci(n - 2);
    }
}
```

### Struct Usage
```eon
struct Rectangle {
    width: int;
    height: int;
}

def area(rect) {
    ret rect.width * rect.height;
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Ensure all tests pass
5. Submit a pull request

## License

This project is open source and available under the MIT License.

## Future Enhancements

- **Additional data types**: float, string, array
- **Advanced optimizations**: Inlining, loop unrolling
- **Standard library**: Built-in functions
- **Debug information**: Source-level debugging
- **Cross-compilation**: Target different architectures
