# RawrZ IDE - Multi-Language Development Environment

## Overview

RawrZ IDE is a web-based integrated development environment that supports compiling and running Assembly (ASM), C, and C++ code directly in your browser. The IDE provides a modern, secure development environment with real-time compilation and execution capabilities.

![RawrZ IDE Interface](https://github.com/user-attachments/assets/7e7728be-0b7b-458c-843e-b312223d74ce)

## Features

### 🚀 Multi-Language Support
- **C Programming**: Full C11 standard support with gcc compiler
- **C++ Programming**: C++17 standard support with g++ compiler  
- **Assembly Language**: GNU Assembler (gas) support via gcc

### 🛠️ IDE Features
- **Syntax-Aware Editor**: Dedicated editing environment for each language
- **Real-Time Compilation**: Instant feedback on compilation errors
- **Code Execution**: Sandboxed execution environment for running compiled programs
- **Template System**: Built-in code templates for quick start (Hello World, Loops, Functions)
- **File Management**: Save/load functionality with proper file extensions
- **Tabbed Interface**: Separate compilation and execution output panels

### 🔒 Security & Sandboxing
- **Sandboxed Execution**: All code execution happens in isolated temporary directories
- **Timeout Protection**: Automatic termination of long-running processes (5-second timeout)
- **Input Validation**: Comprehensive input sanitization and validation
- **Memory Limits**: Compilation and execution memory constraints

## Getting Started

### Prerequisites
- Node.js (v14 or higher)
- GCC compiler suite (`gcc`, `g++`)
- Linux/Unix environment (for assembly support)

### Installation

1. **Install Dependencies**:
   ```bash
   npm install
   ```

2. **Start the IDE Server**:
   ```bash
   npm run start:ide
   ```
   Or directly:
   ```bash
   node ide-server.js
   ```

3. **Access the IDE**:
   Open your browser and navigate to: `http://localhost:4000`

## Usage Guide

### Basic Workflow

1. **Select Language**: Choose C, C++, or Assembly from the dropdown
2. **Write Code**: Use the editor to write your program
3. **Use Templates**: Click template buttons for quick code examples
4. **Compile**: Click "🔨 Compile" to check for syntax errors
5. **Run**: Click "▶️ Compile & Run" to compile and execute your program
6. **View Output**: Check the Compilation and Execution tabs for results

### Language-Specific Examples

#### C Example
```c
#include <stdio.h>

int main() {
    printf("Hello, World!\n");
    return 0;
}
```

#### C++ Example  
```cpp
#include <iostream>

int main() {
    std::cout << "Hello from C++!" << std::endl;
    return 0;
}
```

#### Assembly Example
```asm
.section .data
    msg: .ascii "Hello from Assembly!\n"
    msg_len = . - msg

.section .text
.global _start

_start:
    # write system call
    mov $1, %rax
    mov $1, %rdi
    mov $msg, %rsi
    mov $msg_len, %rdx
    syscall

    # exit system call
    mov $60, %rax
    mov $0, %rdi
    syscall
```

### Keyboard Shortcuts

- **Ctrl+S**: Save current file
- **Ctrl+N**: Create new file
- **Ctrl+Enter**: Compile and run

## API Endpoints

The IDE server exposes several REST endpoints:

### Core Compilation
- `POST /api/compile` - Compile source code only
- `POST /api/compile-and-run` - Compile and execute source code
- `GET /api/languages` - Get supported languages and compilers
- `GET /api/health` - Server health check

### Request Format
```json
{
  "source": "your source code here",
  "language": "c|cpp|assembly",
  "filename": "optional_filename",
  "timeout": 5000
}
```

### Response Format
```json
{
  "success": true,
  "compilation": {
    "success": true,
    "output": "compilation output",
    "compiler": "gcc"
  },
  "execution": {
    "success": true,
    "output": "program output",
    "exitCode": 0
  },
  "language": "C",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

## Screenshots

### IDE Interface
![IDE Main Interface](https://github.com/user-attachments/assets/7e7728be-0b7b-458c-843e-b312223d74ce)

### C++ Compilation & Execution
![C++ Example](https://github.com/user-attachments/assets/3775e1e4-b3e1-434e-bc1e-4e1897bfc31d)

### Assembly Language Support
![Assembly Example](https://github.com/user-attachments/assets/1ca15501-2ae7-4e21-9527-ad8390fcd20a)

## Technical Architecture

### Backend Components
- **Express.js Server**: Web server and API endpoints
- **IDECompiler Class**: Core compilation engine with language-specific handlers
- **Security Layer**: Sandboxed execution with timeout and cleanup mechanisms
- **File Management**: Temporary file handling with automatic cleanup

### Frontend Components  
- **Modern Web UI**: Responsive design with dark theme
- **Real-time Communication**: AJAX-based API communication
- **Status Management**: Live compilation and execution status updates
- **Template System**: Language-specific code templates

### Supported Compilers
- **C**: GCC with C11 standard (`gcc -std=c11 -Wall -Wextra`)
- **C++**: G++ with C++17 standard (`g++ -std=c++17 -Wall -Wextra`)
- **Assembly**: GNU Assembler via GCC (`gcc -nostdlib -static`)

## Security Considerations

### Execution Sandboxing
- All compilation and execution occurs in isolated `/tmp/ide-workspace` directory
- Automatic cleanup of temporary files after each operation
- Process timeout limits prevent infinite loops or hanging processes
- No network access from compiled programs

### Input Validation
- Source code size limits (10MB max)
- Filename sanitization
- Compiler argument validation
- Output size constraints

## Troubleshooting

### Common Issues

**Compilation Errors**:
- Check syntax in the Compilation tab
- Ensure proper language selection
- Verify required headers/includes

**Execution Timeouts**:
- Programs are limited to 5-second execution time
- Optimize code for performance
- Avoid infinite loops

**Assembly Issues**:
- Use GNU Assembler syntax (AT&T syntax)
- Include proper section declarations
- Ensure `_start` label for entry point

### Logs and Debugging
Server logs are available in the console where you started the IDE server. Check for compilation errors, file system issues, or API problems.

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch  
5. Create a Pull Request

## License

MIT License - see LICENSE file for details.

## Support

For issues, bug reports, or feature requests, please create an issue in the GitHub repository.