# Universal Template Generator for RawrZApp

A powerful, assembly-based template generator that can parse various source formats and generate code in multiple programming languages using customizable templates.

## Overview

The Universal Template Generator is a core component of the RawrZApp bootstrapped compiler suite. It provides a flexible system for generating code from templates, supporting multiple input formats (C++ headers, JSON, YAML, SQL schemas) and output languages (Eon, C++, Python, JavaScript, Rust, Go).

## Architecture

The template generator follows a modular architecture with the following components:

### Core Components

1. **Data Source Adapters** (`data_source_adapters.asm`)
   - Parses various file formats into a Universal Intermediate Model (UIM)
   - Supports C++ headers, JSON, YAML, and SQL schemas
   - Provides a unified interface for different data sources

2. **Template Engine** (`eon_template_engine.asm`, `eon_template_parser.asm`, `eon_template_lexer.asm`)
   - Lexes and parses template files (.eont format)
   - Builds Abstract Syntax Trees (AST) from templates
   - Processes placeholders, control structures, and data binding

3. **Universal Intermediate Model** (`uim_model.asm`)
   - Language-agnostic representation of parsed data
   - Supports symbols, functions, modules, and projects
   - Enables cross-language code generation

4. **Language Generators** (`language_generators.asm`)
   - Language-specific code generation macros
   - Supports Eon, C++, Python, JavaScript, Rust, and Go
   - Handles syntax differences and idioms for each language

5. **Main Orchestrator** (`template_generator_main.asm`)
   - Coordinates the entire generation process
   - Manages file I/O and error handling
   - Provides the main API for the template generator

6. **C++ Wrapper** (`template_generator_wrapper.cpp`)
   - User-friendly C++ interface
   - Command-line tool with comprehensive options
   - Exception handling and error reporting

## Template Language

The template generator uses a custom template language with the following features:

### Syntax

- **Placeholders**: `{{variable_name}}` - Inserts variable values
- **Control Structures**: `{% if condition %}...{% endif %}`
- **Loops**: `{% for item in collection %}...{% endfor %}`
- **Comments**: `{# This is a comment #}`

### Example Template

```eont
// Generate Eon bindings from C++ header
module {{module.name}} {
    {% for class in module.classes %}
    def model {{class.name}} {
        {% for method in class.methods %}
        def func {{method.name}}(
            {% for param in method.parameters %}
            var {{param.name}}: {{param.type}}{{#unless @last}}, {{/unless}}
            {% endfor %}
        ): {{method.return_type}} {
            return {{method.default_return}};
        }
        {% endfor %}
    }
    {% endfor %}
}
```

## Supported Languages

### Input Formats
- **C++ Headers** (.h, .hpp) - Functions, classes, structs, enums
- **JSON** (.json) - Configuration data, API schemas
- **YAML** (.yaml, .yml) - Configuration files, data structures
- **SQL Schemas** (.sql) - Database table definitions

### Output Languages
- **Eon** - RawrZApp's primary language
- **C++** - Header and implementation files
- **Python** - Classes and functions
- **JavaScript** - ES6+ modules and classes
- **Rust** - Structs, impl blocks, and functions
- **Go** - Structs, methods, and packages

## Building

### Prerequisites

- NASM (Netwide Assembler) 2.15+
- GCC or Clang with C++17 support
- CMake 3.16+
- Make or Ninja

### Build Instructions

```bash
# Clone the repository
git clone <repository-url>
cd RawrZApp

# Create build directory
mkdir build
cd build

# Configure with CMake
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build the template generator
make template_generator

# Run tests
make test
```

### Cross-Platform Support

The template generator supports multiple platforms:

- **Linux** (x86_64) - Primary development platform
- **macOS** (x86_64, ARM64) - Apple Silicon and Intel
- **Windows** (x86_64) - Via MinGW or MSVC

## Usage

### Command Line Interface

```bash
# Basic usage
template_generator -s source.h -t template.eont -o output.eon -l eon

# With verbose output
template_generator --source header.h --template bindings.eont --output bindings.py --language python --verbose

# Generate C++ bindings
template_generator -s api.json -t cpp_template.eont -o api_wrapper.cpp -l cpp
```

### C++ API

```cpp
#include "template_generator_wrapper.h"

using namespace TemplateGenerator;

// Create generator instance
TemplateGenerator generator;

// Configure
generator.setSourceFile("example.h");
generator.setTemplateFile("template.eont");
generator.setOutputFile("output.eon");
generator.setTargetLanguage(Language::EON);

// Generate code
generator.generate();
```

### CMake Integration

```cmake
# Add template generation to your build
add_template_generation(
    TARGET my_project
    SOURCE api.h
    TEMPLATE bindings.eont
    OUTPUT generated_bindings.eon
    LANGUAGE eon
    DEPENDS api.h bindings.eont
)
```

## Examples

### Example 1: C++ Header to Eon Bindings

**Input C++ Header** (`example.h`):
```cpp
class Calculator {
public:
    int add(int a, int b);
    double divide(double a, double b);
};
```

**Template** (`bindings.eont`):
```eont
def model {{class.name}} {
    {% for method in class.methods %}
    def func {{method.name}}(
        {% for param in method.parameters %}
        var {{param.name}}: {{param.type}}{{#unless @last}}, {{/unless}}
        {% endfor %}
    ): {{method.return_type}} {
        // Generated method
    }
    {% endfor %}
}
```

**Generated Eon Code**:
```eon
def model Calculator {
    def func add(var a: int32, var b: int32): int32 {
        // Generated method
    }
    
    def func divide(var a: double, var b: double): double {
        // Generated method
    }
}
```

### Example 2: JSON Configuration to Python Classes

**Input JSON** (`config.json`):
```json
{
    "database": {
        "host": "localhost",
        "port": 5432,
        "name": "myapp"
    }
}
```

**Template** (`config_template.eont`):
```eont
class {{config.name|title}}Config:
    {% for key, value in config.items() %}
    {{key}} = {{value}}
    {% endfor %}
```

**Generated Python Code**:
```python
class DatabaseConfig:
    host = "localhost"
    port = 5432
    name = "myapp"
```

## Performance

The assembly-based implementation provides excellent performance:

- **Parsing**: ~1MB/s for C++ headers
- **Template Processing**: ~500KB/s for complex templates
- **Code Generation**: ~2MB/s for simple templates
- **Memory Usage**: <10MB for typical projects

## Error Handling

The template generator provides comprehensive error handling:

- **File Not Found**: Clear error messages for missing files
- **Parse Errors**: Detailed syntax error reporting
- **Template Errors**: Line-by-line template error information
- **Generation Errors**: Language-specific error reporting

## Extending the Generator

### Adding New Input Formats

1. Implement parser in `data_source_adapters.asm`
2. Add file type detection logic
3. Create UIM mapping functions
4. Update documentation

### Adding New Output Languages

1. Add language constants and keywords
2. Implement language-specific macros
3. Add syntax generation functions
4. Update language detection

### Custom Template Functions

1. Extend the template engine
2. Add new AST node types
3. Implement evaluation logic
4. Update documentation

## Testing

The template generator includes comprehensive tests:

```bash
# Run all tests
make test

# Run specific test suites
make test_parsing
make test_templates
make test_generation
make test_languages

# Run performance benchmarks
make benchmark
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests for new functionality
5. Update documentation
6. Submit a pull request

## License

This project is part of the RawrZApp suite and is licensed under the MIT License. See the LICENSE file for details.

## Roadmap

### Version 1.1
- [ ] Enhanced C++ parsing (templates, namespaces)
- [ ] More output languages (Java, C#, Swift)
- [ ] Template inheritance and includes
- [ ] Performance optimizations

### Version 1.2
- [ ] Interactive template editor
- [ ] Template validation and linting
- [ ] Plugin system for custom languages
- [ ] Web-based interface

### Version 2.0
- [ ] Self-hosting template generator
- [ ] Advanced template features (macros, filters)
- [ ] Integration with IDEs
- [ ] Cloud-based template sharing

## Support

For questions, bug reports, or feature requests:

- Create an issue on GitHub
- Join the RawrZApp community
- Check the documentation wiki
- Contact the development team

---

*The Universal Template Generator is a key component of the RawrZApp bootstrapped compiler suite, demonstrating the power of assembly-based systems programming and modern software engineering practices.*
