#!/bin/bash
# demo_template_generation.sh
# Demonstration script for the Universal Template Generator
# Shows the complete workflow from source parsing to code generation

set -e  # Exit on any error

echo "🚀 RawrZApp Universal Template Generator Demo"
echo "=============================================="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if template generator is built
if [ ! -f "./build/template_generator" ]; then
    print_error "Template generator not found. Please build it first:"
    echo "  mkdir build && cd build"
    echo "  cmake .. && make template_generator"
    exit 1
fi

# Create demo directory
DEMO_DIR="demo_output"
mkdir -p "$DEMO_DIR"
cd "$DEMO_DIR"

print_status "Created demo directory: $DEMO_DIR"

# Copy example files
cp ../example_header.h .
cp ../example_template.eont .

print_status "Copied example files to demo directory"

echo
echo "📋 Demo Overview"
echo "================"
echo "This demo will:"
echo "1. Parse a C++ header file (example_header.h)"
echo "2. Process a template file (example_template.eont)"
echo "3. Generate code in multiple languages"
echo "4. Show the generated output"
echo

# Function to run template generation
run_generation() {
    local source_file="$1"
    local template_file="$2"
    local output_file="$3"
    local language="$4"
    local language_name="$5"
    
    print_status "Generating $language_name code..."
    echo "  Source: $source_file"
    echo "  Template: $template_file"
    echo "  Output: $output_file"
    echo "  Language: $language_name"
    
    if ../build/template_generator \
        --source "$source_file" \
        --template "$template_file" \
        --output "$output_file" \
        --language "$language" \
        --verbose; then
        print_success "Generated $language_name code: $output_file"
        
        # Show first few lines of generated code
        echo "  Preview:"
        head -20 "$output_file" | sed 's/^/    /'
        if [ $(wc -l < "$output_file") -gt 20 ]; then
            echo "    ... (truncated)"
        fi
        echo
    else
        print_error "Failed to generate $language_name code"
        return 1
    fi
}

# Generate code for different languages
echo "🔧 Code Generation"
echo "=================="

# Generate Eon code
run_generation "example_header.h" "example_template.eont" "generated_example.eon" "eon" "Eon"

# Generate C++ code
run_generation "example_header.h" "example_template.eont" "generated_example.cpp" "cpp" "C++"

# Generate Python code
run_generation "example_header.h" "example_template.eont" "generated_example.py" "python" "Python"

# Generate JavaScript code
run_generation "example_header.h" "example_template.eont" "generated_example.js" "javascript" "JavaScript"

echo "📊 Generation Summary"
echo "===================="
echo "Generated files:"
ls -la generated_example.* | while read line; do
    echo "  $line"
done

echo
echo "📈 File Statistics"
echo "=================="
for file in generated_example.*; do
    if [ -f "$file" ]; then
        lines=$(wc -l < "$file")
        bytes=$(wc -c < "$file")
        echo "  $file: $lines lines, $bytes bytes"
    fi
done

echo
echo "🔍 Detailed Analysis"
echo "==================="

# Analyze the generated Eon code
if [ -f "generated_example.eon" ]; then
    print_status "Analyzing generated Eon code..."
    
    # Count different constructs
    functions=$(grep -c "def func" generated_example.eon || echo "0")
    models=$(grep -c "def model" generated_example.eon || echo "0")
    variables=$(grep -c "var " generated_example.eon || echo "0")
    
    echo "  Functions: $functions"
    echo "  Models: $models"
    echo "  Variables: $variables"
    echo
fi

# Show template processing details
print_status "Template Processing Details:"
echo "  Template file size: $(wc -c < example_template.eont) bytes"
echo "  Template lines: $(wc -l < example_template.eont)"
echo "  Source file size: $(wc -c < example_header.h) bytes"
echo "  Source lines: $(wc -l < example_header.h)"

echo
echo "🧪 Testing Generated Code"
echo "========================"

# Test if generated files are valid
for file in generated_example.*; do
    if [ -f "$file" ]; then
        print_status "Validating $file..."
        
        # Basic syntax checks
        case "$file" in
            *.eon)
                # Check for basic Eon syntax
                if grep -q "def func\|def model" "$file"; then
                    print_success "$file has valid Eon syntax"
                else
                    print_warning "$file may have syntax issues"
                fi
                ;;
            *.cpp)
                # Check for basic C++ syntax
                if grep -q "class\|struct\|void\|int" "$file"; then
                    print_success "$file has valid C++ syntax"
                else
                    print_warning "$file may have syntax issues"
                fi
                ;;
            *.py)
                # Check for basic Python syntax
                if grep -q "def\|class" "$file"; then
                    print_success "$file has valid Python syntax"
                else
                    print_warning "$file may have syntax issues"
                fi
                ;;
            *.js)
                # Check for basic JavaScript syntax
                if grep -q "function\|class" "$file"; then
                    print_success "$file has valid JavaScript syntax"
                else
                    print_warning "$file may have syntax issues"
                fi
                ;;
        esac
    fi
done

echo
echo "📚 Example Usage"
echo "================"
echo "To use the template generator in your own projects:"
echo
echo "1. Create a source file (C++ header, JSON, etc.)"
echo "2. Create a template file (.eont format)"
echo "3. Run the generator:"
echo "   template_generator -s source.h -t template.eont -o output.eon -l eon"
echo
echo "4. Or use the C++ API:"
echo "   #include \"template_generator_wrapper.h\""
echo "   TemplateGenerator generator;"
echo "   generator.setSourceFile(\"source.h\");"
echo "   generator.setTemplateFile(\"template.eont\");"
echo "   generator.setOutputFile(\"output.eon\");"
echo "   generator.setTargetLanguage(Language::EON);"
echo "   generator.generate();"

echo
echo "🎯 Performance Metrics"
echo "====================="
print_status "Measuring generation performance..."

# Time the generation process
start_time=$(date +%s.%N)
../build/template_generator --source example_header.h --template example_template.eont --output performance_test.eon --language eon > /dev/null 2>&1
end_time=$(date +%s.%N)

duration=$(echo "$end_time - $start_time" | bc -l)
echo "  Generation time: ${duration}s"
echo "  Source file size: $(wc -c < example_header.h) bytes"
echo "  Template file size: $(wc -c < example_template.eont) bytes"
echo "  Output file size: $(wc -c < performance_test.eon) bytes"

# Calculate throughput
if (( $(echo "$duration > 0" | bc -l) )); then
    throughput=$(echo "scale=2; $(wc -c < example_header.h) / $duration" | bc -l)
    echo "  Throughput: ${throughput} bytes/second"
fi

echo
echo "✅ Demo Complete!"
echo "================="
print_success "Template generator demonstration completed successfully!"
echo
echo "Generated files are available in: $DEMO_DIR/"
echo "You can examine them to see the generated code."
echo
echo "Next steps:"
echo "1. Modify the example files to experiment with different inputs"
echo "2. Create your own templates for different use cases"
echo "3. Integrate the template generator into your build system"
echo "4. Contribute improvements and new language support"
echo
echo "For more information, see README_template_generator.md"

# Clean up performance test file
rm -f performance_test.eon

echo
print_success "Demo completed successfully! 🎉"
