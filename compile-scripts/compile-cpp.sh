#!/bin/bash

# Advanced C++ Compilation Script
# Supports multiple platforms and output formats

set -e

# Configuration
SOURCE_FILE="$1"
OUTPUT_NAME="$2"
OUTPUT_EXT="$3"
PLATFORM="$4"
COMPILER="$5"
OPTIONS="$6"

# Create output directory
mkdir -p /compile/output

# Set compiler based on platform
case "$PLATFORM" in
    "windows"|"windows32")
        if [ "$PLATFORM" = "windows32" ]; then
            CC="i686-w64-mingw32-gcc"
            CXX="i686-w64-mingw32-g++"
        else
            CC="x86_64-w64-mingw32-gcc"
            CXX="x86_64-w64-mingw32-g++"
        fi
        OUTPUT_FILE="/compile/output/${OUTPUT_NAME}${OUTPUT_EXT}"
        ;;
    "linux"|"linux32")
        if [ "$PLATFORM" = "linux32" ]; then
            CC="gcc -m32"
            CXX="g++ -m32"
        else
            CC="gcc"
            CXX="g++"
        fi
        OUTPUT_FILE="/compile/output/${OUTPUT_NAME}${OUTPUT_EXT}"
        ;;
    *)
        CC="gcc"
        CXX="g++"
        OUTPUT_FILE="/compile/output/${OUTPUT_NAME}${OUTPUT_EXT}"
        ;;
esac

# Compilation flags
FLAGS="-std=c++17 -O2 -Wall -Wextra"

# Add platform-specific flags
case "$PLATFORM" in
    "windows"|"windows32")
        FLAGS="$FLAGS -static-libgcc -static-libstdc++"
        ;;
    "linux"|"linux32")
        FLAGS="$FLAGS -static"
        ;;
esac

# Add security flags
FLAGS="$FLAGS -fstack-protector-strong -D_FORTIFY_SOURCE=2"

# Compile the executable
echo "Compiling with $CXX..."
echo "Flags: $FLAGS"
echo "Output: $OUTPUT_FILE"

$CXX $FLAGS -o "$OUTPUT_FILE" "$SOURCE_FILE"

# Check if compilation was successful
if [ $? -eq 0 ]; then
    echo "Compilation successful!"
    
    # Get file size
    SIZE=$(stat -c%s "$OUTPUT_FILE" 2>/dev/null || stat -f%z "$OUTPUT_FILE" 2>/dev/null || echo "0")
    echo "File size: $SIZE bytes"
    
    # UPX packing if requested
    if [[ "$OPTIONS" == *"pack"* ]]; then
        echo "Packing with UPX..."
        upx --best "$OUTPUT_FILE" 2>/dev/null || echo "UPX packing failed, but executable is ready"
    fi
    
    # Set executable permissions
    chmod +x "$OUTPUT_FILE"
    
    echo "Executable created: $OUTPUT_FILE"
    echo "SIZE:$SIZE"
else
    echo "Compilation failed!"
    exit 1
fi