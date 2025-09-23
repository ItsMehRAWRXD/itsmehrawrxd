#!/bin/bash

echo "🧪 Testing Assembly Compilation..."

# Test if nasm is available
if ! command -v nasm &> /dev/null; then
    echo "📦 Installing nasm..."
    sudo apt-get update && sudo apt-get install -y nasm
fi

# Test syntax compilation only
echo "🔧 Testing syntax compilation..."
if nasm -f elf64 n0mn0m_meta_engine_fixed.asm -o /tmp/meta_test.o 2>/dev/null; then
    echo "✅ N0MN0M Meta-Engine syntax: VALID"
    rm -f /tmp/meta_test.o
else
    echo "❌ N0MN0M Meta-Engine syntax: NEEDS WORK"
fi

if nasm -f elf64 eon_ide_final_fixed.asm -o /tmp/ide_test.o 2>/dev/null; then
    echo "✅ EON IDE System syntax: VALID"
    rm -f /tmp/ide_test.o
else
    echo "❌ EON IDE System syntax: NEEDS WORK"
fi

echo "🔥 Assembly compilation test complete!"
