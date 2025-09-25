#!/bin/bash
# Fix for Npm case sensitivity issue
# This script creates symlinks to handle both "npm" and "Npm" commands

echo "🔧 Fixing Npm case sensitivity issue..."

# Get the actual npm path
NPM_PATH=$(which npm)
if [ -z "$NPM_PATH" ]; then
    echo "❌ npm not found in PATH"
    exit 1
fi

echo "📍 Found npm at: $NPM_PATH"

# Create symlinks for common case variations
echo "🔗 Creating symlinks for case variations..."

# Create symlink for "Npm" (capital N)
sudo ln -sf "$NPM_PATH" /usr/local/bin/Npm

# Create symlink for "NPM" (all caps)
sudo ln -sf "$NPM_PATH" /usr/local/bin/NPM

# Create symlink for "nPM" (mixed case)
sudo ln -sf "$NPM_PATH" /usr/local/bin/nPM

echo "✅ Symlinks created successfully!"

# Test the symlinks
echo "🧪 Testing symlinks..."
echo "Testing 'npm': $(npm --version 2>/dev/null || echo 'Failed')"
echo "Testing 'Npm': $(Npm --version 2>/dev/null || echo 'Failed')"
echo "Testing 'NPM': $(NPM --version 2>/dev/null || echo 'Failed')"
echo "Testing 'nPM': $(nPM --version 2>/dev/null || echo 'Failed')"

echo ""
echo "🎉 Npm case sensitivity fix completed!"
echo "Now both 'npm' and 'Npm' commands will work."