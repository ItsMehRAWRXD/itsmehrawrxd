#!/bin/bash

# Fix for "Npm start" capitalization issue
# This script creates a symbolic link from "Npm" to "npm" to resolve container startup issues

set -e

echo "🔧 Fixing npm capitalization issue..."

# Check if npm exists
if ! command -v npm &> /dev/null; then
    echo "❌ Error: npm is not installed or not in PATH"
    exit 1
fi

# Get npm location
NPM_PATH=$(which npm)
echo "✅ Found npm at: $NPM_PATH"

# Create symbolic link for capitalized Npm
if [ ! -f "/usr/local/bin/Npm" ]; then
    echo "🔗 Creating symbolic link /usr/local/bin/Npm -> $NPM_PATH"
    sudo ln -sf "$NPM_PATH" /usr/local/bin/Npm
    echo "✅ Symbolic link created successfully"
else
    echo "✅ Symbolic link already exists"
fi

# Add to /usr/bin as well for broader compatibility
if [ ! -f "/usr/bin/Npm" ]; then
    echo "🔗 Creating symbolic link /usr/bin/Npm -> $NPM_PATH"
    sudo ln -sf "$NPM_PATH" /usr/bin/Npm
    echo "✅ System-wide symbolic link created"
else
    echo "✅ System-wide symbolic link already exists"
fi

# Create bash alias for current user
if ! grep -q "alias Npm=npm" ~/.bashrc 2>/dev/null; then
    echo "📝 Adding Npm alias to ~/.bashrc"
    echo 'alias Npm=npm' >> ~/.bashrc
    echo "✅ Bash alias added"
else
    echo "✅ Bash alias already exists"
fi

# Test the fix
echo "🧪 Testing the fix..."
if Npm --version &> /dev/null; then
    echo "✅ Success! 'Npm --version' works: $(Npm --version)"
    echo "✅ 'Npm start' should now work correctly"
else
    echo "❌ Error: Npm command still not working"
    exit 1
fi

echo ""
echo "🎉 Fix completed successfully!"
echo "💡 The 'Npm start' command should now work in container environments."
echo ""
echo "To verify the fix:"
echo "  Npm --version"
echo "  Npm start"
echo ""