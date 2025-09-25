#!/bin/bash

# RawrZ Security Platform - Startup Script
# This script ensures proper environment setup and starts the application

echo "🚀 Starting RawrZ Security Platform..."

# Check if we're in a container environment
if [ -f /.dockerenv ] || [ -n "$CONTAINER" ]; then
    echo "📦 Container environment detected"
    
    # Ensure npm is available
    if ! command -v npm &> /dev/null; then
        echo "❌ npm not found, installing Node.js..."
        curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
        apt-get install -y nodejs
    fi
fi

# Check if Node.js is available
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not available"
    exit 1
fi

# Check if npm is available
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not available"
    exit 1
fi

echo "✅ Node.js and npm are available"

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm install --legacy-peer-deps
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p uploads processed logs data keys stubs payloads bots cve engines backups

# Set proper permissions
chmod -R 755 uploads processed logs data keys stubs payloads bots cve engines backups

echo "✅ Environment setup complete"

# Start the application
echo "🚀 Starting RawrZ Security Platform..."
echo "📍 Application will be available at: http://localhost:3000"
echo "📍 API endpoints: http://localhost:3000/api/"
echo "📍 Health check: http://localhost:3000/api/health"

# Use the correct start command
exec node api-server-no-cli.js