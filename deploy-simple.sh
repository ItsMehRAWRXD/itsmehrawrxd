#!/bin/bash

# RawrZ Security Platform - Simple Deployment Script
# This script deploys the application without Docker

echo "🚀 Starting RawrZ Security Platform deployment..."

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js first."
    exit 1
fi

# Check if npm is installed
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed. Please install npm first."
    exit 1
fi

echo "✅ Node.js and npm are available"

# Install dependencies
echo "📦 Installing dependencies..."
npm install --legacy-peer-deps

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo "✅ Dependencies installed successfully"

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p uploads processed logs data keys stubs payloads bots cve engines backups

# Set permissions
chmod -R 755 uploads processed logs data keys stubs payloads bots cve engines backups

echo "✅ Directories created and permissions set"

# Start the application
echo "🚀 Starting RawrZ Security Platform..."
echo "📍 Application will be available at: http://localhost:3000"
echo "📍 API endpoints: http://localhost:3000/api/"
echo "📍 Health check: http://localhost:3000/api/health"
echo ""
echo "Press Ctrl+C to stop the application"

# Start the application
node api-server-no-cli.js