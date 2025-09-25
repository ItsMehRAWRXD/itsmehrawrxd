#!/bin/bash
# RawrZ Security Platform - Docker Entry Point
# This script ensures proper startup of the Node.js application

set -e

echo "RawrZ Security Platform - Starting application..."

# Ensure we're in the right directory
cd /app

# Check if Node.js is available
if ! command -v node &> /dev/null; then
    echo "ERROR: Node.js not found!"
    exit 1
fi

# Check if the main file exists
if [ ! -f "api-server-no-cli.js" ]; then
    echo "ERROR: api-server-no-cli.js not found!"
    exit 1
fi

# Create necessary directories
echo "Creating necessary directories..."
mkdir -p uploads downloads temp logs data keys stubs payloads bots cve engines backups processed

# Set proper permissions
echo "Setting permissions..."
chmod -R 755 /app

# Start the application
echo "Starting RawrZ Security Platform..."
exec node api-server-no-cli.js