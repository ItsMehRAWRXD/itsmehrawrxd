#!/bin/bash
# RawrZ Security Platform - Startup Script
# This script properly starts the Node.js application

set -e

echo "Starting RawrZ Security Platform..."

# Check if we're in the right directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

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

# Create necessary directories if they don't exist
echo "Creating necessary directories..."
mkdir -p uploads downloads temp logs data keys stubs payloads bots cve engines backups processed

# Set proper permissions
echo "Setting permissions..."
chmod -R 755 .

# Start the application
echo "Starting application..."
exec node api-server-no-cli.js