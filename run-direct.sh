#!/bin/bash
# DIRECT RUN - No Docker, just Node.js
echo "🚀 Starting RawrZ Platform (Direct Node.js)..."

# Install missing dependencies
npm install form-data

# Set environment variables
export NODE_ENV=production
export PORT=8080
export MAX_FILE_SIZE=500MB
export NODE_OPTIONS="--max-old-space-size=768"

# Create required directories
mkdir -p uploads downloads generated-stubs

# Start the application
node server.js

echo "✅ RawrZ Platform is running at http://localhost:8080"
