#!/bin/bash
# DOCKER-IN-DOCKER FIX
echo "🔧 Fixing Docker daemon..."

# Kill all Docker processes
sudo pkill -f dockerd
sudo pkill -f docker

# Remove PID files
sudo rm -f /var/run/docker.pid
sudo rm -f /var/run/docker.sock

# Start Docker daemon with proper permissions
sudo dockerd --host=unix:///var/run/docker.sock --host=tcp://0.0.0.0:2376 --storage-driver=overlay2 --log-level=info > /var/log/docker.log 2>&1 &

# Wait for Docker to start
echo "⏳ Waiting for Docker daemon to start..."
sleep 30

# Test Docker
if sudo docker ps > /dev/null 2>&1; then
    echo "✅ Docker daemon is running!"
    echo "🚀 Starting RawrZ Platform with Docker support..."
    
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
else
    echo "❌ Docker daemon failed to start"
    echo "📋 Docker log:"
    cat /var/log/docker.log | tail -10
    echo ""
    echo "🔄 Trying alternative approach..."
    
    # Fallback: Start without Docker (limited functionality)
    echo "⚠️  Starting without Docker - C++ compilation will be limited"
    npm install form-data
    export NODE_ENV=production
    export PORT=8080
    export MAX_FILE_SIZE=500MB
    export NODE_OPTIONS="--max-old-space-size=768"
    mkdir -p uploads downloads generated-stubs
    node server.js
fi
