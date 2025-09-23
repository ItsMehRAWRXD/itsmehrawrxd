#!/bin/bash

# RawrZ Security Platform - Local Build Test Script

echo "🧪 RawrZ Security Platform - Local Build Test"
echo "=============================================="

# Check if required files exist
echo "📋 Checking required files..."
if [[ ! -f "Dockerfile" ]]; then
    echo "❌ Dockerfile not found!"
    exit 1
fi

if [[ ! -f "api-server.js" ]]; then
    echo "❌ api-server.js not found!"
    exit 1
fi

if [[ ! -f "package-docker.json" ]]; then
    echo "❌ package-docker.json not found!"
    exit 1
fi

echo "✅ All required files found"

# Build the Docker image
echo "🏗️  Building Docker image..."
docker build -t rawrz-security-platform:test .

if [[ $? -ne 0 ]]; then
    echo "❌ Docker build failed!"
    exit 1
fi

echo "✅ Docker image built successfully"

# Run a quick test
echo "🧪 Testing container..."
docker run -d --name rawrz-test -p 3000:3000 rawrz-security-platform:test

# Wait for startup
echo "⏳ Waiting for server to start..."
sleep 10

# Test health endpoint
echo "🏥 Testing health endpoint..."
if curl -f http://localhost:3000/api/health &> /dev/null; then
    echo "✅ Health check passed!"
else
    echo "❌ Health check failed!"
    docker logs rawrz-test
fi

# Cleanup
echo "🧹 Cleaning up test container..."
docker stop rawrz-test &> /dev/null
docker rm rawrz-test &> /dev/null

echo "✅ Local build test completed successfully!"