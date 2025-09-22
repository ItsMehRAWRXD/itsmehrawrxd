#!/bin/bash

# Quantum-Inspired LLM Showcase - Deployment Script

echo "🚀 Quantum-Inspired LLM Showcase Deployment"
echo "==========================================="

# Check if required files exist
if [[ ! -f "quantum-showcase-server.js" ]]; then
    echo "❌ quantum-showcase-server.js not found!"
    exit 1
fi

if [[ ! -f "package-quantum.json" ]]; then
    echo "❌ package-quantum.json not found!"
    exit 1
fi

if [[ ! -f "Dockerfile.quantum" ]]; then
    echo "❌ Dockerfile.quantum not found!"
    exit 1
fi

echo "✅ All required files found"

# Build the Docker image
echo "🏗️  Building Quantum Docker image..."
docker build -f Dockerfile.quantum -t quantum-showcase:latest .

if [[ $? -ne 0 ]]; then
    echo "❌ Docker build failed!"
    exit 1
fi

echo "✅ Quantum Docker image built successfully"

# Run the container
echo "🚀 Starting Quantum Showcase Server..."
docker run -d \
    --name quantum-showcase \
    -p 3000:3000 \
    -p 3001:3001 \
    -v $(pwd)/quantum-showcase-server.js:/app/quantum-showcase-server.js \
    -v $(pwd)/public:/app/public \
    -e NODE_ENV=production \
    -e PORT=3000 \
    --restart unless-stopped \
    quantum-showcase:latest

if [[ $? -ne 0 ]]; then
    echo "❌ Failed to start container!"
    exit 1
fi

echo "✅ Quantum Showcase Server started successfully!"

# Wait for server to be ready
echo "⏳ Waiting for server to start..."
sleep 10

# Test health endpoint
echo "🏥 Testing health endpoint..."
if curl -f http://localhost:3000/api/health &> /dev/null; then
    echo "✅ Health check passed!"
else
    echo "❌ Health check failed!"
    docker logs quantum-showcase
fi

# Get public IP
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com | tr -d '\n')

echo ""
echo "🎉 QUANTUM SYSTEM DEPLOYED SUCCESSFULLY!"
echo "=========================================="
echo "🌐 Access your Quantum Showcase at:"
echo "   http://$PUBLIC_IP:3000"
echo ""
echo "📊 Available endpoints:"
echo "   Health Check: http://$PUBLIC_IP:3000/api/health"
echo "   Quantum Generation: http://$PUBLIC_IP:3000/api/quantum/generate"
echo "   Streaming: http://$PUBLIC_IP:3000/api/quantum/stream"
echo "   WebSocket: ws://$PUBLIC_IP:3001"
echo "   Quantum Circuit: http://$PUBLIC_IP:3000/api/quantum/circuit"
echo "   System Stats: http://$PUBLIC_IP:3000/api/system/stats"
echo ""
echo "🔧 To view logs: docker logs quantum-showcase -f"
echo "🛑 To stop: docker stop quantum-showcase"
echo "🔄 To restart: docker restart quantum-showcase"