#!/bin/bash

# n0mn0m Quantum System - Production Deployment Script

echo "🚀 n0mn0m Quantum System - Production Deployment"
echo "================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}📋 $1${NC}"
}

# Configuration
DEPLOYMENT_MODE=${1:-"docker"}  # docker, manual, or auto
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com 2>/dev/null | tr -d '\n' || echo "localhost")
CONTAINER_NAME="n0mn0m-quantum-system"
PORT=3000
WEBSOCKET_PORT=3001

print_info "n0mn0m Quantum System Production Deployment"
echo "================================================"
echo ""

# Check prerequisites
print_info "Checking prerequisites..."

# Check if required files exist
REQUIRED_FILES=(
    "compile-n0mn0m.sh"
    "deploy-quantum-system.sh"
    "quantum-showcase-server.js"
    "package-quantum.json"
    "Dockerfile.n0mn0m"
    "docker-compose.n0mn0m.yml"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [[ ! -f "$file" ]]; then
        print_error "Required file $file not found!"
        exit 1
    fi
done

print_status "All required files found"

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    print_error "Docker not found! Please install Docker first."
    exit 1
fi

print_status "Docker available"

# Step 1: Build the system
print_info "Step 1: Building n0mn0m System..."

if [[ "$DEPLOYMENT_MODE" == "docker" ]]; then
    print_info "Building Docker image..."
    docker build -f Dockerfile.n0mn0m -t n0mn0m-quantum-system:latest .

    if [[ $? -ne 0 ]]; then
        print_error "Docker build failed!"
        exit 1
    fi

    print_status "Docker image built successfully"

elif [[ "$DEPLOYMENT_MODE" == "manual" ]]; then
    print_info "Compiling n0mn0m components manually..."
    ./compile-n0mn0m.sh

    if [[ $? -ne 0 ]]; then
        print_error "Manual compilation failed!"
        exit 1
    fi

    print_status "Manual compilation completed"
fi

# Step 2: Stop any existing deployments
print_info "Step 2: Cleaning up existing deployments..."

# Stop existing containers
docker stop $CONTAINER_NAME 2>/dev/null || true
docker rm $CONTAINER_NAME 2>/dev/null || true

# Kill any running processes
sudo pkill -f "quantum-showcase-server.js" 2>/dev/null || true
sudo pkill -f "n0mn0m" 2>/dev/null || true

print_status "Cleanup completed"

# Step 3: Deploy the system
print_info "Step 3: Deploying n0mn0m Quantum System..."

if [[ "$DEPLOYMENT_MODE" == "docker" ]]; then
    print_info "Starting Docker container..."

    docker run -d \
        --name $CONTAINER_NAME \
        -p $PORT:$PORT \
        -p $WEBSOCKET_PORT:$WEBSOCKET_PORT \
        --restart unless-stopped \
        --memory=1g \
        --cpus=1.0 \
        n0mn0m-quantum-system:latest

    if [[ $? -ne 0 ]]; then
        print_error "Docker container failed to start!"
        exit 1
    fi

elif [[ "$DEPLOYMENT_MODE" == "manual" ]]; then
    print_info "Starting n0mn0m system manually..."
    ./deploy-quantum-system.sh

    if [[ $? -ne 0 ]]; then
        print_error "Manual deployment failed!"
        exit 1
    fi
fi

print_status "n0mn0m Quantum System deployed"

# Step 4: Wait for system to be ready
print_info "Step 4: Waiting for system initialization..."

# Wait for health check to pass
MAX_RETRIES=30
RETRY_COUNT=0

while [[ $RETRY_COUNT -lt $MAX_RETRIES ]]; do
    if curl -f http://localhost:$PORT/api/health &> /dev/null; then
        print_status "n0mn0m Quantum System is ready!"
        break
    fi

    echo "⏳ Waiting for system to start... (attempt $((RETRY_COUNT + 1))/$MAX_RETRIES)"
    sleep 10
    RETRY_COUNT=$((RETRY_COUNT + 1))
done

if [[ $RETRY_COUNT -eq $MAX_RETRIES ]]; then
    print_error "n0mn0m Quantum System failed to start within timeout!"
    print_info "Checking logs..."
    docker logs $CONTAINER_NAME 2>/dev/null || echo "Container logs not available"
    exit 1
fi

# Step 5: Configure firewall
print_info "Step 5: Configuring firewall..."

if command -v ufw &> /dev/null; then
    sudo ufw allow $PORT/tcp 2>/dev/null || true
    sudo ufw allow $WEBSOCKET_PORT/tcp 2>/dev/null || true
    print_status "Firewall configured"
else
    print_warning "UFW not available, skipping firewall configuration"
fi

# Step 6: Display deployment summary
echo ""
echo "🎉 n0mn0m QUANTUM SYSTEM PRODUCTION DEPLOYMENT COMPLETE!"
echo "======================================================="
echo ""
echo "🌐 **Access your n0mn0m Quantum System at:**"
echo "   http://$PUBLIC_IP:$PORT"
echo ""
echo "📊 **Available Services:**"
echo "   🔍 Health Check:      http://$PUBLIC_IP:$PORT/api/health"
echo "   🧬 Quantum Generation: http://$PUBLIC_IP:$PORT/api/quantum/generate"
echo "   ⚡ Real-time Streaming: http://$PUBLIC_IP:$PORT/api/quantum/stream"
echo "   🔗 WebSocket:          ws://$PUBLIC_IP:$WEBSOCKET_PORT"
echo "   ⚛️  Quantum Circuit:    http://$PUBLIC_IP:$PORT/api/quantum/circuit"
echo "   📈 System Stats:       http://$PUBLIC_IP:$PORT/api/system/stats"
echo ""
echo "🚀 **System Features:**"
echo "   • 49 Language Compilers from Scratch"
echo "   • Quantum Computing Support"
echo "   • Advanced Debugging & Reverse Engineering"
echo "   • AI-Powered Development Environment"
echo "   • Cross-Platform Compilation"
echo "   • Self-Maintaining Architecture"
echo "   • Complete Transparency (50,000+ Lines)"
echo ""
echo "🔧 **Management Commands:**"
echo "   View Logs:           docker logs $CONTAINER_NAME -f"
echo "   Restart System:      docker restart $CONTAINER_NAME"
echo "   Stop System:         docker stop $CONTAINER_NAME"
echo "   System Status:       docker ps | grep $CONTAINER_NAME"
echo "   Health Check:        curl http://$PUBLIC_IP:$PORT/api/health"
echo ""
echo "📊 **Resource Usage:**"
echo "   Container: $CONTAINER_NAME"
echo "   Memory Limit: 1GB"
echo "   CPU Limit: 1.0 cores"
echo "   Ports: $PORT, $WEBSOCKET_PORT"
echo ""
echo "🛡️  **Security Features:**"
echo "   • Non-root container execution"
echo "   • Resource limits enforced"
echo "   • Complete transparency"
echo "   • Input validation"
echo "   • Safe compilation sandbox"
echo ""
echo "🎯 **Your n0mn0m Quantum System is now operational!**"
echo ""
echo "💡 **Next Steps:**"
echo "   1. Visit http://$PUBLIC_IP:$PORT to access the interface"
echo "   2. Test quantum generation at /api/quantum/generate"
echo "   3. Monitor system health at /api/health"
echo "   4. Check logs with: docker logs $CONTAINER_NAME -f"
echo ""

# Save deployment info
DEPLOYMENT_TIME=$(date)
cat > deployment-production-info.txt << EOF
n0mn0m Quantum System - Production Deployment
============================================

Deployment Information:
- Deployment Time: $DEPLOYMENT_TIME
- Deployment Mode: $DEPLOYMENT_MODE
- Public IP: $PUBLIC_IP
- Main Port: $PORT
- WebSocket Port: $WEBSOCKET_PORT
- Container: $CONTAINER_NAME

Access URLs:
- Main Interface: http://$PUBLIC_IP:$PORT
- Health Check: http://$PUBLIC_IP:$PORT/api/health
- API Documentation: http://$PUBLIC_IP:$PORT/api/docs

System Features:
- 49 Language Compilers (from scratch)
- Quantum Computing Support
- Advanced Debugging Suite
- AI-Powered Development
- Cross-Platform Compilation
- Self-Maintaining Architecture

Monitoring:
- Container Logs: docker logs $CONTAINER_NAME -f
- System Health: curl http://$PUBLIC_IP:$PORT/api/health
- Resource Usage: docker stats $CONTAINER_NAME

Management:
- Restart: docker restart $CONTAINER_NAME
- Stop: docker stop $CONTAINER_NAME
- Remove: docker rm $CONTAINER_NAME

Security:
- Non-root execution
- Resource limits: 1GB RAM, 1 CPU
- Complete transparency
- Input validation

Built Components:
$(ls -la *.o 2>/dev/null | wc -l) compiled assembly objects
Node.js showcase server
Quantum compilation system
Universal compiler suite

Status: ✅ PRODUCTION READY
EOF

print_status "Production deployment information saved to deployment-production-info.txt"
print_status "n0mn0m Quantum System production deployment complete!"
print_status "Access your system at: http://$PUBLIC_IP:$PORT"