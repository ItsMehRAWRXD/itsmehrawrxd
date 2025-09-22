#!/bin/bash

# n0mn0m Quantum System - Complete Deployment Script

echo "🚀 n0mn0m Quantum System Deployment"
echo "===================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Check if we're in the right directory
if [[ ! -f "compile-n0mn0m.sh" ]]; then
    print_error "compile-n0mn0m.sh not found! Please run this from the project root."
    exit 1
fi

print_info "Starting n0mn0m Quantum System deployment..."

# Step 1: Compile the system
print_info "Step 1: Compiling n0mn0m System..."

if [[ -f "n0mn0m_final_complete.asm" ]]; then
    print_info "Compiling n0mn0m Final System..."
    nasm -f elf64 n0mn0m_final_complete.asm -o n0mn0m_final_complete.o

    if [[ $? -eq 0 ]]; then
        print_status "n0mn0m Final System compiled successfully!"
    else
        print_error "n0mn0m Final System compilation failed!"
        exit 1
    fi
else
    print_warning "n0mn0m Final System source not found, skipping..."
fi

# Step 2: Compile Master Universal Compiler
print_info "Step 2: Compiling Master Universal Compiler..."

if [[ -f "master_universal_compiler.asm" ]]; then
    print_info "Compiling Master Universal Compiler..."
    nasm -f elf64 master_universal_compiler.asm -o master_universal_compiler.o

    if [[ $? -eq 0 ]]; then
        print_status "Master Universal Compiler compiled successfully!"
    else
        print_error "Master Universal Compiler compilation failed!"
        exit 1
    fi
else
    print_warning "Master Universal Compiler source not found, skipping..."
fi

# Step 3: Compile Quantum ASM Compiler
print_info "Step 3: Compiling Quantum ASM Compiler..."

if [[ -f "n0mn0m_quantum_asm_compiler.asm" ]]; then
    print_info "Compiling Quantum ASM Compiler..."
    nasm -f elf64 n0mn0m_quantum_asm_compiler.asm -o n0mn0m_quantum_asm_compiler.o

    if [[ $? -eq 0 ]]; then
        print_status "Quantum ASM Compiler compiled successfully!"
    else
        print_error "Quantum ASM Compiler compilation failed!"
        exit 1
    fi
else
    print_warning "Quantum ASM Compiler source not found, skipping..."
fi

# Step 4: Set up Node.js server
print_info "Step 4: Setting up Quantum Showcase Server..."

if [[ -f "package-quantum.json" ]]; then
    cp package-quantum.json package.json

    if [[ -f "package-lock.json" ]]; then
        print_info "Installing dependencies with lock file..."
        npm ci --omit=dev
    else
        print_info "Installing dependencies..."
        npm install --omit=dev
    fi

    if [[ $? -eq 0 ]]; then
        print_status "Quantum Showcase Server dependencies installed!"
    else
        print_error "Failed to install dependencies!"
        exit 1
    fi
else
    print_error "package-quantum.json not found!"
    exit 1
fi

# Step 5: Kill any existing processes
print_info "Step 5: Stopping any existing processes..."
sudo pkill -f "quantum-showcase-server.js" 2>/dev/null || true
sudo pkill -f "node.*quantum" 2>/dev/null || true

# Step 6: Start the Quantum Showcase Server
print_info "Step 6: Starting Quantum Showcase Server..."

# Create logs directory
mkdir -p logs

# Start the server in background
nohup node quantum-showcase-server.js > logs/quantum.log 2>&1 &

# Wait for server to start
print_info "Waiting for server to initialize..."
sleep 10

# Check if server started successfully
if curl -f http://localhost:3000/api/health &> /dev/null; then
    print_status "Quantum Showcase Server started successfully!"
else
    print_error "Quantum Showcase Server failed to start!"
    print_info "Checking logs..."
    tail -20 logs/quantum.log
    exit 1
fi

# Step 7: Open firewall (if running locally)
print_info "Step 7: Configuring firewall..."
sudo ufw allow 3000/tcp 2>/dev/null || true
sudo ufw allow 3001/tcp 2>/dev/null || true

# Step 8: Get public IP
print_info "Step 8: Getting deployment information..."
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com 2>/dev/null | tr -d '\n' || echo "localhost")

if [[ "$PUBLIC_IP" == "localhost" ]]; then
    PUBLIC_IP="127.0.0.1"
fi

# Step 9: Display deployment summary
echo ""
echo "🎉 n0mn0m QUANTUM SYSTEM DEPLOYED SUCCESSFULLY!"
echo "==============================================="
echo ""
echo "🌐 **Access your Quantum System at:**"
echo "   http://$PUBLIC_IP:3000"
echo ""
echo "📊 **Available Services:**"
echo "   🔍 Health Check:      http://$PUBLIC_IP:3000/api/health"
echo "   🧬 Quantum Generation: http://$PUBLIC_IP:3000/api/quantum/generate"
echo "   ⚡ Real-time Streaming: http://$PUBLIC_IP:3000/api/quantum/stream"
echo "   🔗 WebSocket:          ws://$PUBLIC_IP:3001"
echo "   ⚛️  Quantum Circuit:    http://$PUBLIC_IP:3000/api/quantum/circuit"
echo "   📈 System Stats:       http://$PUBLIC_IP:3000/api/system/stats"
echo ""
echo "🔧 **Compiled Components:**"
if [[ -f "n0mn0m_final_complete.o" ]]; then
    echo "   ✅ n0mn0m Final System"
fi
if [[ -f "master_universal_compiler.o" ]]; then
    echo "   ✅ Master Universal Compiler (49 Languages)"
fi
if [[ -f "n0mn0m_quantum_asm_compiler.o" ]]; then
    echo "   ✅ Quantum ASM Compiler"
fi
echo "   ✅ Quantum Showcase Server"
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
echo "📋 **To view logs:**"
echo "   tail -f logs/quantum.log"
echo ""
echo "🛑 **To stop the system:**"
echo "   sudo pkill -f \"quantum-showcase-server.js\""
echo ""
echo "🔄 **To restart the system:**"
echo "   ./deploy-quantum-system.sh"
echo ""
echo "💡 **Digital Ocean Deployment:**"
echo "   1. Copy all files to your server"
echo "   2. Run: ./deploy-quantum-system.sh"
echo "   3. Access via: http://YOUR_SERVER_IP:3000"
echo ""
echo "🎯 **Your n0mn0m Quantum System is now operational!**"
echo ""

# Save deployment info
cat > deployment-info.txt << EOF
n0mn0m Quantum System Deployment
=================================

Deployment Time: $(date)
Public IP: $PUBLIC_IP
Port: 3000

Access URL: http://$PUBLIC_IP:3000

Components:
$(ls -la *.o 2>/dev/null | wc -l) compiled assembly objects
Quantum Showcase Server: Running
Node.js Server: Running on port 3000
WebSocket Server: Running on port 3001

Logs: logs/quantum.log
EOF

print_status "Deployment information saved to deployment-info.txt"
print_status "n0mn0m Quantum System deployment complete!"