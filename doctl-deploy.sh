#!/bin/bash

# Digital Ocean CLI (doctl) Deployment Script
# For RawrZ Security Platform and n0mn0m Quantum System

echo "🚀 Digital Ocean CLI Deployment"
echo "================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

print_info "Digital Ocean CLI Deployment Setup"
echo "=================================="

# Check if doctl is installed
if ! command -v doctl &> /dev/null; then
    print_error "doctl not found! Please install Digital Ocean CLI:"
    echo ""
    echo "Installation commands:"
    echo "curl -sL https://github.com/digitalocean/doctl/releases/latest/download/doctl-linux-amd64.tar.gz | tar -xzf - && sudo mv doctl /usr/local/bin/"
    echo ""
    echo "Or on macOS:"
    echo "brew install doctl"
    echo ""
    echo "Or on Windows:"
    echo "scoop install doctl"
    echo ""
    exit 1
fi

print_status "doctl found"

# Check if user is authenticated
print_info "Checking Digital Ocean authentication..."

if ! doctl account get &> /dev/null; then
    print_error "Not authenticated with Digital Ocean!"
    echo ""
    echo "🔑 Please authenticate with your token:"
    echo "   doctl auth init"
    echo ""
    echo "💡 Get your token from:"
    echo "   https://cloud.digitalocean.com/account/api/tokens"
    echo ""
    exit 1
fi

print_status "Digital Ocean authentication verified"

# Get account info
print_info "Getting account information..."
ACCOUNT_INFO=$(doctl account get)
echo "$ACCOUNT_INFO"

# Create app specification for RawrZ Security Platform
print_info "Creating RawrZ Security Platform app specification..."

cat > do-app-rawrz.yaml << 'EOF'
name: rawrz-security-platform
region: nyc3
services:
  - name: web
    dockerfile_path: Dockerfile.rawrz
    source_dir: .
    github:
      repo: # Add your GitHub repo here
      branch: main
    envs:
      - key: NODE_ENV
        value: production
      - key: PORT
        value: "3000"
      - key: RAWRZ_UPLOAD_DIR
        value: "/app/uploads"
      - key: RAWRZ_LOG_DIR
        value: "/app/logs"
      - key: RAWRZ_MAX_FILE_SIZE
        value: "1024MB"
    health_check:
      http_path: /api/health
      initial_delay_seconds: 60
    instance_count: 1
    instance_size_slug: basic-xxs
    http_port: 3000

  - name: websocket
    dockerfile_path: Dockerfile.rawrz
    source_dir: .
    github:
      repo: # Add your GitHub repo here
      branch: main
    envs:
      - key: NODE_ENV
        value: production
      - key: WEBSOCKET_PORT
        value: "3001"
    health_check:
      http_path: /api/health
      initial_delay_seconds: 60
    instance_count: 1
    instance_size_slug: basic-xxs
    http_port: 3001
EOF

print_status "RawrZ app specification created"

# Create app specification for n0mn0m Quantum System
print_info "Creating n0mn0m Quantum System app specification..."

cat > do-app-n0mn0m.yaml << 'EOF'
name: n0mn0m-quantum-system
region: nyc3
services:
  - name: quantum
    dockerfile_path: Dockerfile.n0mn0m
    source_dir: .
    github:
      repo: # Add your GitHub repo here
      branch: main
    envs:
      - key: NODE_ENV
        value: production
      - key: PORT
        value: "3000"
      - key: QUANTUM_SIMULATION_ENABLED
        value: "true"
      - key: N0MN0M_SYSTEM_MODE
        value: "production"
    health_check:
      http_path: /api/health
      initial_delay_seconds: 90
    instance_count: 1
    instance_size_slug: basic-xxs
    http_port: 3000
EOF

print_status "n0mn0m app specification created"

# Deploy RawrZ Security Platform
print_info "Deploying RawrZ Security Platform to Digital Ocean..."

echo ""
echo "🚀 **Deploying RawrZ Security Platform:**"
echo ""
echo "   doctl apps create --spec do-app-rawrz.yaml"
echo ""
echo "📋 **Expected result:**"
echo "   Notice: App created"
echo "   App ID: [app-id]"
echo "   Default ingress: [url].ondigitalocean.app"
echo ""

# Deploy n0mn0m Quantum System
print_info "Deploying n0mn0m Quantum System to Digital Ocean..."

echo ""
echo "🚀 **Deploying n0mn0m Quantum System:**"
echo ""
echo "   doctl apps create --spec do-app-n0mn0m.yaml"
echo ""
echo "📋 **Expected result:**"
echo "   Notice: App created"
echo "   App ID: [app-id]"
echo "   Default ingress: [url].ondigitalocean.app"
echo ""

# Management commands
print_info "Management commands after deployment:"

echo ""
echo "🔧 **View deployed apps:**"
echo "   doctl apps list"
echo ""

echo "📊 **Get app details:**"
echo "   doctl apps get [app-id]"
echo ""

echo "📝 **View logs:**"
echo "   doctl apps logs [app-id]"
echo ""

echo "🔄 **Update app:**"
echo "   doctl apps update [app-id] --spec do-app-rawrz.yaml"
echo ""

echo "🗑️  **Delete app:**"
echo "   doctl apps delete [app-id]"
echo ""

# Create deployment commands file
cat > doctl-commands.txt << 'EOF'
# Digital Ocean CLI Commands for RawrZ and n0mn0m Deployment

# Install doctl (if not already installed)
curl -sL https://github.com/digitalocean/doctl/releases/latest/download/doctl-linux-amd64.tar.gz | tar -xzf - && sudo mv doctl /usr/local/bin/

# Authenticate with Digital Ocean
doctl auth init

# Deploy RawrZ Security Platform
doctl apps create --spec do-app-rawrz.yaml

# Deploy n0mn0m Quantum System
doctl apps create --spec do-app-n0mn0m.yaml

# List all apps
doctl apps list

# Get specific app details
doctl apps get [app-id]

# View logs
doctl apps logs [app-id]

# Update app
doctl apps update [app-id] --spec do-app-rawrz.yaml

# Delete app (be careful!)
doctl apps delete [app-id]

# Get account info
doctl account get

# List droplets
doctl compute droplet list

# Create droplet (if needed)
doctl compute droplet create rawrz-server --image ubuntu-20-04-x64 --region nyc3 --size s-1vcpu-1gb --ssh-keys [ssh-key-id]
EOF

print_status "doctl commands saved to doctl-commands.txt"

# Display final instructions
echo ""
echo "🎉 **Digital Ocean Deployment Ready!**"
echo "===================================="
echo ""
echo "📋 **Next Steps:**"
echo ""
echo "1. **Authenticate with Digital Ocean:**"
echo "   doctl auth init"
echo ""
echo "2. **Deploy RawrZ Security Platform:**"
echo "   doctl apps create --spec do-app-rawrz.yaml"
echo ""
echo "3. **Deploy n0mn0m Quantum System:**"
echo "   doctl apps create --spec do-app-n0mn0m.yaml"
echo ""
echo "4. **Monitor deployment:**"
echo "   doctl apps list"
echo "   doctl apps logs [app-id]"
echo ""
echo "🌐 **Your apps will be available at:**"
echo "   RawrZ: https://[app-name].ondigitalocean.app"
echo "   n0mn0m: https://[app-name].ondigitalocean.app"
echo ""
echo "🔧 **Management:**"
echo "   - View all apps: doctl apps list"
echo "   - Update apps: doctl apps update [id] --spec [file]"
echo "   - View logs: doctl apps logs [id]"
echo "   - Delete apps: doctl apps delete [id]"
echo ""
echo "🚀 **Your systems are ready for deployment!**"
echo ""

# Clean up
print_info "Cleaning up temporary files..."
rm -f do-app-rawrz.yaml do-app-n0mn0m.yaml

print_status "Digital Ocean CLI deployment setup complete!"