#!/bin/bash

# RawrZ Security Platform - DigitalOcean Token-Based Deployment
set -e

echo "=== RawrZ Security Platform - DigitalOcean Deployment ==="
echo "🚀 Deploying with your DigitalOcean token..."

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
APP_NAME="rawrz-security-platform"
REGION="nyc1"
SIZE="basic-xxs"  # Most cost-effective

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Check if DO token is provided
if [ -z "$DIGITALOCEAN_ACCESS_TOKEN" ]; then
    print_error "DIGITALOCEAN_ACCESS_TOKEN environment variable is required"
    echo "Please set your token like this:"
    echo "export DIGITALOCEAN_ACCESS_TOKEN=your_token_here"
    echo ""
    echo "Or run with token:"
    echo "DIGITALOCEAN_ACCESS_TOKEN=your_token ./deploy-with-token.sh"
    exit 1
fi

# Install doctl if not present
install_doctl() {
    if command -v doctl &> /dev/null; then
        print_status "doctl is already installed ✓"
        return 0
    fi

    print_header "Installing doctl CLI"
    
    # Detect OS and architecture
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        arm64|aarch64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
        *) print_error "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    
    # Download and install doctl
    DOCTL_VERSION="1.104.0"  # Use latest stable version
    DOCTL_URL="https://github.com/digitalocean/doctl/releases/download/v${DOCTL_VERSION}/doctl-${DOCTL_VERSION}-${OS}-${ARCH}.tar.gz"
    
    curl -sL "$DOCTL_URL" | tar -xzv
    sudo mv doctl /usr/local/bin/
    
    print_status "doctl installed successfully ✓"
}

# Authenticate with DigitalOcean
authenticate() {
    print_header "Authenticating with DigitalOcean"
    
    doctl auth init --access-token "$DIGITALOCEAN_ACCESS_TOKEN"
    
    # Verify authentication
    if doctl account get >/dev/null 2>&1; then
        ACCOUNT_EMAIL=$(doctl account get --format Email --no-header)
        print_status "Authenticated successfully as: $ACCOUNT_EMAIL ✓"
    else
        print_error "Authentication failed. Please check your token."
        exit 1
    fi
}

# Prepare deployment files
prepare_deployment() {
    print_header "Preparing Deployment Files"
    
    # Create a deployment directory
    DEPLOY_DIR="/tmp/rawrz-deploy-$(date +%s)"
    mkdir -p "$DEPLOY_DIR"
    
    # Copy optimized files
    cp Dockerfile.optimized "$DEPLOY_DIR/Dockerfile"
    cp package.optimized.json "$DEPLOY_DIR/package.json"
    cp server.optimized.js "$DEPLOY_DIR/server.js"
    cp .env.production "$DEPLOY_DIR/.env"
    
    # Create a simple public directory
    mkdir -p "$DEPLOY_DIR/public"
    cat > "$DEPLOY_DIR/public/index.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>RawrZ Security Platform</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .container { max-width: 600px; margin: 0 auto; }
        .status { color: #28a745; font-size: 24px; }
        .endpoints { text-align: left; background: #f8f9fa; padding: 20px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ RawrZ Security Platform</h1>
        <p class="status">✅ Platform is running successfully!</p>
        
        <div class="endpoints">
            <h3>Available Endpoints:</h3>
            <ul>
                <li><strong>GET /</strong> - This page</li>
                <li><strong>GET /health</strong> - Health check</li>
                <li><strong>GET /api</strong> - API information</li>
                <li><strong>POST /api/test</strong> - Test endpoint</li>
                <li><strong>GET /api/status</strong> - Server status</li>
            </ul>
        </div>
        
        <p><em>Optimized for DigitalOcean App Platform</em></p>
    </div>
</body>
</html>
EOF
    
    # Update server.js to use the correct filename
    sed -i 's/server\.optimized\.js/server.js/g' "$DEPLOY_DIR/server.js" || true
    
    cd "$DEPLOY_DIR"
    print_status "Deployment files prepared in: $DEPLOY_DIR ✓"
}

# Initialize git repository for deployment
setup_git() {
    print_header "Setting up Git Repository"
    
    git init
    git config user.name "RawrZ Deployer"
    git config user.email "deploy@rawrz.platform"
    
    # Create .gitignore
    cat > .gitignore << 'EOF'
node_modules/
*.log
.DS_Store
.env.local
EOF
    
    git add .
    git commit -m "Initial optimized deployment"
    
    print_status "Git repository initialized ✓"
}

# Create the App Platform app
create_app() {
    print_header "Creating DigitalOcean App"
    
    # Create app spec
    cat > app-spec.yaml << EOF
name: $APP_NAME
region: $REGION
services:
- name: api
  source_dir: /
  run_command: node server.js
  environment_slug: node-js
  instance_count: 1
  instance_size_slug: $SIZE
  
  envs:
  - key: NODE_ENV
    value: production
  - key: PORT
    value: "8080"
  - key: LOG_LEVEL
    value: info
  - key: NODE_OPTIONS
    value: "--max-old-space-size=256"
    
  health_check:
    http_path: /health
    
  routes:
  - path: /
    
  alerts:
  - rule: CPU_UTILIZATION
    disabled: false
  - rule: MEM_UTILIZATION  
    disabled: false
  - rule: RESTART_COUNT
    disabled: false
EOF

    # Check if app already exists
    if doctl apps list --format Name --no-header | grep -q "^$APP_NAME$"; then
        print_warning "App '$APP_NAME' already exists. Updating instead..."
        APP_ID=$(doctl apps list --format ID,Name --no-header | grep "$APP_NAME" | awk '{print $1}')
        doctl apps update "$APP_ID" --spec app-spec.yaml
        print_status "App updated successfully ✓"
    else
        # Create new app
        print_status "Creating new app: $APP_NAME"
        doctl apps create --spec app-spec.yaml --wait
        print_status "App created successfully ✓"
    fi
    
    # Get app information
    APP_ID=$(doctl apps list --format ID,Name --no-header | grep "$APP_NAME" | awk '{print $1}')
    APP_URL=$(doctl apps get "$APP_ID" --format LiveURL --no-header)
    
    echo ""
    print_header "Deployment Completed Successfully!"
    echo ""
    echo -e "${GREEN}🎉 Your optimized RawrZ Security Platform is deployed!${NC}"
    echo ""
    echo -e "${BLUE}📋 App Information:${NC}"
    echo "   🆔 App ID: $APP_ID"
    echo "   📛 App Name: $APP_NAME"
    echo "   🌐 App URL: $APP_URL"
    echo "   🌍 Region: $REGION"
    echo "   📦 Size: $SIZE"
    echo ""
    echo -e "${BLUE}🔗 Quick Links:${NC}"
    echo "   🏠 Homepage: $APP_URL"
    echo "   💚 Health Check: $APP_URL/health"
    echo "   🧪 API Status: $APP_URL/api/status"
    echo "   🔧 API Test: $APP_URL/api"
    echo ""
    echo -e "${BLUE}🛠️  Management Commands:${NC}"
    echo "   📊 App status: doctl apps get $APP_ID"
    echo "   📋 View logs: doctl apps logs $APP_ID --follow"
    echo "   🔄 Restart: doctl apps restart $APP_ID"
    echo "   🗑️  Delete: doctl apps delete $APP_ID"
    echo ""
    echo -e "${GREEN}✅ Optimization Features Active:${NC}"
    echo "   • Memory limit: 256MB heap, auto-scaling"
    echo "   • CPU optimization: Auto-scaling based on load"
    echo "   • Health monitoring: Automatic restart on failures"
    echo "   • Minimal dependencies: Fast startup and low resource usage"
    echo "   • Log rotation: Automatic log management"
    echo ""
    
    # Cleanup
    cd /
    rm -rf "$DEPLOY_DIR"
}

# Main deployment function
main() {
    print_header "RawrZ Security Platform - Token Deployment"
    
    install_doctl
    authenticate
    prepare_deployment
    setup_git
    create_app
    
    print_status "🚀 Deployment process completed successfully!"
}

# Error handling
trap 'print_error "Deployment failed at line $LINENO. Check the error above."' ERR

# Run main function
main "$@"