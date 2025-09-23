#!/bin/bash

# n0mn0m Quantum System - Upload to Digital Ocean Script

echo "🚀 n0mn0m Quantum System - Digital Ocean Upload"
echo "=============================================="

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

# Configuration - UPDATE THESE VALUES
DROPLET_IP="YOUR_DROPLET_IP_HERE"
DROPLET_USER="root"  # or your username
REMOTE_PATH="/opt/n0mn0m"

# Function to check if droplet IP is set
check_config() {
    if [[ "$DROPLET_IP" == "YOUR_DROPLET_IP_HERE" ]]; then
        print_error "Please update DROPLET_IP in this script with your actual droplet IP"
        echo ""
        echo "To find your droplet IP:"
        echo "1. Go to: https://cloud.digitalocean.com/droplets"
        echo "2. Click on your droplet name"
        echo "3. Copy the 'Public IPv4 address'"
        echo "4. Update line 20 in this script"
        echo ""
        exit 1
    fi
}

print_info "n0mn0m Quantum System Upload to Digital Ocean"
echo "=============================================="

# Check configuration
check_config

# Required files to upload
REQUIRED_FILES=(
    "n0mn0m_final_complete.asm"
    "master_universal_compiler.asm"
    "n0mn0m_quantum_asm_compiler.asm"
    "java_compiler_from_scratch.asm"
    "javascript_compiler_from_scratch.asm"
    "quantum-showcase-server.js"
    "package-quantum.json"
    "digitalocean-deploy.sh"
    "compile-n0mn0m.sh"
    "deploy-quantum-system.sh"
    "deploy-to-production.sh"
    "n0mn0m-README.md"
)

# Check if all required files exist
print_info "Checking required files..."

for file in "${REQUIRED_FILES[@]}"; do
    if [[ ! -f "$file" ]]; then
        print_error "Required file $file not found!"
        exit 1
    fi
done

print_status "All required files found"

# Create archive
print_info "Creating deployment archive..."

ARCHIVE_NAME="n0mn0m-quantum-system-$(date +%Y%m%d-%H%M%S).tar.gz"

tar -czf "$ARCHIVE_NAME" \
    n0mn0m_final_complete.asm \
    master_universal_compiler.asm \
    n0mn0m_quantum_asm_compiler.asm \
    java_compiler_from_scratch.asm \
    javascript_compiler_from_scratch.asm \
    quantum-showcase-server.js \
    package-quantum.json \
    digitalocean-deploy.sh \
    compile-n0mn0m.sh \
    deploy-quantum-system.sh \
    deploy-to-production.sh \
    n0mn0m-README.md \
    Dockerfile.n0mn0m \
    docker-compose.n0mn0m.yml \
    monitoring/

if [[ $? -ne 0 ]]; then
    print_error "Failed to create archive!"
    exit 1
fi

print_status "Archive created: $ARCHIVE_NAME"

# Upload to Digital Ocean
print_info "Uploading to Digital Ocean droplet..."

echo "📤 Uploading $ARCHIVE_NAME to $DROPLET_USER@$DROPLET_IP:$REMOTE_PATH"
scp "$ARCHIVE_NAME" "$DROPLET_USER@$DROPLET_IP:$REMOTE_PATH/"

if [[ $? -ne 0 ]]; then
    print_error "Upload failed! Please check:"
    echo "1. Your droplet IP address"
    echo "2. SSH access to your droplet"
    echo "3. Network connectivity"
    exit 1
fi

print_status "Archive uploaded successfully"

# Extract on remote server
print_info "Extracting files on remote server..."

ssh "$DROPLET_USER@$DROPLET_IP" "cd $REMOTE_PATH && tar -xzf $ARCHIVE_NAME && rm $ARCHIVE_NAME"

if [[ $? -ne 0 ]]; then
    print_error "Extraction failed!"
    exit 1
fi

print_status "Files extracted successfully"

# Make scripts executable
print_info "Setting permissions on remote server..."

ssh "$DROPLET_USER@$DROPLET_IP" "cd $REMOTE_PATH && chmod +x *.sh"

if [[ $? -ne 0 ]]; then
    print_warning "Failed to set permissions, but continuing..."
fi

print_status "Permissions set"

# Display deployment instructions
echo ""
echo "🎉 UPLOAD COMPLETE!"
echo "==================="
echo ""
echo "📦 Files uploaded to: $DROPLET_USER@$DROPLET_IP:$REMOTE_PATH"
echo ""
echo "🚀 **Next Steps - SSH to your droplet and run:**"
echo ""
echo "   ssh $DROPLET_USER@$DROPLET_IP"
echo "   cd $REMOTE_PATH"
echo "   ./digitalocean-deploy.sh"
echo ""
echo "📋 **Alternative deployment options:**"
echo ""
echo "   # Quick deployment"
echo "   ./deploy-quantum-system.sh"
echo ""
echo "   # Production deployment"
echo "   ./deploy-to-production.sh docker"
echo ""
echo "   # Manual compilation first"
echo "   ./compile-n0mn0m.sh"
echo ""
echo "🌐 **After deployment, access at:**"
echo "   http://$DROPLET_IP:3000"
echo ""
echo "📋 **Verify deployment:**"
echo "   curl http://$DROPLET_IP:3000/api/health"
echo ""
echo "🔧 **Management commands (run on droplet):**"
echo "   tail -f logs/quantum.log"
echo "   sudo pkill -f quantum-showcase-server.js"
echo "   docker ps (if using Docker)"
echo ""

# Save upload info
UPLOAD_TIME=$(date)
cat > upload-info.txt << EOF
n0mn0m Quantum System - Digital Ocean Upload
==========================================

Upload Information:
- Upload Time: $UPLOAD_TIME
- Droplet IP: $DROPLET_IP
- Remote User: $DROPLET_USER
- Remote Path: $REMOTE_PATH
- Archive: $ARCHIVE_NAME

Files Uploaded:
$(ls -la *.asm *.js *.json *.sh *.md 2>/dev/null | wc -l) files uploaded

Next Steps:
1. SSH to droplet: ssh $DROPLET_USER@$DROPLET_IP
2. Navigate to directory: cd $REMOTE_PATH
3. Deploy system: ./digitalocean-deploy.sh

Access URLs (after deployment):
- Main Interface: http://$DROPLET_IP:3000
- Health Check: http://$DROPLET_IP:3000/api/health
- API Documentation: http://$DROPLET_IP:3000/api/docs

Local Archive: $ARCHIVE_NAME
Upload Status: ✅ COMPLETE
EOF

print_status "Upload information saved to upload-info.txt"
print_status "n0mn0m Quantum System upload to Digital Ocean complete!"
print_status "SSH to your droplet and run: ./digitalocean-deploy.sh"