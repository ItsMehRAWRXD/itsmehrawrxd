#!/bin/bash

# RawrZ Security Platform - DigitalOcean Droplet Deployment
# Enhanced deployment script with improved error handling and security

set -e

# Color codes for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Configuration
APP_NAME="rawrz-security-platform"
VERSION="1.0.0"
DEFAULT_PORT=3000
DEFAULT_REPO="https://github.com/ItsMehRAWRXD/itsmehrawrxd.git"
DOCKER_IMAGE="rawrz-security-platform:latest"
CONTAINER_NAME="rawrz-app"

log() {
    echo -e "${WHITE}$1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

display_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                   RawrZ Security Platform                       ║"
    echo "║                DigitalOcean Droplet Deployment                  ║"
    echo "║                        Version $VERSION                               ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}🚀 Enhanced deployment with improved security and monitoring${NC}"
    echo ""
}

log_header() {
    echo -e "${PURPLE}$1${NC}"
}

# Check if we're on a DigitalOcean Droplet
if [ ! -f /etc/digitalocean ]; then
    echo "⚠️  This script is designed to run on a DigitalOcean Droplet"
    echo "Please run this script on your DigitalOcean server"
    exit 1
fi

# Update system
echo "📦 Updating system packages..."
apt update && apt upgrade -y

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "🐳 Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    usermod -aG docker $USER
    systemctl enable docker
    systemctl start docker
fi

# Install Docker Compose if not present
if ! command -v docker-compose &> /dev/null; then
    echo "🐳 Installing Docker Compose..."
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
fi

# Create app directory
echo "📁 Creating application directory..."
mkdir -p /opt/rawrz-platform
cd /opt/rawrz-platform

# Clone the repository (you'll need to update this with your actual repo)
echo "📥 Cloning repository..."
git clone https://github.com/ItsMehRAWRXD/itsmehrawrxd.git .

# Build and run the application
echo "🔨 Building Docker image..."
docker build -t rawrz-security-platform:latest .

# Stop any existing container
echo "🛑 Stopping existing container..."
docker stop rawrz-app 2>/dev/null || true
docker rm rawrz-app 2>/dev/null || true

# Run the application
echo "🚀 Starting application..."
docker run -d \
    --name rawrz-app \
    --restart unless-stopped \
    -p 3000:3000 \
    -v /opt/rawrz-platform/logs:/app/logs \
    rawrz-security-platform:latest

# Configure firewall
echo "🔥 Configuring firewall..."
ufw allow 3000/tcp
ufw allow ssh
ufw --force enable

# Get public IP
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com/)
echo ""
echo "🎉 Deployment completed successfully!"
echo "🌐 Your RawrZ Security Platform is available at:"
echo "   http://$PUBLIC_IP:3000"
echo "📊 Health check: http://$PUBLIC_IP:3000/health"
echo "🧪 API test: http://$PUBLIC_IP:3000/api/simple-test"
echo ""
echo "📝 Useful commands:"
echo "  View logs: docker logs rawrz-app"
echo "  Stop app: docker stop rawrz-app"
echo "  Restart app: docker restart rawrz-app"
echo "  Remove app: docker rm -f rawrz-app"
echo ""
echo "🔒 Security Note: Make sure to configure SSL/TLS for production use!"
