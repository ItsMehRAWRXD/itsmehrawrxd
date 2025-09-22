#!/bin/bash

# RawrZ Security Platform - Optimized DigitalOcean Deployment
set -e

echo "=== RawrZ Security Platform - Optimized DigitalOcean Deployment ==="
echo "🚀 Starting optimized deployment to DigitalOcean..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="rawrz-security-platform"
CONTAINER_NAME="rawrz-optimized"
IMAGE_NAME="rawrz-platform:optimized"
PORT=3000

# Function to print colored output
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

# Check if running on DigitalOcean
check_digitalocean() {
    if [[ -f /etc/digitalocean || -n "$DIGITALOCEAN_DROPLET_ID" ]]; then
        print_status "Running on DigitalOcean Droplet ✓"
        return 0
    else
        print_warning "This script is optimized for DigitalOcean Droplets"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Update system packages
update_system() {
    print_header "Updating System Packages"
    
    if command -v apt &> /dev/null; then
        sudo apt update
        sudo apt upgrade -y
        sudo apt autoremove -y
        sudo apt autoclean
    elif command -v yum &> /dev/null; then
        sudo yum update -y
    else
        print_warning "Unknown package manager. Skipping system update."
    fi
}

# Install Docker if not present
install_docker() {
    if command -v docker &> /dev/null; then
        print_status "Docker is already installed ✓"
        return 0
    fi

    print_header "Installing Docker"
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    sudo systemctl enable docker
    sudo systemctl start docker
    
    # Install Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        print_status "Installing Docker Compose..."
        sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        sudo chmod +x /usr/local/bin/docker-compose
    fi
    
    print_status "Docker installation completed ✓"
}

# Optimize system for containerized applications
optimize_system() {
    print_header "Optimizing System for Containers"
    
    # Configure kernel parameters
    sudo tee /etc/sysctl.d/99-docker.conf > /dev/null <<EOF
# Docker optimization
vm.max_map_count=262144
vm.overcommit_memory=1
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=65535
net.ipv4.ip_local_port_range=1024 65535
EOF
    
    sudo sysctl -p /etc/sysctl.d/99-docker.conf
    
    # Configure Docker daemon
    sudo mkdir -p /etc/docker
    sudo tee /etc/docker/daemon.json > /dev/null <<EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2",
  "live-restore": true
}
EOF
    
    sudo systemctl restart docker
    print_status "System optimization completed ✓"
}

# Create application directory and setup
setup_application() {
    print_header "Setting Up Application"
    
    # Create app directory
    APP_DIR="/opt/$PROJECT_NAME"
    sudo mkdir -p $APP_DIR
    sudo chown -R $USER:$USER $APP_DIR
    cd $APP_DIR
    
    # Create necessary directories
    mkdir -p logs temp uploads public
    chmod 755 logs temp uploads
    
    print_status "Application directory setup completed ✓"
}

# Deploy the application
deploy_application() {
    print_header "Deploying Application"
    
    # Stop existing container if running
    if docker ps -a | grep -q $CONTAINER_NAME; then
        print_status "Stopping existing container..."
        docker stop $CONTAINER_NAME 2>/dev/null || true
        docker rm $CONTAINER_NAME 2>/dev/null || true
    fi
    
    # Remove old image
    if docker images | grep -q "rawrz-platform"; then
        print_status "Removing old image..."
        docker rmi $(docker images "rawrz-platform" -q) 2>/dev/null || true
    fi
    
    # Build optimized image
    print_status "Building optimized Docker image..."
    docker build -f Dockerfile.optimized -t $IMAGE_NAME .
    
    # Run optimized container
    print_status "Starting optimized container..."
    docker run -d \
        --name $CONTAINER_NAME \
        --restart unless-stopped \
        -p $PORT:$PORT \
        -v $(pwd)/logs:/app/logs \
        -v $(pwd)/temp:/app/temp \
        -v $(pwd)/uploads:/app/uploads \
        -e NODE_ENV=production \
        -e PORT=$PORT \
        -e LOG_LEVEL=info \
        --memory=512m \
        --cpus=1.0 \
        --oom-kill-disable=false \
        $IMAGE_NAME
    
    # Wait for container to start
    print_status "Waiting for application to start..."
    sleep 10
    
    # Health check
    for i in {1..30}; do
        if curl -f http://localhost:$PORT/health >/dev/null 2>&1; then
            print_status "Application is healthy ✓"
            break
        fi
        if [ $i -eq 30 ]; then
            print_error "Application failed to start properly"
            docker logs $CONTAINER_NAME --tail 50
            exit 1
        fi
        sleep 2
    done
}

# Configure firewall
configure_firewall() {
    print_header "Configuring Firewall"
    
    if command -v ufw &> /dev/null; then
        sudo ufw allow $PORT/tcp comment "RawrZ Platform"
        sudo ufw allow ssh
        sudo ufw --force enable
        print_status "UFW firewall configured ✓"
    elif command -v firewall-cmd &> /dev/null; then
        sudo firewall-cmd --permanent --add-port=$PORT/tcp
        sudo firewall-cmd --reload
        print_status "FirewallD configured ✓"
    else
        print_warning "No recognized firewall found. Please manually open port $PORT"
    fi
}

# Setup monitoring and maintenance
setup_monitoring() {
    print_header "Setting Up Monitoring"
    
    # Create monitoring script
    cat > monitor-app.sh << 'EOF'
#!/bin/bash
CONTAINER_NAME="rawrz-optimized"

# Check if container is running
if ! docker ps | grep -q $CONTAINER_NAME; then
    echo "$(date): Container not running, attempting restart..."
    docker start $CONTAINER_NAME
fi

# Check health endpoint
if ! curl -f http://localhost:3000/health >/dev/null 2>&1; then
    echo "$(date): Health check failed, restarting container..."
    docker restart $CONTAINER_NAME
fi
EOF
    
    chmod +x monitor-app.sh
    
    # Setup cron job for monitoring
    (crontab -l 2>/dev/null; echo "*/5 * * * * $(pwd)/monitor-app.sh >> $(pwd)/logs/monitor.log 2>&1") | crontab -
    
    print_status "Monitoring setup completed ✓"
}

# Main deployment function
main() {
    print_header "RawrZ Security Platform - Optimized Deployment"
    
    check_digitalocean
    update_system
    install_docker
    optimize_system
    setup_application
    deploy_application
    configure_firewall
    setup_monitoring
    
    # Get server information
    PUBLIC_IP=$(curl -s http://checkip.amazonaws.com/ || echo "Unable to detect IP")
    MEMORY_USAGE=$(docker stats $CONTAINER_NAME --no-stream --format "table {{.MemUsage}}" | tail -1)
    
    print_header "Deployment Completed Successfully!"
    echo ""
    echo -e "${GREEN}🎉 Your optimized RawrZ Security Platform is now running!${NC}"
    echo ""
    echo -e "${BLUE}📋 Deployment Information:${NC}"
    echo "   🌐 Application URL: http://$PUBLIC_IP:$PORT"
    echo "   💚 Health Check: http://$PUBLIC_IP:$PORT/health"
    echo "   🧪 API Status: http://$PUBLIC_IP:$PORT/api/status"
    echo "   📊 Memory Usage: $MEMORY_USAGE"
    echo ""
    echo -e "${BLUE}🛠️  Useful Commands:${NC}"
    echo "   📋 View logs: docker logs $CONTAINER_NAME"
    echo "   🔄 Restart: docker restart $CONTAINER_NAME"
    echo "   🛑 Stop: docker stop $CONTAINER_NAME"
    echo "   📊 Stats: docker stats $CONTAINER_NAME"
    echo "   🗑️  Remove: docker rm -f $CONTAINER_NAME"
    echo ""
    echo -e "${YELLOW}📝 Notes:${NC}"
    echo "   • Resource limits: 512MB RAM, 1 CPU core"
    echo "   • Auto-restart enabled"
    echo "   • Health monitoring active"
    echo "   • Logs rotation configured"
    echo ""
    echo -e "${GREEN}✅ Deployment optimization features:${NC}"
    echo "   • Minimal dependencies (10 vs 100+ packages)"
    echo "   • Memory-efficient Docker image (Alpine Linux)"
    echo "   • Resource limits and monitoring"
    echo "   • Graceful shutdown handling"
    echo "   • Automatic health checks"
    echo ""
}

# Run main function
main "$@"