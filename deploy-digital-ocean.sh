#!/bin/bash

# RawrZ Security Platform - Digital Ocean Deployment Application
# Comprehensive deployment tool with interactive interface and automation

set -e

# Color codes for output
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
CONFIG_FILE="/opt/deployment-config.json"

# Functions
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

log_header() {
    echo -e "${PURPLE}$1${NC}"
}

display_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                   RawrZ Security Platform                       ║"
    echo "║                Digital Ocean Deployment App                     ║"
    echo "║                        Version $VERSION                               ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}🚀 Interactive deployment tool for Digital Ocean droplets${NC}"
    echo -e "${PURPLE}🔧 Automated setup with Docker, SSL, and monitoring${NC}"
    echo -e "${GREEN}🛡️  Production-ready security configurations${NC}"
    echo ""
}

display_menu() {
    log_header "\n📋 Deployment Options:"
    echo -e "${CYAN}1. 🚀 Quick Deploy (Default Configuration)${NC}"
    echo -e "${CYAN}2. ⚙️  Custom Configuration${NC}"
    echo -e "${CYAN}3. 🔧 Advanced Setup with SSL${NC}"
    echo -e "${CYAN}4. 📊 Monitoring & Backup Setup${NC}"
    echo -e "${CYAN}5. 🐳 Docker Compose Deployment${NC}"
    echo -e "${CYAN}6. 🔄 Update Existing Deployment${NC}"
    echo -e "${CYAN}7. 📋 View Configuration${NC}"
    echo -e "${CYAN}8. 🧪 Test Deployment${NC}"
    echo -e "${CYAN}9. 🔍 System Diagnostics${NC}"
    echo -e "${RED}0. ❌ Exit${NC}"
}

check_digital_ocean() {
    log_info "Checking Digital Ocean environment..."
    
    if curl -s --connect-timeout 5 http://169.254.169.254/metadata/v1/id > /dev/null 2>&1; then
        log_success "Running on Digital Ocean droplet"
        return 0
    else
        log_warning "Not running on Digital Ocean droplet"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        [[ $REPLY =~ ^[Yy]$ ]]
    fi
}

update_system() {
    log_header "\n📦 Updating system packages..."
    
    if apt update && apt upgrade -y; then
        log_success "System updated successfully"
    else
        log_error "System update failed"
        exit 1
    fi
}

install_docker() {
    log_header "\n🐳 Installing Docker..."
    
    if command -v docker > /dev/null 2>&1; then
        log_info "Docker is already installed"
        return 0
    fi
    
    if curl -fsSL https://get.docker.com -o get-docker.sh && \
       sh get-docker.sh && \
       usermod -aG docker $USER && \
       systemctl enable docker && \
       systemctl start docker; then
        log_success "Docker installed successfully"
        rm -f get-docker.sh
    else
        log_error "Docker installation failed"
        exit 1
    fi
}

install_docker_compose() {
    log_header "\n🐳 Installing Docker Compose..."
    
    if command -v docker-compose > /dev/null 2>&1; then
        log_info "Docker Compose is already installed"
        return 0
    fi
    
    if curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose && \
       chmod +x /usr/local/bin/docker-compose; then
        log_success "Docker Compose installed successfully"
    else
        log_error "Docker Compose installation failed"
        exit 1
    fi
}

setup_application() {
    log_header "\n📁 Setting up application directory..."
    
    local app_dir="/opt/$APP_NAME"
    mkdir -p "$app_dir"
    cd "$app_dir"
    
    if [ ! -d ".git" ]; then
        log_info "Cloning repository..."
        if git clone "$DEFAULT_REPO" .; then
            log_success "Repository cloned successfully"
        else
            log_error "Failed to clone repository"
            exit 1
        fi
    else
        log_info "Updating existing repository..."
        if git pull; then
            log_success "Repository updated successfully"
        else
            log_warning "Failed to update repository, continuing with existing code"
        fi
    fi
}

build_and_deploy() {
    log_header "\n🔨 Building and deploying application..."
    
    # Build Docker image
    if docker build -t "$DOCKER_IMAGE" .; then
        log_success "Docker image built successfully"
    else
        log_error "Docker build failed"
        exit 1
    fi
    
    # Stop existing container
    docker stop "$CONTAINER_NAME" 2>/dev/null || true
    docker rm "$CONTAINER_NAME" 2>/dev/null || true
    
    # Run new container
    log_info "Starting container..."
    if docker run -d \
        --name "$CONTAINER_NAME" \
        --restart unless-stopped \
        -p "$DEFAULT_PORT:3000" \
        -v "/opt/$APP_NAME/logs:/app/logs" \
        -v "/opt/$APP_NAME/data:/app/data" \
        -e NODE_ENV=production \
        "$DOCKER_IMAGE"; then
        log_success "Container started successfully"
    else
        log_error "Failed to start container"
        exit 1
    fi
}

deploy_with_compose() {
    log_header "\n🐳 Deploying with Docker Compose..."
    
    if [ -f "docker-compose.yml" ]; then
        if docker-compose down && docker-compose up -d --build; then
            log_success "Docker Compose deployment successful"
        else
            log_error "Docker Compose deployment failed"
            exit 1
        fi
    else
        log_error "docker-compose.yml not found"
        exit 1
    fi
}

configure_firewall() {
    log_header "\n🔥 Configuring firewall..."
    
    if ufw allow "$DEFAULT_PORT/tcp" && \
       ufw allow ssh && \
       ufw --force enable; then
        log_success "Firewall configured successfully"
    else
        log_warning "Firewall configuration failed, continuing..."
    fi
}

setup_ssl() {
    log_header "\n🔒 Setting up SSL/TLS..."
    
    read -p "Enter your domain name: " domain
    if [ -z "$domain" ]; then
        log_warning "Domain not provided, skipping SSL setup"
        return 0
    fi
    
    # Install certbot
    if apt install -y certbot python3-certbot-nginx; then
        log_success "Certbot installed"
    else
        log_error "Failed to install certbot"
        return 1
    fi
    
    # Generate SSL certificate
    if certbot --nginx -d "$domain" --non-interactive --agree-tos --email "admin@$domain"; then
        log_success "SSL certificate generated successfully"
    else
        log_warning "SSL certificate generation failed"
    fi
}

setup_monitoring() {
    log_header "\n📊 Setting up monitoring..."
    
    local monitoring_dir="/opt/monitoring"
    mkdir -p "$monitoring_dir"
    cd "$monitoring_dir"
    
    # Create Prometheus configuration
    cat > prometheus.yml << EOF
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'rawrz-app'
    static_configs:
      - targets: ['localhost:$DEFAULT_PORT']
EOF

    # Create Docker Compose for monitoring
    cat > docker-compose.yml << EOF
version: '3.8'
services:
  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=200h'
      - '--web.enable-lifecycle'

  grafana:
    image: grafana/grafana
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
EOF

    if docker-compose up -d; then
        log_success "Monitoring stack deployed successfully"
        log_info "Prometheus: http://$(curl -s http://checkip.amazonaws.com/):9090"
        log_info "Grafana: http://$(curl -s http://checkip.amazonaws.com/):3001 (admin/admin)"
    else
        log_error "Monitoring setup failed"
    fi
}

setup_backup() {
    log_header "\n💾 Setting up automatic backups..."
    
    local backup_script="/opt/backup.sh"
    local app_dir="/opt/$APP_NAME"
    
    cat > "$backup_script" << EOF
#!/bin/bash
# Backup script for RawrZ Security Platform
BACKUP_DIR="/opt/backups"
APP_DIR="$app_dir"
DATE=\$(date +%Y%m%d_%H%M%S)

mkdir -p \$BACKUP_DIR

# Backup application data
tar -czf \$BACKUP_DIR/rawrz_backup_\$DATE.tar.gz -C \$APP_DIR .

# Keep only last 7 days of backups
find \$BACKUP_DIR -name "rawrz_backup_*.tar.gz" -mtime +7 -delete

echo "Backup completed: rawrz_backup_\$DATE.tar.gz"
EOF

    chmod +x "$backup_script"
    
    # Add to crontab
    echo "0 2 * * * $backup_script" | crontab -
    
    log_success "Backup system configured"
    log_info "Backups will run daily at 2 AM"
}

display_results() {
    log_header "\n🎉 Deployment completed successfully!"
    
    local public_ip=$(curl -s http://checkip.amazonaws.com/)
    
    log_header "\n🌐 Access Information:"
    echo -e "${CYAN}   Main Application: http://$public_ip:$DEFAULT_PORT${NC}"
    echo -e "${CYAN}   Health Check: http://$public_ip:$DEFAULT_PORT/health${NC}"
    echo -e "${CYAN}   API Test: http://$public_ip:$DEFAULT_PORT/api/simple-test${NC}"
    
    log_header "\n📝 Management Commands:"
    echo -e "${WHITE}   View logs: docker logs $CONTAINER_NAME${NC}"
    echo -e "${WHITE}   Stop app: docker stop $CONTAINER_NAME${NC}"
    echo -e "${WHITE}   Restart app: docker restart $CONTAINER_NAME${NC}"
    echo -e "${WHITE}   Remove app: docker rm -f $CONTAINER_NAME${NC}"
}

test_deployment() {
    log_header "\n🧪 Testing deployment..."
    
    local test_url="http://localhost:$DEFAULT_PORT/health"
    
    if curl -f "$test_url" > /dev/null 2>&1; then
        log_success "Health check passed - Deployment is working!"
    else
        log_error "Health check failed"
        log_info "Container logs:"
        docker logs "$CONTAINER_NAME" --tail 20
    fi
}

system_diagnostics() {
    log_header "\n🔍 System Diagnostics..."
    
    log_info "System Information:"
    echo "OS: $(lsb_release -d | cut -f2)"
    echo "Kernel: $(uname -r)"
    echo "Architecture: $(uname -m)"
    echo "CPU: $(nproc) cores"
    echo "Memory: $(free -h | grep '^Mem:' | awk '{print $2}')"
    echo "Disk: $(df -h / | tail -1 | awk '{print $4}') available"
    
    log_info "\nDocker Status:"
    if command -v docker > /dev/null 2>&1; then
        echo "Docker: $(docker --version)"
        echo "Docker Compose: $(docker-compose --version)"
        echo "Running containers: $(docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}')"
    else
        echo "Docker: Not installed"
    fi
    
    log_info "\nNetwork Status:"
    echo "Public IP: $(curl -s http://checkip.amazonaws.com/)"
    echo "Open ports: $(ss -tlnp | grep -E ':(3000|3001|9090|80|443)' || echo 'None')"
    
    log_info "\nApplication Status:"
    if docker ps | grep -q "$CONTAINER_NAME"; then
        log_success "Application container is running"
        docker logs "$CONTAINER_NAME" --tail 5
    else
        log_error "Application container is not running"
    fi
}

quick_deploy() {
    log_header "\n🚀 Starting Quick Deploy..."
    
    if ! check_digital_ocean; then
        log_error "Deployment cancelled"
        return 1
    fi
    
    update_system
    install_docker
    install_docker_compose
    setup_application
    build_and_deploy
    configure_firewall
    display_results
}

custom_configuration() {
    log_header "\n⚙️  Custom Configuration Setup"
    
    read -p "App name [$APP_NAME]: " input_name
    APP_NAME=${input_name:-$APP_NAME}
    
    read -p "Port [$DEFAULT_PORT]: " input_port
    DEFAULT_PORT=${input_port:-$DEFAULT_PORT}
    
    read -p "Repository URL [$DEFAULT_REPO]: " input_repo
    DEFAULT_REPO=${input_repo:-$DEFAULT_REPO}
    
    read -p "Enable SSL/TLS? (y/N): " -n 1 -r ssl_choice
    echo
    SSL_ENABLED=$([ "$ssl_choice" = "y" ] || [ "$ssl_choice" = "Y" ] && echo "true" || echo "false")
    
    read -p "Enable monitoring? (y/N): " -n 1 -r monitor_choice
    echo
    MONITORING_ENABLED=$([ "$monitor_choice" = "y" ] || [ "$monitor_choice" = "Y" ] && echo "true" || echo "false")
    
    read -p "Enable backups? (y/N): " -n 1 -r backup_choice
    echo
    BACKUP_ENABLED=$([ "$backup_choice" = "y" ] || [ "$backup_choice" = "Y" ] && echo "true" || echo "false")
    
    log_success "Configuration updated!"
}

advanced_setup() {
    log_header "\n🔧 Advanced Setup with SSL"
    
    custom_configuration
    
    if [ "$SSL_ENABLED" = "true" ]; then
        setup_ssl
    fi
    
    if [ "$MONITORING_ENABLED" = "true" ]; then
        setup_monitoring
    fi
    
    if [ "$BACKUP_ENABLED" = "true" ]; then
        setup_backup
    fi
    
    # Deploy with advanced configuration
    update_system
    install_docker
    install_docker_compose
    setup_application
    deploy_with_compose
    configure_firewall
    display_results
}

main() {
    display_banner
    
    while true; do
        display_menu
        read -p "Select an option (0-9): " choice
        
        case $choice in
            1)
                quick_deploy
                ;;
            2)
                custom_configuration
                ;;
            3)
                advanced_setup
                ;;
            4)
                setup_monitoring
                setup_backup
                ;;
            5)
                setup_application
                deploy_with_compose
                ;;
            6)
                quick_deploy
                ;;
            7)
                log_header "\n📋 Current Configuration:"
                echo "App Name: $APP_NAME"
                echo "Port: $DEFAULT_PORT"
                echo "Repository: $DEFAULT_REPO"
                echo "Docker Image: $DOCKER_IMAGE"
                echo "Container Name: $CONTAINER_NAME"
                ;;
            8)
                test_deployment
                ;;
            9)
                system_diagnostics
                ;;
            0)
                log "\n👋 Goodbye!"
                exit 0
                ;;
            *)
                log_error "Invalid option. Please select 0-9."
                ;;
        esac
        
        echo
        read -p "Press Enter to continue..."
        clear
    done
}

# Handle script interruption
trap 'echo -e "\n\n👋 Deployment app shutting down..."; exit 0' INT TERM

# Run main function
main "$@"