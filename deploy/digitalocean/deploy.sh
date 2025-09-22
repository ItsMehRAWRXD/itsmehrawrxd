#!/bin/bash

#####################################
# Digital Ocean Deployment Script
# For RawrZ Security Platform
#####################################

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
APP_NAME="rawrz-security-platform"
DOCKER_REGISTRY="${DOCKER_REGISTRY:-registry.digitalocean.com}"
DOCKER_REPO="${DOCKER_REPO:-$DOCKER_REGISTRY/$APP_NAME}"
DOCKER_TAG="${DOCKER_TAG:-latest}"
DROPLET_USER="${DROPLET_USER:-root}"
NGINX_ENABLED="${NGINX_ENABLED:-true}"
SSL_ENABLED="${SSL_ENABLED:-true}"
DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"

# Function to print colored output
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to check prerequisites
check_prerequisites() {
    print_message "$BLUE" "🔍 Checking prerequisites..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        print_message "$RED" "❌ Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check if doctl is installed (Digital Ocean CLI)
    if ! command -v doctl &> /dev/null; then
        print_message "$YELLOW" "⚠️  doctl (DigitalOcean CLI) is not installed."
        print_message "$YELLOW" "   Install it from: https://docs.digitalocean.com/reference/doctl/how-to/install/"
    fi
    
    # Check if required environment variables are set
    if [ -z "$DROPLET_IP" ]; then
        print_message "$RED" "❌ DROPLET_IP environment variable is not set."
        print_message "$YELLOW" "   Set it with: export DROPLET_IP=your.droplet.ip.address"
        exit 1
    fi
    
    print_message "$GREEN" "✅ Prerequisites check completed."
}

# Function to build Docker image
build_docker_image() {
    print_message "$BLUE" "🔨 Building Docker image..."
    
    # Build the Docker image
    docker build -t ${APP_NAME}:${DOCKER_TAG} \
        --build-arg NODE_ENV=production \
        --build-arg PORT=8080 \
        -f Dockerfile.production .
    
    # Tag for registry
    docker tag ${APP_NAME}:${DOCKER_TAG} ${DOCKER_REPO}:${DOCKER_TAG}
    
    print_message "$GREEN" "✅ Docker image built successfully."
}

# Function to push to Digital Ocean Container Registry
push_to_registry() {
    print_message "$BLUE" "📤 Pushing to Digital Ocean Container Registry..."
    
    # Login to Digital Ocean registry if doctl is available
    if command -v doctl &> /dev/null; then
        doctl registry login
    else
        print_message "$YELLOW" "⚠️  Manual docker login required:"
        print_message "$YELLOW" "   docker login $DOCKER_REGISTRY"
    fi
    
    # Push the image
    docker push ${DOCKER_REPO}:${DOCKER_TAG}
    
    print_message "$GREEN" "✅ Image pushed to registry successfully."
}

# Function to deploy to Droplet
deploy_to_droplet() {
    print_message "$BLUE" "🚀 Deploying to Digital Ocean Droplet..."
    
    # Create deployment directory on droplet
    ssh ${DROPLET_USER}@${DROPLET_IP} "mkdir -p ~/deployments/${APP_NAME}"
    
    # Copy docker-compose and environment files
    scp docker-compose.production.yml ${DROPLET_USER}@${DROPLET_IP}:~/deployments/${APP_NAME}/docker-compose.yml
    scp .env.production ${DROPLET_USER}@${DROPLET_IP}:~/deployments/${APP_NAME}/.env
    
    # Copy nginx configuration if enabled
    if [ "$NGINX_ENABLED" = "true" ]; then
        scp nginx/nginx.conf ${DROPLET_USER}@${DROPLET_IP}:~/deployments/${APP_NAME}/nginx.conf
    fi
    
    # Deploy on the droplet
    ssh ${DROPLET_USER}@${DROPLET_IP} << EOF
        cd ~/deployments/${APP_NAME}
        
        # Pull the latest image
        docker pull ${DOCKER_REPO}:${DOCKER_TAG}
        
        # Stop existing containers
        docker-compose down || true
        
        # Start new containers
        docker-compose up -d
        
        # Clean up old images
        docker image prune -f
EOF
    
    print_message "$GREEN" "✅ Deployment to droplet completed."
}

# Function to setup SSL with Let's Encrypt
setup_ssl() {
    if [ "$SSL_ENABLED" != "true" ] || [ -z "$DOMAIN" ] || [ -z "$EMAIL" ]; then
        print_message "$YELLOW" "⚠️  SSL setup skipped. Set SSL_ENABLED=true, DOMAIN, and EMAIL to enable."
        return
    fi
    
    print_message "$BLUE" "🔒 Setting up SSL with Let's Encrypt..."
    
    ssh ${DROPLET_USER}@${DROPLET_IP} << EOF
        # Install Certbot if not present
        if ! command -v certbot &> /dev/null; then
            apt-get update
            apt-get install -y certbot python3-certbot-nginx
        fi
        
        # Get SSL certificate
        certbot --nginx -d ${DOMAIN} --non-interactive --agree-tos -m ${EMAIL}
        
        # Setup auto-renewal
        echo "0 12 * * * /usr/bin/certbot renew --quiet" | crontab -
EOF
    
    print_message "$GREEN" "✅ SSL setup completed."
}

# Function to run health check
health_check() {
    print_message "$BLUE" "🏥 Running health check..."
    
    # Wait for service to be ready
    sleep 10
    
    # Check if service is responding
    if curl -f -s -o /dev/null -w "%{http_code}" http://${DROPLET_IP}:8080/health | grep -q "200"; then
        print_message "$GREEN" "✅ Service is healthy and responding."
    else
        print_message "$RED" "❌ Service health check failed."
        print_message "$YELLOW" "   Check logs with: ssh ${DROPLET_USER}@${DROPLET_IP} 'docker-compose logs'"
        exit 1
    fi
}

# Function to setup monitoring
setup_monitoring() {
    print_message "$BLUE" "📊 Setting up monitoring..."
    
    ssh ${DROPLET_USER}@${DROPLET_IP} << 'EOF'
        # Create monitoring script
        cat > ~/deployments/monitor.sh << 'MONITOR'
#!/bin/bash
# Simple monitoring script

check_service() {
    if ! docker ps | grep -q rawrz-security-platform; then
        echo "Service is down! Attempting restart..."
        cd ~/deployments/rawrz-security-platform
        docker-compose up -d
    fi
}

check_disk_space() {
    USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [ $USAGE -gt 80 ]; then
        echo "Warning: Disk usage is above 80%"
        docker system prune -af
    fi
}

check_service
check_disk_space
MONITOR
        
        chmod +x ~/deployments/monitor.sh
        
        # Add to crontab
        (crontab -l 2>/dev/null; echo "*/5 * * * * ~/deployments/monitor.sh") | crontab -
EOF
    
    print_message "$GREEN" "✅ Monitoring setup completed."
}

# Function to rollback deployment
rollback() {
    print_message "$YELLOW" "⏪ Rolling back deployment..."
    
    ssh ${DROPLET_USER}@${DROPLET_IP} << EOF
        cd ~/deployments/${APP_NAME}
        
        # Rollback to previous version
        docker-compose down
        docker pull ${DOCKER_REPO}:previous
        docker tag ${DOCKER_REPO}:previous ${DOCKER_REPO}:${DOCKER_TAG}
        docker-compose up -d
EOF
    
    print_message "$GREEN" "✅ Rollback completed."
}

# Function to show deployment info
show_info() {
    print_message "$BLUE" "ℹ️  Deployment Information:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "App Name: ${APP_NAME}"
    echo "Docker Image: ${DOCKER_REPO}:${DOCKER_TAG}"
    echo "Droplet IP: ${DROPLET_IP}"
    echo "Service URL: http://${DROPLET_IP}:8080"
    if [ -n "$DOMAIN" ]; then
        echo "Domain: https://${DOMAIN}"
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Useful commands:"
    echo "  View logs: ssh ${DROPLET_USER}@${DROPLET_IP} 'docker-compose logs -f'"
    echo "  Restart: ssh ${DROPLET_USER}@${DROPLET_IP} 'cd ~/deployments/${APP_NAME} && docker-compose restart'"
    echo "  Stop: ssh ${DROPLET_USER}@${DROPLET_IP} 'cd ~/deployments/${APP_NAME} && docker-compose down'"
}

# Main deployment flow
main() {
    print_message "$GREEN" "🚀 Starting Digital Ocean Deployment for ${APP_NAME}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Parse command line arguments
    case "${1:-deploy}" in
        deploy)
            check_prerequisites
            build_docker_image
            push_to_registry
            deploy_to_droplet
            setup_ssl
            health_check
            setup_monitoring
            show_info
            print_message "$GREEN" "🎉 Deployment completed successfully!"
            ;;
        rollback)
            rollback
            ;;
        info)
            show_info
            ;;
        health)
            health_check
            ;;
        *)
            print_message "$RED" "Usage: $0 [deploy|rollback|info|health]"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"