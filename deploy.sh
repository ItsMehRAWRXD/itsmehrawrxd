#!/bin/bash

# RawrZ Security Platform Deployment Script
# This script handles deployment of the RawrZ Security Platform

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="rawrz-security-platform"
DOCKER_COMPOSE_FILE="docker-compose.yml"
ENV_FILE=".env"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    log_success "Docker and Docker Compose are installed"
}

# Check if .env file exists
check_env_file() {
    if [ ! -f "$ENV_FILE" ]; then
        log_warning ".env file not found. Creating from example..."
        if [ -f "env.example" ]; then
            cp env.example .env
            log_warning "Please edit .env file with your configuration before continuing"
            log_warning "Press Enter to continue after editing .env file..."
            read
        else
            log_error "env.example file not found. Please create .env file manually."
            exit 1
        fi
    fi
    log_success "Environment file found"
}

# Create necessary directories
create_directories() {
    log_info "Creating necessary directories..."
    mkdir -p data uploads logs ssl
    log_success "Directories created"
}

# Generate SSL certificates (self-signed for development)
generate_ssl_certificates() {
    if [ ! -f "ssl/cert.pem" ] || [ ! -f "ssl/key.pem" ]; then
        log_info "Generating self-signed SSL certificates..."
        openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
        log_success "SSL certificates generated"
    else
        log_success "SSL certificates already exist"
    fi
}

# Build and start services
deploy_services() {
    log_info "Building and starting services..."
    docker-compose -f $DOCKER_COMPOSE_FILE down --remove-orphans
    docker-compose -f $DOCKER_COMPOSE_FILE build --no-cache
    docker-compose -f $DOCKER_COMPOSE_FILE up -d
    log_success "Services deployed"
}

# Wait for services to be ready
wait_for_services() {
    log_info "Waiting for services to be ready..."
    
    # Wait for main application
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f http://localhost:8080/api/status &> /dev/null; then
            log_success "RawrZ Security Platform is ready"
            break
        fi
        
        if [ $attempt -eq $max_attempts ]; then
            log_error "RawrZ Security Platform failed to start within timeout"
            exit 1
        fi
        
        log_info "Waiting for RawrZ Security Platform... (attempt $attempt/$max_attempts)"
        sleep 10
        ((attempt++))
    done
}

# Run health checks
run_health_checks() {
    log_info "Running health checks..."
    
    # Check main application
    if curl -f http://localhost:8080/api/status &> /dev/null; then
        log_success "Main application health check passed"
    else
        log_error "Main application health check failed"
        exit 1
    fi
    
    # Check database
    if docker-compose -f $DOCKER_COMPOSE_FILE exec -T postgres pg_isready -U rawrz &> /dev/null; then
        log_success "Database health check passed"
    else
        log_error "Database health check failed"
        exit 1
    fi
    
    # Check Redis
    if docker-compose -f $DOCKER_COMPOSE_FILE exec -T redis redis-cli ping &> /dev/null; then
        log_success "Redis health check passed"
    else
        log_error "Redis health check failed"
        exit 1
    fi
}

# Show deployment information
show_deployment_info() {
    log_success "Deployment completed successfully!"
    echo
    echo "RawrZ Security Platform is now running:"
    echo "  - Web Interface: https://localhost"
    echo "  - API Endpoint: https://localhost/api/status"
    echo "  - Health Check: https://localhost/health"
    echo
    echo "To view logs:"
    echo "  docker-compose -f $DOCKER_COMPOSE_FILE logs -f"
    echo
    echo "To stop services:"
    echo "  docker-compose -f $DOCKER_COMPOSE_FILE down"
    echo
    echo "To restart services:"
    echo "  docker-compose -f $DOCKER_COMPOSE_FILE restart"
}

# Main deployment function
main() {
    log_info "Starting RawrZ Security Platform deployment..."
    
    check_docker
    check_env_file
    create_directories
    generate_ssl_certificates
    deploy_services
    wait_for_services
    run_health_checks
    show_deployment_info
}

# Handle script arguments
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "stop")
        log_info "Stopping RawrZ Security Platform..."
        docker-compose -f $DOCKER_COMPOSE_FILE down
        log_success "Services stopped"
        ;;
    "restart")
        log_info "Restarting RawrZ Security Platform..."
        docker-compose -f $DOCKER_COMPOSE_FILE restart
        log_success "Services restarted"
        ;;
    "logs")
        docker-compose -f $DOCKER_COMPOSE_FILE logs -f
        ;;
    "status")
        docker-compose -f $DOCKER_COMPOSE_FILE ps
        ;;
    "clean")
        log_info "Cleaning up RawrZ Security Platform..."
        docker-compose -f $DOCKER_COMPOSE_FILE down -v --remove-orphans
        docker system prune -f
        log_success "Cleanup completed"
        ;;
    *)
        echo "Usage: $0 {deploy|stop|restart|logs|status|clean}"
        echo
        echo "Commands:"
        echo "  deploy  - Deploy the RawrZ Security Platform (default)"
        echo "  stop    - Stop all services"
        echo "  restart - Restart all services"
        echo "  logs    - View service logs"
        echo "  status  - Show service status"
        echo "  clean   - Stop services and clean up volumes"
        exit 1
        ;;
esac