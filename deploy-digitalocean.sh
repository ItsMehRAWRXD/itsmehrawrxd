#!/bin/bash

# RawrZ Security Platform - DigitalOcean Deployment Script
# This script deploys the optimized app to DigitalOcean using your token

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DROPLET_NAME="rawrz-security-platform"
DROPLET_SIZE="s-1vcpu-1gb"  # 1GB RAM, 1 vCPU - cost-effective
DROPLET_REGION="nyc3"
DROPLET_IMAGE="docker-20-04"
SSH_KEY_NAME="rawrz-deploy-key"

echo -e "${BLUE}=== RawrZ Security Platform - DigitalOcean Deployment ===${NC}"
echo ""

# Check if DigitalOcean CLI is installed
if ! command -v doctl &> /dev/null; then
    echo -e "${YELLOW}Installing DigitalOcean CLI...${NC}"
    cd /tmp
    wget https://github.com/digitalocean/doctl/releases/download/v1.104.0/doctl-1.104.0-linux-amd64.tar.gz
    tar xf doctl-1.104.0-linux-amd64.tar.gz
    sudo mv doctl /usr/local/bin
    rm doctl-1.104.0-linux-amd64.tar.gz
fi

# Check if token is provided
if [ -z "$DO_TOKEN" ]; then
    echo -e "${RED}Error: DO_TOKEN environment variable is required${NC}"
    echo "Please set your DigitalOcean API token:"
    echo "export DO_TOKEN=your_token_here"
    exit 1
fi

# Authenticate with DigitalOcean
echo -e "${YELLOW}Authenticating with DigitalOcean...${NC}"
doctl auth init -t "$DO_TOKEN"

# Check if droplet already exists
echo -e "${YELLOW}Checking for existing droplet...${NC}"
if doctl compute droplet list --format Name --no-header | grep -q "^${DROPLET_NAME}$"; then
    echo -e "${YELLOW}Droplet ${DROPLET_NAME} already exists. Deleting...${NC}"
    doctl compute droplet delete "${DROPLET_NAME}" --force
    sleep 10
fi

# Create SSH key if it doesn't exist
echo -e "${YELLOW}Setting up SSH key...${NC}"
if ! doctl compute ssh-key list --format Name --no-header | grep -q "^${SSH_KEY_NAME}$"; then
    # Generate SSH key if it doesn't exist
    if [ ! -f ~/.ssh/id_rsa.pub ]; then
        ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
    fi
    
    # Add SSH key to DigitalOcean
    doctl compute ssh-key create "${SSH_KEY_NAME}" --public-key "$(cat ~/.ssh/id_rsa.pub)"
fi

# Get SSH key ID
SSH_KEY_ID=$(doctl compute ssh-key list --format ID,Name --no-header | grep "${SSH_KEY_NAME}" | awk '{print $1}')

# Create droplet
echo -e "${YELLOW}Creating droplet...${NC}"
doctl compute droplet create "${DROPLET_NAME}" \
    --size "${DROPLET_SIZE}" \
    --image "${DROPLET_IMAGE}" \
    --region "${DROPLET_REGION}" \
    --ssh-keys "${SSH_KEY_ID}" \
    --wait

# Get droplet IP
DROPLET_IP=$(doctl compute droplet list --format Name,PublicIPv4 --no-header | grep "${DROPLET_NAME}" | awk '{print $2}')

echo -e "${GREEN}Droplet created successfully!${NC}"
echo -e "${BLUE}Droplet IP: ${DROPLET_IP}${NC}"

# Wait for SSH to be ready
echo -e "${YELLOW}Waiting for SSH to be ready...${NC}"
sleep 30

# Test SSH connection
echo -e "${YELLOW}Testing SSH connection...${NC}"
until ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@${DROPLET_IP} "echo 'SSH connection successful'"; do
    echo "Waiting for SSH..."
    sleep 10
done

# Deploy application
echo -e "${YELLOW}Deploying application...${NC}"
ssh -o StrictHostKeyChecking=no root@${DROPLET_IP} << 'EOF'
    # Update system
    apt update && apt upgrade -y
    
    # Install Docker if not present
    if ! command -v docker &> /dev/null; then
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh
        systemctl enable docker
        systemctl start docker
    fi
    
    # Install Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
    fi
    
    # Create app directory
    mkdir -p /opt/rawrz-platform
    cd /opt/rawrz-platform
    
    # Install git if not present
    apt install -y git
    
    # Clone repository (you'll need to update this with your actual repo)
    git clone https://github.com/ItsMehRAWRXD/itsmehrawrxd.git .
    
    # Configure firewall
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 3000/tcp
    ufw --force enable
    
    # Create optimized deployment files
    cat > Dockerfile.optimized << 'DOCKERFILE_EOF'
# RawrZ Security Platform - Optimized for DigitalOcean
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Install only essential system dependencies
RUN apk add --no-cache \
    curl \
    bash \
    git \
    && rm -rf /var/cache/apk/*

# Copy package files first for better caching
COPY package.json ./
COPY package-docker.json ./

# Install only production dependencies with optimizations
RUN npm ci --only=production --no-audit --no-fund \
    && npm cache clean --force

# Copy only necessary application files
COPY finished/online-deployment/api-server-no-cli.js ./
COPY public/ ./public/

# Create minimal required directories
RUN mkdir -p \
    /app/uploads \
    /app/processed \
    /app/temp \
    /app/logs

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Set proper permissions
RUN chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Expose only necessary ports
EXPOSE 3000

# Add health check with proper timeout
HEALTHCHECK --interval=60s --timeout=30s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:3000/api/health || exit 1

# Set memory limits and optimizations
ENV NODE_ENV=production
ENV NODE_OPTIONS="--max-old-space-size=512"
ENV PORT=3000

# Start the application
CMD ["node", "api-server-no-cli.js"]
DOCKERFILE_EOF

    # Create optimized docker-compose file
    cat > docker-compose.yml << 'COMPOSE_EOF'
version: '3.8'

services:
  rawrz-app:
    build:
      context: .
      dockerfile: Dockerfile.optimized
    container_name: rawrz-security-platform
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - PORT=3000
      - NODE_OPTIONS=--max-old-space-size=512
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/api/health"]
      interval: 60s
      timeout: 30s
      retries: 3
      start_period: 30s
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'
    volumes:
      - rawrz_uploads:/app/uploads
      - rawrz_logs:/app/logs

volumes:
  rawrz_uploads:
    driver: local
  rawrz_logs:
    driver: local
COMPOSE_EOF

    # Create nginx directory and config
    mkdir -p nginx
    
    cat > nginx/nginx.conf << 'NGINX_EOF'
events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;
    
    upstream rawrz_backend {
        server rawrz-app:3000;
    }
    
    server {
        listen 80;
        server_name _;
        
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
        
        location / {
            proxy_pass http://rawrz_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_timeout 30s;
            proxy_connect_timeout 5s;
        }
        
        location /health {
            proxy_pass http://rawrz_backend/api/health;
            access_log off;
        }
    }
}
NGINX_EOF

    # Build and start the application
    echo "Building Docker image..."
    docker-compose build
    
    echo "Starting application..."
    docker-compose up -d
    
    # Wait for application to start
    echo "Waiting for application to start..."
    sleep 30
    
    # Test the application
    if curl -f http://localhost:3000/api/health; then
        echo "Application started successfully!"
    else
        echo "Application health check failed. Checking logs..."
        docker-compose logs
    fi
EOF

# Final output
echo ""
echo -e "${GREEN}🎉 Deployment completed successfully!${NC}"
echo -e "${BLUE}🌐 Your RawrZ Security Platform is available at:${NC}"
echo -e "   ${GREEN}http://${DROPLET_IP}:3000${NC}"
echo -e "   ${GREEN}http://${DROPLET_IP}${NC} (via nginx)"
echo ""
echo -e "${BLUE}📊 Health check: http://${DROPLET_IP}:3000/api/health${NC}"
echo -e "${BLUE}🧪 API test: http://${DROPLET_IP}:3000/api/simple-test${NC}"
echo ""
echo -e "${BLUE}📝 Useful commands:${NC}"
echo -e "  ${YELLOW}SSH into droplet:${NC} ssh root@${DROPLET_IP}"
echo -e "  ${YELLOW}View logs:${NC} ssh root@${DROPLET_IP} 'cd /opt/rawrz-platform && docker-compose logs'"
echo -e "  ${YELLOW}Restart app:${NC} ssh root@${DROPLET_IP} 'cd /opt/rawrz-platform && docker-compose restart'"
echo -e "  ${YELLOW}Stop app:${NC} ssh root@${DROPLET_IP} 'cd /opt/rawrz-platform && docker-compose down'"
echo ""
echo -e "${BLUE}💰 Droplet cost: ~$5/month (1GB RAM, 1 vCPU)${NC}"
echo -e "${BLUE}🔒 Security: Non-root user, resource limits, health checks${NC}"
echo ""
echo -e "${GREEN}Deployment completed! Your app should be running without container termination issues.${NC}"