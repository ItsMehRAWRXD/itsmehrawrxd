#!/bin/bash

# Deploy optimized RawrZ app to existing droplet
set -e

DROPLET_IP="167.71.161.107"
DROPLET_NAME="rawrz-optimized-deploy"

echo "=== Deploying Optimized RawrZ Security Platform ==="
echo "Droplet IP: $DROPLET_IP"
echo ""

# Create a deployment package
echo "📦 Creating deployment package..."
tar -czf rawrz-optimized.tar.gz \
    finished/online-deployment/api-server-no-cli.js \
    package.json \
    package-docker.json \
    public/ \
    Dockerfile.optimized \
    docker-compose.optimized.yml \
    nginx/nginx.conf

echo "✅ Deployment package created"

# Copy files to droplet
echo "📤 Copying files to droplet..."
scp -o StrictHostKeyChecking=no rawrz-optimized.tar.gz root@$DROPLET_IP:/tmp/

echo "✅ Files copied to droplet"

# Deploy on the droplet
echo "🚀 Deploying on droplet..."
ssh -o StrictHostKeyChecking=no root@$DROPLET_IP << 'EOF'
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
    
    # Extract deployment package
    tar -xzf /tmp/rawrz-optimized.tar.gz
    
    # Stop any existing containers
    docker-compose down 2>/dev/null || true
    docker stop rawrz-app 2>/dev/null || true
    docker rm rawrz-app 2>/dev/null || true
    
    # Configure firewall
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 3000/tcp
    ufw --force enable
    
    # Build and start the optimized application
    echo "Building optimized Docker image..."
    docker-compose build
    
    echo "Starting optimized application..."
    docker-compose up -d
    
    # Wait for application to start
    echo "Waiting for application to start..."
    sleep 30
    
    # Test the application
    if curl -f http://localhost:3000/api/health; then
        echo "✅ Application started successfully!"
        echo "🌐 App is available at: http://$(curl -s http://checkip.amazonaws.com/):3000"
        echo "📊 Health check: http://$(curl -s http://checkip.amazonaws.com/):3000/api/health"
    else
        echo "❌ Application health check failed. Checking logs..."
        docker-compose logs --tail=20
    fi
EOF

echo ""
echo "🎉 Deployment completed!"
echo "🌐 Your optimized RawrZ Security Platform is available at:"
echo "   http://$DROPLET_IP:3000"
echo "📊 Health check: http://$DROPLET_IP:3000/api/health"
echo ""
echo "📝 Management commands:"
echo "  SSH: ssh root@$DROPLET_IP"
echo "  Logs: ssh root@$DROPLET_IP 'cd /opt/rawrz-platform && docker-compose logs'"
echo "  Restart: ssh root@$DROPLET_IP 'cd /opt/rawrz-platform && docker-compose restart'"
echo ""
echo "✅ Container termination issues should now be resolved!"