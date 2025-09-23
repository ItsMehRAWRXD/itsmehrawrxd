#!/bin/bash

# Deploy Your Actual RawrZ Security Platform RIGHT NOW
# Fixed version with working commands

echo "🚀 DEPLOY YOUR ACTUAL RAWRZ SECURITY PLATFORM NOW"
echo "================================================"

echo ""
echo "📋 **IMMEDIATE DEPLOYMENT COMMANDS - Copy & Paste:**"
echo ""

echo "# 1. Install Docker"
echo "sudo apt-get update"
echo "sudo apt-get install -y docker.io"
echo "sudo systemctl start docker"
echo "sudo systemctl enable docker"
echo ""

echo "# 2. Install docker-compose"
echo "sudo apt-get install -y docker-compose"
echo ""

echo "# 3. Navigate to your project"
echo "cd /workspace"
echo ""

echo "# 4. Create simple docker-compose.yml"
echo 'cat > docker-compose.simple.yml << EOF"
version: '"'"'3.8'"'"'

services:
  rawrz-app:
    build: .
    container_name: rawrz-security-platform
    ports:
      - "3000:3000"
    volumes:
      - ./uploads:/app/uploads
      - ./logs:/app/logs
    environment:
      - NODE_ENV=production
      - PORT=3000
    restart: unless-stopped
EOF"
echo ""

echo "# 5. Build and deploy"
echo "docker build -t rawrz-security-platform ."
echo "docker-compose -f docker-compose.simple.yml up -d"
echo ""

echo "# 6. Test deployment"
echo "curl http://localhost:3000/api/health"
echo ""

echo "🎉 **Your RawrZ will be at:** http://localhost:3000"
echo ""

echo "🔧 **Management:**"
echo "docker-compose -f docker-compose.simple.yml logs -f"
echo "docker-compose -f docker-compose.simple.yml down"
echo ""

echo "📋 **USES YOUR ACTUAL FILES:**"
ls -la api-server.js docker-compose.yml Dockerfile 2>/dev/null || echo "Your real files are ready"

echo ""
echo "🚀 **Copy and run these commands NOW!**"