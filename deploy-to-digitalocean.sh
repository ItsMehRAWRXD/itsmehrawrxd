#!/bin/bash

# RawrZ Security Platform - Digital Ocean Deployment Script

echo "🚀 RawrZ Security Platform - Digital Ocean Deployment"
echo "=================================================="

# Check if required files exist
if [[ ! -f "Dockerfile" ]]; then
    echo "❌ Dockerfile not found!"
    exit 1
fi

if [[ ! -f "api-server.js" ]]; then
    echo "❌ api-server.js not found!"
    exit 1
fi

if [[ ! -f "package-docker.json" ]]; then
    echo "❌ package-docker.json not found!"
    exit 1
fi

echo "✅ All required files found"

# Build the Docker image
echo "🏗️  Building Docker image..."
docker build -t rawrz-security-platform:latest .

if [[ $? -ne 0 ]]; then
    echo "❌ Docker build failed!"
    exit 1
fi

echo "✅ Docker image built successfully"

# Check if Digital Ocean CLI is installed
if ! command -v doctl &> /dev/null; then
    echo "⚠️  doctl (Digital Ocean CLI) not found"
    echo "📋 Please install doctl first:"
    echo "   curl -sL https://github.com/digitalocean/doctl/releases/latest/download/doctl-linux-amd64.tar.gz | tar -xzf - && sudo mv doctl /usr/local/bin/"
    echo ""
    echo "🔑 Then authenticate with your token:"
    echo "   doctl auth init"
    exit 1
fi

# Check if user is authenticated
if ! doctl account get &> /dev/null; then
    echo "❌ Digital Ocean authentication required"
    echo "🔑 Please run: doctl auth init"
    exit 1
fi

echo "✅ Digital Ocean CLI authenticated"

# Create app specification
echo "📝 Creating app specification..."
cat > do-app.yaml << EOF
name: rawrz-security-platform
region: nyc3
services:
  - name: web
    dockerfile_path: Dockerfile
    source_dir: .
    github:
      repo: # Add your GitHub repo here
      branch: main
    envs:
      - key: NODE_ENV
        value: production
      - key: PORT
        value: "3000"
    health_check:
      http_path: /api/health
    instance_count: 1
    instance_size_slug: basic-xxs
    http_port: 3000
EOF

echo "✅ App specification created"

# Deploy to Digital Ocean
echo "🚀 Deploying to Digital Ocean..."
doctl apps create --spec do-app.yaml

if [[ $? -eq 0 ]]; then
    echo "✅ Deployment successful!"
    echo "🌐 Your app will be available at: https://your-app-name.ondigitalocean.app"
    echo "📊 Health check endpoint: https://your-app-name.ondigitalocean.app/api/health"
else
    echo "❌ Deployment failed!"
    echo "📋 Troubleshooting tips:"
    echo "   1. Check your Digital Ocean token permissions"
    echo "   2. Ensure your account has sufficient credits"
    echo "   3. Verify the app specification is correct"
    echo "   4. Check Digital Ocean console for detailed error messages"
fi

# Cleanup
rm -f do-app.yaml