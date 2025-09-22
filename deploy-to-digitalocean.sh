#!/bin/bash

# Digital Ocean App Platform Deployment Script
# This script prepares and deploys the app to Digital Ocean

echo "🚀 Digital Ocean Deployment Script"
echo "================================="

# Check if doctl is installed
if ! command -v doctl &> /dev/null; then
    echo "❌ doctl CLI not found. Please install it first:"
    echo "   brew install doctl (macOS)"
    echo "   snap install doctl (Linux)"
    echo "   Or download from: https://docs.digitalocean.com/reference/doctl/how-to/install/"
    exit 1
fi

# Check if authenticated
if ! doctl auth list &> /dev/null; then
    echo "❌ Not authenticated. Please run:"
    echo "   doctl auth init"
    exit 1
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}📋 Pre-deployment checklist:${NC}"

# 1. Check package.json
if [ -f "package.json" ]; then
    echo -e "${GREEN}✓${NC} package.json found"
else
    echo -e "${RED}✗${NC} package.json not found"
    exit 1
fi

# 2. Check main server file
if [ -f "server-optimized.js" ]; then
    echo -e "${GREEN}✓${NC} server-optimized.js found"
else
    echo -e "${RED}✗${NC} server-optimized.js not found"
    exit 1
fi

# 3. Check Dockerfile
if [ -f "Dockerfile" ]; then
    echo -e "${GREEN}✓${NC} Dockerfile found"
else
    echo -e "${RED}✗${NC} Dockerfile not found"
    exit 1
fi

# 4. Check app.yaml
if [ -f ".do/app.yaml" ]; then
    echo -e "${GREEN}✓${NC} .do/app.yaml found"
else
    echo -e "${RED}✗${NC} .do/app.yaml not found"
    exit 1
fi

echo ""
echo -e "${YELLOW}🔧 Deployment options:${NC}"
echo "1) Deploy using App Platform (Recommended)"
echo "2) Deploy using Droplet with Docker"
echo "3) Update existing app"
echo ""
read -p "Select option (1-3): " option

case $option in
    1)
        echo -e "${GREEN}Deploying to App Platform...${NC}"
        
        # Create the app
        echo "Creating app from spec..."
        doctl apps create --spec .do/app.yaml
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ App created successfully!${NC}"
            echo ""
            echo "Next steps:"
            echo "1. Go to https://cloud.digitalocean.com/apps"
            echo "2. Connect your GitHub repository"
            echo "3. The app will auto-deploy on push"
        else
            echo -e "${RED}✗ Deployment failed${NC}"
            exit 1
        fi
        ;;
        
    2)
        echo -e "${GREEN}Deploying to Droplet...${NC}"
        
        # Build Docker image
        echo "Building Docker image..."
        docker build -t rawrz-app:latest .
        
        # Tag for registry
        echo "Tagging image..."
        docker tag rawrz-app:latest registry.digitalocean.com/your-registry/rawrz-app:latest
        
        echo ""
        echo "To complete deployment:"
        echo "1. Create a container registry: doctl registry create your-registry"
        echo "2. Login: doctl registry login"
        echo "3. Push: docker push registry.digitalocean.com/your-registry/rawrz-app:latest"
        echo "4. Deploy to droplet or Kubernetes cluster"
        ;;
        
    3)
        echo -e "${GREEN}Updating existing app...${NC}"
        
        # List apps
        echo "Your apps:"
        doctl apps list
        
        read -p "Enter app ID to update: " app_id
        
        # Update app spec
        doctl apps update $app_id --spec .do/app.yaml
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ App updated successfully!${NC}"
        else
            echo -e "${RED}✗ Update failed${NC}"
            exit 1
        fi
        ;;
        
    *)
        echo -e "${RED}Invalid option${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}🎉 Deployment process completed!${NC}"
echo ""
echo "Monitor your app:"
echo "  doctl apps list"
echo "  doctl apps logs <app-id>"
echo ""
echo "Useful commands:"
echo "  View app: doctl apps get <app-id>"
echo "  Get URL: doctl apps list --format Name,LiveURL"
echo "  View logs: doctl apps logs <app-id> --follow"