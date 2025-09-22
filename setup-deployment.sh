#!/bin/bash

# RawrZ Security Platform - Deployment Setup Script
# This script helps you set up and deploy to DigitalOcean

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== RawrZ Security Platform - Deployment Setup ===${NC}"
echo ""

# Check if DigitalOcean token is provided
if [ -z "$DO_TOKEN" ]; then
    echo -e "${YELLOW}DigitalOcean API Token Required${NC}"
    echo ""
    echo "To get your DigitalOcean API token:"
    echo "1. Go to https://cloud.digitalocean.com/account/api/tokens"
    echo "2. Click 'Generate New Token'"
    echo "3. Give it a name like 'RawrZ Deployment'"
    echo "4. Select 'Full Access' scope"
    echo "5. Copy the token"
    echo ""
    echo "Then run:"
    echo -e "${GREEN}export DO_TOKEN=your_token_here${NC}"
    echo -e "${GREEN}./setup-deployment.sh${NC}"
    echo ""
    exit 1
fi

echo -e "${GREEN}✓ DigitalOcean token found${NC}"

# Check if required files exist
echo -e "${YELLOW}Checking required files...${NC}"

required_files=(
    "package.json"
    "package-docker.json"
    "finished/online-deployment/api-server-no-cli.js"
    "deploy-digitalocean.sh"
)

missing_files=()
for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        missing_files+=("$file")
    else
        echo -e "${GREEN}✓ $file${NC}"
    fi
done

if [ ${#missing_files[@]} -ne 0 ]; then
    echo -e "${RED}Missing required files:${NC}"
    for file in "${missing_files[@]}"; do
        echo -e "${RED}  ✗ $file${NC}"
    done
    exit 1
fi

echo ""
echo -e "${GREEN}✓ All required files found${NC}"

# Check if public directory exists
if [ ! -d "public" ]; then
    echo -e "${YELLOW}Creating public directory...${NC}"
    mkdir -p public
    echo -e "${GREEN}✓ Created public directory${NC}"
fi

# Display deployment information
echo ""
echo -e "${BLUE}=== Deployment Information ===${NC}"
echo -e "${YELLOW}Droplet Configuration:${NC}"
echo "  • Name: rawrz-security-platform"
echo "  • Size: s-1vcpu-1gb (1GB RAM, 1 vCPU)"
echo "  • Region: nyc3 (New York)"
echo "  • Image: Docker 20.04"
echo "  • Cost: ~$5/month"
echo ""
echo -e "${YELLOW}Application Configuration:${NC}"
echo "  • Memory limit: 512MB"
echo "  • CPU limit: 0.5 cores"
echo "  • Health checks enabled"
echo "  • Non-root user for security"
echo "  • Optimized Docker image"
echo ""

# Ask for confirmation
read -p "Do you want to proceed with the deployment? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Deployment cancelled.${NC}"
    exit 0
fi

echo ""
echo -e "${YELLOW}Starting deployment...${NC}"
echo "This will:"
echo "  1. Create a new DigitalOcean droplet"
echo "  2. Install Docker and dependencies"
echo "  3. Deploy the optimized application"
echo "  4. Configure firewall and nginx"
echo ""

# Run the deployment script
./deploy-digitalocean.sh

echo ""
echo -e "${GREEN}🎉 Setup completed successfully!${NC}"
echo -e "${BLUE}Your RawrZ Security Platform is now deployed and optimized to prevent container termination.${NC}"