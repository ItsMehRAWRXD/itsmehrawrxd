#!/bin/bash

# RawrZ Security Platform - Local Deployment Test
# This script tests the optimized deployment locally before pushing to DigitalOcean

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== RawrZ Security Platform - Local Deployment Test ===${NC}"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed${NC}"
    echo "Please install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}Error: Docker Compose is not installed${NC}"
    echo "Please install Docker Compose first: https://docs.docker.com/compose/install/"
    exit 1
fi

echo -e "${GREEN}✓ Docker and Docker Compose are installed${NC}"

# Check if required files exist
echo -e "${YELLOW}Checking required files...${NC}"

required_files=(
    "package.json"
    "package-docker.json"
    "finished/online-deployment/api-server-no-cli.js"
    "Dockerfile.optimized"
    "docker-compose.optimized.yml"
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

echo -e "${GREEN}✓ All required files found${NC}"

# Create public directory if it doesn't exist
if [ ! -d "public" ]; then
    echo -e "${YELLOW}Creating public directory...${NC}"
    mkdir -p public
    echo '<html><body><h1>RawrZ Security Platform</h1><p>API is running on port 3000</p></body></html>' > public/index.html
    echo -e "${GREEN}✓ Created public directory${NC}"
fi

# Stop any existing containers
echo -e "${YELLOW}Stopping any existing containers...${NC}"
docker-compose -f docker-compose.optimized.yml down 2>/dev/null || true

# Build the optimized image
echo -e "${YELLOW}Building optimized Docker image...${NC}"
docker-compose -f docker-compose.optimized.yml build

# Start the application
echo -e "${YELLOW}Starting application...${NC}"
docker-compose -f docker-compose.optimized.yml up -d

# Wait for application to start
echo -e "${YELLOW}Waiting for application to start...${NC}"
sleep 30

# Test the application
echo -e "${YELLOW}Testing application...${NC}"

# Test health endpoint
if curl -f http://localhost:3000/api/health >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Health check passed${NC}"
else
    echo -e "${RED}✗ Health check failed${NC}"
    echo "Checking logs..."
    docker-compose -f docker-compose.optimized.yml logs
    exit 1
fi

# Test main endpoint
if curl -f http://localhost:3000 >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Main endpoint accessible${NC}"
else
    echo -e "${RED}✗ Main endpoint failed${NC}"
fi

# Check container resource usage
echo -e "${YELLOW}Checking container resource usage...${NC}"
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}" rawrz-security-platform

# Test for 60 seconds to ensure stability
echo -e "${YELLOW}Testing stability for 60 seconds...${NC}"
for i in {1..12}; do
    if curl -f http://localhost:3000/api/health >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Test $i/12 passed${NC}"
    else
        echo -e "${RED}✗ Test $i/12 failed${NC}"
        docker-compose -f docker-compose.optimized.yml logs --tail=20
        exit 1
    fi
    sleep 5
done

echo ""
echo -e "${GREEN}🎉 Local deployment test completed successfully!${NC}"
echo -e "${BLUE}Your application is running at: http://localhost:3000${NC}"
echo -e "${BLUE}Health check: http://localhost:3000/api/health${NC}"
echo ""
echo -e "${YELLOW}Container Status:${NC}"
docker-compose -f docker-compose.optimized.yml ps

echo ""
echo -e "${YELLOW}To stop the test deployment:${NC}"
echo -e "${BLUE}docker-compose -f docker-compose.optimized.yml down${NC}"
echo ""
echo -e "${GREEN}✓ Ready for DigitalOcean deployment!${NC}"