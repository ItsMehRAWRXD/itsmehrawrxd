#!/bin/bash

# RawrZ Enterprise Deployment Script
set -e

echo "🚀 Starting RawrZ Enterprise Deployment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ENVIRONMENT=${1:-production}
DOMAIN=${2:-localhost}
EMAIL=${3:-admin@rawrz.com}

echo -e "${BLUE}📋 Deployment Configuration:${NC}"
echo "Environment: $ENVIRONMENT"
echo "Domain: $DOMAIN"
echo "Email: $EMAIL"

# Check prerequisites
echo -e "${YELLOW}🔍 Checking prerequisites...${NC}"

if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed${NC}"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ Docker Compose is not installed${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Prerequisites check passed${NC}"

# Create environment file
echo -e "${YELLOW}📝 Creating environment configuration...${NC}"
cat > .env << EOF
# RawrZ Enterprise Environment
NODE_ENV=production
DOMAIN=$DOMAIN
EMAIL=$EMAIL

# Database
POSTGRES_PASSWORD=$(openssl rand -base64 32)
POSTGRES_DB=rawrz_enterprise
POSTGRES_USER=rawrz

# Redis
REDIS_PASSWORD=$(openssl rand -base64 32)

# Monitoring
GRAFANA_PASSWORD=$(openssl rand -base64 16)

# SSL
SSL_EMAIL=$EMAIL
EOF

echo -e "${GREEN}✅ Environment file created${NC}"

# Generate SSL certificates
echo -e "${YELLOW}🔐 Generating SSL certificates...${NC}"
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout nginx/ssl/key.pem \
    -out nginx/ssl/cert.pem \
    -subj "/C=US/ST=State/L=City/O=RawrZ/CN=$DOMAIN"

echo -e "${GREEN}✅ SSL certificates generated${NC}"

# Start services
echo -e "${YELLOW}🐳 Starting enterprise services...${NC}"
docker-compose -f docker-compose.enterprise.yml up -d

# Wait for services to be ready
echo -e "${YELLOW}⏳ Waiting for services to be ready...${NC}"
sleep 30

# Health check
echo -e "${YELLOW}🏥 Performing health checks...${NC}"
if curl -f http://localhost:8080/health; then
    echo -e "${GREEN}✅ RawrZ application is healthy${NC}"
else
    echo -e "${RED}❌ RawrZ application health check failed${NC}"
    exit 1
fi

# Display deployment information
echo -e "${GREEN}🎉 RawrZ Enterprise Deployment Complete!${NC}"
echo ""
echo -e "${BLUE}📊 Service URLs:${NC}"
echo "RawrZ Application: https://$DOMAIN"
echo "Grafana Dashboard: http://$DOMAIN:3000"
echo "Prometheus Metrics: http://$DOMAIN:9090"
echo "Kibana Logs: http://$DOMAIN:5601"
echo ""
echo -e "${BLUE}🔑 Default Credentials:${NC}"
echo "Grafana Admin: admin / $(grep GRAFANA_PASSWORD .env | cut -d'=' -f2)"
echo ""
echo -e "${YELLOW}📝 Next Steps:${NC}"
echo "1. Configure your domain DNS to point to this server"
echo "2. Update SSL certificates with Let's Encrypt if needed"
echo "3. Configure monitoring alerts in Grafana"
echo "4. Set up backup schedules"
echo "5. Review security settings"
echo ""
echo -e "${GREEN}🚀 RawrZ Enterprise is ready for production use!${NC}"
