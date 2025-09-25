#!/bin/bash

# RawrZ Security Platform - Quick Deploy Script
# One-command deployment to DigitalOcean

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════════╗
║                     RawrZ Security Platform                                 ║
║                      Quick Deploy Script                                    ║
║                                                                              ║
║  🚀 Deploy Full Branch to DigitalOcean in One Command                       ║
║  📊 All Files Preserved + Complete Monitoring Setup                         ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Get user preferences
echo -e "${YELLOW}🔧 Configuration Options:${NC}"
echo ""

read -p "Enter your domain name (optional, press Enter to skip): " DOMAIN
read -p "Enter email for SSL certificate (optional, press Enter to skip): " SSL_EMAIL
read -p "Backup existing installation if found? (y/N): " BACKUP_EXISTING

# Convert to lowercase
BACKUP_EXISTING=$(echo "$BACKUP_EXISTING" | tr '[:upper:]' '[:lower:]')

# Set backup flag
if [[ "$BACKUP_EXISTING" == "y" || "$BACKUP_EXISTING" == "yes" ]]; then
    BACKUP_FLAG="--backup-existing"
else
    BACKUP_FLAG=""
fi

echo ""
echo -e "${GREEN}🚀 Starting deployment with the following configuration:${NC}"
echo "   • Domain: ${DOMAIN:-"Not specified"}"
echo "   • SSL Email: ${SSL_EMAIL:-"Not specified"}"
echo "   • Backup Existing: ${BACKUP_EXISTING:-"No"}"
echo ""

read -p "Continue with deployment? (Y/n): " CONFIRM
CONFIRM=$(echo "$CONFIRM" | tr '[:upper:]' '[:lower:]')

if [[ "$CONFIRM" == "n" || "$CONFIRM" == "no" ]]; then
    echo -e "${YELLOW}Deployment cancelled.${NC}"
    exit 0
fi

echo ""
echo -e "${BLUE}📥 Downloading deployment script...${NC}"

# Download the main deployment script
wget -q https://raw.githubusercontent.com/ItsMehRAWRXD/itsmehrawrxd/main/deploy-digitalocean-complete.sh -O deploy-digitalocean-complete.sh
chmod +x deploy-digitalocean-complete.sh

echo -e "${GREEN}✅ Deployment script downloaded${NC}"

echo ""
echo -e "${BLUE}🚀 Starting deployment...${NC}"
echo ""

# Build command arguments
CMD_ARGS=""

if [[ -n "$DOMAIN" ]]; then
    CMD_ARGS="$CMD_ARGS --domain $DOMAIN"
fi

if [[ -n "$SSL_EMAIL" ]]; then
    CMD_ARGS="$CMD_ARGS --ssl-email $SSL_EMAIL"
fi

if [[ -n "$BACKUP_FLAG" ]]; then
    CMD_ARGS="$CMD_ARGS $BACKUP_FLAG"
fi

# Run the deployment script
./deploy-digitalocean-complete.sh $CMD_ARGS

echo ""
echo -e "${GREEN}🎉 Quick deployment completed!${NC}"
echo ""
echo -e "${BLUE}📊 Next Steps:${NC}"
echo "   1. Access your platform at: http://$(curl -s http://checkip.amazonaws.com/ 2>/dev/null || hostname -I | awk '{print $1}'):3000"
echo "   2. Review the deployment guide: DIGITALOCEAN-DEPLOYMENT-GUIDE.md"
echo "   3. Check monitoring setup: MONITORING-MAINTENANCE-GUIDE.md"
echo "   4. Configure your domain DNS if applicable"
echo ""
echo -e "${YELLOW}⚠️ Important:${NC}"
echo "   • All files have been preserved"
echo "   • Monitoring is configured and running"
echo "   • Automated backups are scheduled"
echo "   • SSL is configured if domain was provided"
echo ""
echo -e "${GREEN}🚀 Your RawrZ Security Platform is ready!${NC}"