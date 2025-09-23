#!/bin/bash

# Deploy RawrZ and n0mn0m to Digital Ocean from Local Machine
# No web panels needed - everything via command line

echo "🚀 Local to Digital Ocean Deployment (No Web Panels Needed)"
echo "=========================================================="

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_info() {
    echo -e "${BLUE}📋 $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info "Digital Ocean Local Deployment (CLI Only)"
echo "========================================="

echo ""
echo "📋 **Copy and paste these commands into your local terminal:**"
echo ""

echo "# 1. Install doctl (if not installed)"
echo "curl -sL https://github.com/digitalocean/doctl/releases/latest/download/doctl-linux-amd64.tar.gz | tar -xzf - && sudo mv doctl /usr/local/bin/"
echo ""

echo "# 2. Get your Digital Ocean token from: https://cloud.digitalocean.com/account/api/tokens"
echo "#    Then authenticate:"
echo "doctl auth init"
echo ""

echo "# 3. Verify authentication works"
echo "doctl account get"
echo ""

echo "# 4. Deploy RawrZ Security Platform"
echo "doctl apps create --spec do-app-rawrz.yaml"
echo ""

echo "# 5. Deploy n0mn0m Quantum System"
echo "doctl apps create --spec do-app-n0mn0m.yaml"
echo ""

echo "# 6. List your deployed apps"
echo "doctl apps list"
echo ""

echo "🎉 **After deployment, your apps will be available at:**"
echo "   RawrZ: https://[rawrz-app-url].ondigitalocean.app"
echo "   n0mn0m: https://[n0mn0m-app-url].ondigitalocean.app"
echo ""

echo "🔧 **Test your deployments (replace [app-url] with actual URL):"
echo ""
echo "# RawrZ Health Check"
echo "curl https://[rawrz-app-url].ondigitalocean.app/api/health"
echo ""

echo "# n0mn0m Health Check"
echo "curl https://[n0mn0m-app-url].ondigitalocean.app/api/health"
echo ""

echo "# Expected response:"
echo '{"success": true, "status": "healthy", "features": 72}'
echo ""

echo "📊 **Management commands (run locally):"
echo ""
echo "# View logs"
echo "doctl apps logs [app-id]"
echo ""

echo "# Update apps"
echo "doctl apps update [app-id] --spec do-app-rawrz.yaml"
echo ""

echo "# List apps"
echo "doctl apps list"
echo ""

echo "# Get app details"
echo "doctl apps get [app-id]"
echo ""

echo "🚀 **Your commands will deploy:**"
echo ""
echo "🔥 **RawrZ Security Platform:**"
echo "   • 72+ Security Features"
echo "   • Advanced Cryptography"
echo "   • Network Analysis Tools"
echo "   • File Forensic Analysis"
echo "   • Enterprise Web Interface"
echo "   • Real-time Processing"
echo ""

echo "⚛️ **n0mn0m Quantum System:**"
echo "   • 49 Language Compilers"
echo "   • Quantum Computing Support"
echo "   • Advanced Debugging Suite"
echo "   • AI-Powered Development"
echo "   • Cross-Platform Compilation"
echo "   • Complete Transparency"
echo ""

echo "🎯 **No web panels needed - everything via command line!**"
echo ""
echo "💡 **Pro tip: Save these commands to a text file on your tablet**"
echo "   Then copy and paste them one by one into your terminal"
echo ""

echo "🔥 **Your systems will be the most advanced ever deployed to Digital Ocean!**"