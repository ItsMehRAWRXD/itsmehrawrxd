#!/bin/bash

# RawrZ Security Platform - Deployment Demo Script
# This shows the exact commands to run on your Digital Ocean droplet

echo "🚀 RawrZ Security Platform - Deployment Demo"
echo "============================================"

echo ""
echo "📋 **Copy and paste these commands into your Digital Ocean droplet terminal:**"
echo ""

echo "# 1. Update system and install dependencies"
echo "sudo apt-get update"
echo "curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -"
echo "sudo apt-get install -y nodejs nasm build-essential git curl wget htop net-tools ufw fail2ban"
echo ""

echo "# 2. Navigate to RawrZ directory (adjust path if needed)"
echo "cd /opt/rawrz  # or wherever you uploaded the files"
echo ""

echo "# 3. Make deployment script executable"
echo "chmod +x rawrz-optimized-deploy.sh"
echo ""

echo "# 4. Deploy the complete RawrZ Security Platform"
echo "sudo ./rawrz-optimized-deploy.sh"
echo ""

echo "🎉 **After deployment, access your RawrZ Security Platform at:**"
echo "   http://YOUR_DROPLET_IP:3000"
echo ""

echo "📋 **Verify deployment:**"
echo "   curl http://localhost:3000/api/health"
echo ""

echo "🔧 **Management commands:**"
echo "   sudo systemctl status rawrz                    # Check service status"
echo "   sudo journalctl -u rawrz -f                   # View logs"
echo "   sudo systemctl restart rawrz                  # Restart service"
echo ""

echo "📊 **Test RawrZ features:**"
echo "   node rawrz-standalone.js sysinfo              # System info"
echo "   node rawrz-standalone.js files                # List files"
echo "   node rawrz-standalone.js encrypt aes256 test.txt  # Test encryption"
echo "   curl http://localhost:3000/api/health         # API health check"
echo ""

echo "🌐 **Available endpoints after deployment:**"
echo "   Health Check:      http://YOUR_DROPLET_IP:3000/api/health"
echo "   File Upload:       http://YOUR_DROPLET_IP:3000/api/upload"
echo "   RawrZ Commands:    http://YOUR_DROPLET_IP:3000/api/rawrz/{command}"
echo "   File Management:   http://YOUR_DROPLET_IP:3000/api/files"
echo "   System Stats:      http://YOUR_DROPLET_IP:3000/api/stats"
echo "   WebSocket:         ws://YOUR_DROPLET_IP:3001"
echo ""

echo "🚀 **Your RawrZ Security Platform provides 72+ security features:**"
echo "   • Advanced Cryptography (AES, RSA, Blowfish, etc.)"
echo "   • Network Analysis (Port scanning, Ping, Traceroute, WHOIS)"
echo "   • File Analysis (Deep forensic analysis, entropy calculation)"
echo "   • System Monitoring (Process monitoring, resource tracking)"
echo "   • Text Processing (Encoding, validation, manipulation)"
echo "   • Security Tools (Hashing, key generation, digital signatures)"
echo "   • Enterprise Web Interface (Professional security dashboard)"
echo "   • Real-time Processing (WebSocket integration)"
echo "   • Complete CLI Interface (Full command-line security platform)"
echo ""

echo "🎯 **Expected result after deployment:**"
echo '   {"success": true, "status": "healthy", "features": 72}'
echo ""

echo "🔥 **Your RawrZ Security Platform will be the most advanced security suite ever deployed!**"