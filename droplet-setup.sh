#!/bin/bash

# n0mn0m Quantum System - Digital Ocean Droplet Setup Commands
# Run these commands on your Digital Ocean droplet

echo "🚀 n0mn0m Quantum System - Droplet Setup Commands"
echo "================================================"

echo ""
echo "📋 **Copy and paste these commands into your droplet terminal:**"
echo ""

echo "# 1. Update system and install dependencies"
echo "sudo apt-get update"
echo "curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -"
echo "sudo apt-get install -y nodejs nasm build-essential git curl wget htop net-tools"
echo ""

echo "# 2. Navigate to n0mn0m directory (assuming files are in /opt/n0mn0m)"
echo "cd /opt/n0mn0m"
echo ""

echo "# 3. Make scripts executable"
echo "chmod +x *.sh"
echo ""

echo "# 4. Compile the system"
echo "./compile-n0mn0m.sh"
echo ""

echo "# 5. Deploy the system"
echo "./digitalocean-deploy.sh"
echo ""

echo "🎉 **After deployment, access your system at:**"
echo "   http://YOUR_DROPLET_IP:3000"
echo ""

echo "📋 **Verify deployment:**"
echo "   curl http://localhost:3000/api/health"
echo ""

echo "🔧 **Management commands:**"
echo "   tail -f logs/quantum.log                    # View logs"
echo "   sudo pkill -f quantum-showcase-server.js   # Stop server"
echo "   nohup node quantum-showcase-server.js > logs/quantum.log 2>&1 &  # Start server"
echo ""

echo "📊 **Test endpoints:**"
echo "   curl http://localhost:3000/api/health"
echo "   curl http://localhost:3000/api/quantum/generate"
echo "   curl http://localhost:3000/api/system/stats"
echo ""

echo "💡 **If you encounter issues:**"
echo "   1. Check logs: tail -f logs/quantum.log"
echo "   2. Verify ports: netstat -tulpn | grep :3000"
echo "   3. Check processes: ps aux | grep quantum"
echo "   4. Restart: sudo pkill -f quantum-showcase-server.js && nohup node quantum-showcase-server.js > logs/quantum.log 2>&1 &"
echo ""

echo "🚀 **Your n0mn0m Quantum System will be ready with:**"
echo "   • 49 Language Compilers from Scratch"
echo "   • Quantum Computing Support"
echo "   • Advanced Debugging Suite"
echo "   • AI-Powered Development Environment"
echo "   • Complete Transparency (50,000+ Lines)"
echo ""

echo "🎯 Ready to deploy your incredible n0mn0m Quantum System!"