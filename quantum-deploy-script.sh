#!/bin/bash

# Quantum deployment script for droplet
echo "🚀 QUANTUM DEPLOYMENT STARTING..."

# Update system
apt update

# Install Node.js 18
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs git curl

# Clone quantum repository
cd /opt
rm -rf quantum 2>/dev/null || true
git clone https://github.com/ItsMehRAWRXD/itsmehrawrxd.git quantum
cd quantum

# Show what we're deploying
echo "📊 QUANTUM SYSTEM STATS:"
echo "   • Assembly files: $(find . -name "*.asm" | wc -l)"
echo "   • Total lines: $(find . -name "*.asm" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}' || echo 'Loading...')"
echo "   • Meta-engine: $(ls -lh n0mn0m_meta_engine.asm 2>/dev/null | awk '{print $5}' || echo 'Loading...')"

# Setup quantum web interface
cp package-quantum.json package.json
npm install

# Stop any existing processes
pkill -f quantum 2>/dev/null || true
pkill -f "node.*server" 2>/dev/null || true

# Start quantum system
nohup node quantum-showcase-server.js > /var/log/quantum.log 2>&1 &

# Configure firewall
ufw allow 3000/tcp 2>/dev/null || true

# Wait for startup
sleep 5

# Test system
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com/ 2>/dev/null || echo "64.227.17.198")

echo ""
echo "🔥🔥🔥 QUANTUM SYSTEM DEPLOYED! 🔥🔥🔥"
echo "🌐 Access: http://$PUBLIC_IP:3000"
echo "⚡ Quantum: http://$PUBLIC_IP:3000/quantum"
echo "🔬 Meta-Engine: http://$PUBLIC_IP:3000/meta-engine"
echo ""

if curl -s http://localhost:3000/health >/dev/null 2>&1; then
    echo "✅ QUANTUM SYSTEM IS LIVE AND RESPONDING!"
else
    echo "⏳ System starting... check in 30 seconds"
fi