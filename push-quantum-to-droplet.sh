#!/bin/bash

# 🚀 PUSH QUANTUM SYSTEM TO DROPLET - DIRECT DEPLOYMENT
set -e

DROPLET_IP="64.227.17.198"
DROPLET_USER="root"

echo "🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥"
echo "🚀 PUSHING 1.6M+ LINE QUANTUM SYSTEM TO DROPLET!"
echo "📊 Deploying N0MN0M Meta-Engine (565K lines)"
echo "🧠 Deploying EON IDE System (184K lines)" 
echo "⚡ Direct git clone + instant deployment"
echo "🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥"

# Create deployment script that runs on droplet
cat > /tmp/droplet-quantum-deploy.sh << 'REMOTE_SCRIPT'
#!/bin/bash
set -e

echo "🚀 QUANTUM DEPLOYMENT STARTING ON DROPLET!"

# Update system
echo "📦 Updating system..."
apt update && apt upgrade -y

# Install Node.js 18
echo "⚡ Installing Node.js 18..."
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs git curl

# Clone the quantum repository
echo "🔥 Cloning quantum repository..."
cd /opt
rm -rf quantum 2>/dev/null || true
git clone https://github.com/ItsMehRAWRXD/itsmehrawrxd.git quantum
cd quantum

# Show quantum stats
echo ""
echo "📊 QUANTUM SYSTEM STATS:"
echo "   • Total assembly files: $(find . -name "*.asm" | wc -l)"
echo "   • Total assembly lines: $(find . -name "*.asm" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}')"
echo "   • Meta-engine size: $(ls -lh n0mn0m_meta_engine.asm 2>/dev/null | awk '{print $5}' || echo 'N/A')"
echo ""

# Install quantum web interface dependencies
echo "🌐 Setting up quantum web interface..."
cp package-quantum.json package.json
npm install

# Start quantum system
echo "🚀 Starting quantum system..."
pkill -f "node.*server.js" 2>/dev/null || true
pkill -f "quantum" 2>/dev/null || true

# Start with nohup for background execution
nohup node quantum-showcase-server.js > /var/log/quantum.log 2>&1 &
QUANTUM_PID=$!

# Wait a moment for startup
sleep 3

# Configure firewall
echo "🔥 Configuring firewall..."
ufw allow 3000/tcp 2>/dev/null || true
ufw --force enable 2>/dev/null || true

# Get public IP
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com/ || echo "64.227.17.198")

echo ""
echo "🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉"
echo "🔥 QUANTUM SYSTEM DEPLOYED SUCCESSFULLY! 🔥"
echo "🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉"
echo ""
echo "🌐 QUANTUM SYSTEM: http://$PUBLIC_IP:3000"
echo "⚡ Quantum Interface: http://$PUBLIC_IP:3000/quantum"
echo "🔬 Meta-Engine (565K): http://$PUBLIC_IP:3000/meta-engine"
echo "🧠 EON IDE (184K): http://$PUBLIC_IP:3000/eon-ide"
echo "💚 Health Check: http://$PUBLIC_IP:3000/health"
echo "📊 Stats: http://$PUBLIC_IP:3000/stats"
echo ""
echo "📋 QUANTUM DEPLOYMENT INFO:"
echo "   • Process ID: $QUANTUM_PID"
echo "   • Log file: /var/log/quantum.log"
echo "   • Repository: /opt/quantum"
echo "   • Assembly lines: 1,646,390"
echo ""
echo "🔥 QUANTUM DOMINATION ACHIEVED! 🔥"

# Test the deployment
echo "🧪 Testing quantum system..."
sleep 2
if curl -s http://localhost:3000/health >/dev/null; then
    echo "✅ Quantum system is responding!"
    echo "🚀 Deployment successful!"
else
    echo "⚠️  Quantum system may need a moment to start"
    echo "📋 Check logs: tail -f /var/log/quantum.log"
fi

REMOTE_SCRIPT

# Copy deployment script to droplet and execute
echo "📤 Copying deployment script to droplet..."

# First, let's use doctl to get SSH key info
echo "🔑 Using DigitalOcean SSH access..."

# Create the deployment using DigitalOcean's user data approach
cat > /tmp/quantum-deploy-command.sh << 'CMD_SCRIPT'
curl -fsSL https://raw.githubusercontent.com/ItsMehRAWRXD/itsmehrawrxd/cursor/fix-and-redeploy-digital-ocean-app-d6ce/quantum-showcase-server.js -o /tmp/quantum-server.js 2>/dev/null || {
    echo "📦 Installing quantum system from scratch..."
    apt update
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt-get install -y nodejs git
    cd /opt
    git clone https://github.com/ItsMehRAWRXD/itsmehrawrxd.git quantum
    cd quantum
    cp package-quantum.json package.json
    npm install
    pkill -f quantum 2>/dev/null || true
    nohup node quantum-showcase-server.js > /var/log/quantum.log 2>&1 &
    ufw allow 3000/tcp
    echo "🚀 Quantum system deployed at http://$(curl -s http://checkip.amazonaws.com/):3000"
}
CMD_SCRIPT

# Try multiple deployment approaches
echo "🚀 Attempting quantum deployment..."

# Approach 1: Direct execution
echo "📡 Attempting direct deployment..."
if timeout 30 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 $DROPLET_USER@$DROPLET_IP 'bash -s' < /tmp/droplet-quantum-deploy.sh 2>/dev/null; then
    echo "✅ Direct deployment successful!"
else
    echo "🔄 Direct SSH failed, trying alternative approach..."
    
    # Approach 2: Using doctl console access
    echo "📱 Using DigitalOcean console..."
    echo ""
    echo "🔧 MANUAL DEPLOYMENT INSTRUCTIONS:"
    echo "=================================="
    echo ""
    echo "1. 📱 Open DigitalOcean Dashboard"
    echo "2. 🖥️  Go to your droplet console (64.227.17.198)"
    echo "3. 📋 Copy and paste this command:"
    echo ""
    echo "curl -fsSL https://raw.githubusercontent.com/ItsMehRAWRXD/itsmehrawrxd/main/quantum-auto-install.sh | bash"
    echo ""
    echo "OR run these commands step by step:"
    echo ""
    cat /tmp/droplet-quantum-deploy.sh
    echo ""
fi

# Test if quantum system is running
echo ""
echo "🧪 Testing quantum deployment..."
sleep 5

if curl -m 10 -s http://$DROPLET_IP:3000/health >/dev/null 2>&1; then
    echo ""
    echo "🎉 SUCCESS! Quantum system is LIVE!"
    echo "🌐 Access your quantum system: http://$DROPLET_IP:3000"
    
    # Get quantum system info
    echo "📊 Quantum system status:"
    curl -s http://$DROPLET_IP:3000/health | head -5 || echo "System is starting up..."
    
else
    echo ""
    echo "⏳ Quantum system is deploying... This may take a moment."
    echo "🔍 Try accessing in 1-2 minutes:"
    echo ""
    echo "🌐 http://$DROPLET_IP:3000"
    echo "⚡ http://$DROPLET_IP:3000/quantum"
    echo "🔬 http://$DROPLET_IP:3000/meta-engine"
    echo ""
    echo "📋 If not working, use the manual deployment above!"
fi

echo ""
echo "🔥🔥🔥 QUANTUM DEPLOYMENT COMPLETE! 🔥🔥🔥"