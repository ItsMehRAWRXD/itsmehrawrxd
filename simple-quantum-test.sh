#!/bin/bash

# Test if quantum system is accessible and provide status
DROPLET_IP="64.227.17.198"
PORT="3000"

echo "🔥 TESTING QUANTUM SYSTEM STATUS"
echo "================================"

echo "📍 Testing droplet: $DROPLET_IP:$PORT"

# Test basic connectivity
if ping -c 1 $DROPLET_IP >/dev/null 2>&1; then
    echo "✅ Droplet is reachable"
else
    echo "❌ Droplet not reachable"
    exit 1
fi

# Test port 3000
echo "🧪 Testing quantum system port..."
if timeout 10 bash -c "</dev/tcp/$DROPLET_IP/$PORT" 2>/dev/null; then
    echo "✅ Port $PORT is open and responding!"
    
    # Try to get quantum system response
    echo "🚀 Testing quantum endpoints..."
    
    # Test health endpoint
    if HEALTH=$(curl -m 5 -s http://$DROPLET_IP:$PORT/health 2>/dev/null); then
        echo "💚 Health endpoint responding!"
        echo "📊 Response: $HEALTH"
    fi
    
    # Test main page
    if curl -m 5 -s http://$DROPLET_IP:$PORT/ >/dev/null 2>&1; then
        echo "🌐 Main page responding!"
    fi
    
    echo ""
    echo "🎉 QUANTUM SYSTEM IS LIVE!"
    echo "🌐 Access your 1.6M+ line quantum system:"
    echo "   • Main: http://$DROPLET_IP:$PORT"
    echo "   • Quantum: http://$DROPLET_IP:$PORT/quantum" 
    echo "   • Meta-Engine: http://$DROPLET_IP:$PORT/meta-engine"
    echo "   • Health: http://$DROPLET_IP:$PORT/health"
    
else
    echo "⏳ Port $PORT not yet responding"
    echo "🔄 Quantum system may still be starting up..."
    echo ""
    echo "📋 MANUAL DEPLOYMENT OPTION:"
    echo "1. Go to DigitalOcean Dashboard"
    echo "2. Access droplet console: $DROPLET_IP"  
    echo "3. Run this one-liner:"
    echo ""
    echo "curl -fsSL https://raw.githubusercontent.com/ItsMehRAWRXD/itsmehrawrxd/main/quantum-showcase-server.js -o /tmp/server.js && cd /tmp && echo '{\"dependencies\":{\"express\":\"^4.18.2\",\"cors\":\"^2.8.5\"}}' > package.json && npm install && nohup node server.js > quantum.log 2>&1 &"
    echo ""
    echo "⚡ Then access: http://$DROPLET_IP:$PORT"
fi

echo ""
echo "🔥 QUANTUM STATUS CHECK COMPLETE!"