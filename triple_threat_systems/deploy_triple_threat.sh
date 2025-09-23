#!/bin/bash

# Triple Threat Systems Deployment Script
echo "🔥🔥🔥 DEPLOYING TRIPLE THREAT SYSTEMS 🔥🔥🔥"
echo "🕵️ Invisible Hypervisor"
echo "🎮 Gaming Acceleration Engine"  
echo "🛡️ Security Interception Layer"

# Build all systems
make -C invisible_hypervisor
make -C gaming_acceleration  
make -C security_interception
make -C integration

# Deploy invisibly
echo "💀 Deploying invisible hypervisor..."
./invisible_hypervisor/deploy_invisible.sh

echo "🎮 Activating gaming acceleration..."
./gaming_acceleration/deploy_gaming.sh

echo "🛡️ Enabling security interception..."
./security_interception/deploy_security.sh

echo "⚡ Starting system integration..."
./integration/start_integration.sh

echo "✅ TRIPLE THREAT SYSTEMS DEPLOYED!"
echo "📊 Access dashboard: file://$(pwd)/dashboard/triple_threat_dashboard.html"
