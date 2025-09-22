#!/bin/bash

# Deploy optimized RawrZ to specific droplet
DROPLET_IP="64.227.17.198"
DROPLET_USER="root"

echo "🚀 Deploying optimized RawrZ to droplet: $DROPLET_IP"

# Create deployment package
echo "📦 Creating deployment package..."
mkdir -p /tmp/rawrz-optimized-deploy
cd /tmp/rawrz-optimized-deploy

# Copy optimized files
cp /workspace/Dockerfile.optimized ./Dockerfile
cp /workspace/package.optimized.json ./package.json
cp /workspace/server.optimized.js ./server.js
cp /workspace/.env.production ./.env

# Create startup script
cat > start-app.sh << 'EOF'
#!/bin/bash
echo "🚀 Starting RawrZ Security Platform (Optimized)"

# Update system
apt update && apt upgrade -y

# Install Node.js 18
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs

# Install PM2 for process management
npm install -g pm2

# Create app directory
mkdir -p /opt/rawrz
cd /opt/rawrz

# Copy files (they should already be here)
if [ ! -f "server.js" ]; then
    echo "❌ Server files not found!"
    exit 1
fi

# Install dependencies
npm install --only=production

# Set up PM2 ecosystem
cat > ecosystem.config.js << 'ECOSYSTEM'
module.exports = {
  apps: [{
    name: 'rawrz-optimized',
    script: 'server.js',
    instances: 1,
    exec_mode: 'fork',
    env: {
      NODE_ENV: 'production',
      PORT: 3000,
      LOG_LEVEL: 'info',
      NODE_OPTIONS: '--max-old-space-size=256'
    },
    max_memory_restart: '256M',
    watch: false,
    log_file: '/var/log/rawrz/combined.log',
    out_file: '/var/log/rawrz/out.log',
    error_file: '/var/log/rawrz/error.log',
    time: true
  }]
};
ECOSYSTEM

# Create log directory
mkdir -p /var/log/rawrz
chown -R $USER:$USER /var/log/rawrz

# Start the application
pm2 start ecosystem.config.js
pm2 save
pm2 startup

# Configure firewall
ufw allow 3000/tcp
ufw allow ssh
ufw --force enable

# Get public IP
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com/)

echo ""
echo "🎉 Deployment completed successfully!"
echo "🌐 Your app is available at: http://$PUBLIC_IP:3000"
echo "💚 Health check: http://$PUBLIC_IP:3000/health"
echo "🧪 API status: http://$PUBLIC_IP:3000/api/status"
echo ""
echo "📊 Management commands:"
echo "  pm2 status"
echo "  pm2 logs rawrz-optimized"
echo "  pm2 restart rawrz-optimized"
echo "  pm2 stop rawrz-optimized"
echo ""
EOF

chmod +x start-app.sh

echo "✅ Deployment package created"
echo "📤 Uploading to droplet..."

# Upload files to droplet
scp -o StrictHostKeyChecking=no -r . $DROPLET_USER@$DROPLET_IP:/opt/rawrz/

echo "🚀 Running deployment on droplet..."

# Execute deployment on droplet
ssh -o StrictHostKeyChecking=no $DROPLET_USER@$DROPLET_IP << 'REMOTE'
cd /opt/rawrz
chmod +x start-app.sh
./start-app.sh
REMOTE

echo ""
echo "🎉 Deployment completed!"
echo "🌐 Your optimized app is running at: http://64.227.17.198:3000"
echo "💚 Test it: curl http://64.227.17.198:3000/health"
echo ""