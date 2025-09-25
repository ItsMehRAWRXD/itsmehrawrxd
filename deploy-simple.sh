#!/bin/bash
# RawrZ Security Platform - Simple Deployment
# Minimal deployment without Docker or complex dependencies

set -e

echo "RawrZ Security Platform - Simple Deployment"
echo "==========================================="

# Update system packages
echo "Updating system packages..."
apt update && apt upgrade -y

# Install basic dependencies
echo "Installing basic dependencies..."
apt install -y git curl wget build-essential

# Fix Node.js conflicts and install
echo "Fixing Node.js conflicts..."
wget https://raw.githubusercontent.com/ItsMehRAWRXD/itsmehrawrxd/main/fix-nodejs-conflicts.sh
chmod +x fix-nodejs-conflicts.sh
./fix-nodejs-conflicts.sh

# Clone the repository
echo "Cloning repository..."
if [ -d "/root/RawrZApp" ]; then
    echo "Updating existing repository..."
    cd /root/RawrZApp
    git pull origin main
else
    echo "Cloning repository..."
    git clone https://github.com/ItsMehRAWRXD/itsmehrawrxd.git /root/RawrZApp
    cd /root/RawrZApp
fi

# Fix npm capitalization issue
echo "Fixing npm capitalization issue..."
if [ -f "fix-npm-capitalization.sh" ]; then
    chmod +x fix-npm-capitalization.sh
    ./fix-npm-capitalization.sh
else
    # Create symbolic links directly if script doesn't exist
    NPM_PATH=$(which npm)
    ln -sf "$NPM_PATH" /usr/local/bin/Npm 2>/dev/null || true
    ln -sf "$NPM_PATH" /usr/bin/Npm 2>/dev/null || true
fi

# Install Node.js dependencies
echo "Installing Node.js dependencies..."
npm install

# Create necessary directories
echo "Creating directories..."
mkdir -p /root/RawrZApp/data
mkdir -p /root/RawrZApp/logs
mkdir -p /root/RawrZApp/uploads
mkdir -p /root/RawrZApp/processed

# Set up systemd service
echo "Setting up systemd service..."
cat > /etc/systemd/system/rawrz.service << 'EOF'
[Unit]
Description=RawrZ Security Platform
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/RawrZApp
ExecStart=/usr/bin/node api-server-real.js
Restart=always
RestartSec=10
Environment=NODE_ENV=production
Environment=PORT=3000

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable service
echo "Enabling RawrZ service..."
systemctl daemon-reload
systemctl enable rawrz.service

# Configure firewall
echo "Configuring firewall..."
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 3000/tcp
ufw --force enable

# Start the service
echo "Starting RawrZ Security Platform..."
systemctl start rawrz.service

# Check service status
echo "Checking service status..."
sleep 5
systemctl status rawrz.service --no-pager

# Check if the service is running
if systemctl is-active --quiet rawrz.service; then
    echo "✅ RawrZ Security Platform deployed successfully!"
    echo "🌐 Access the platform at: http://$(curl -s ifconfig.me):3000"
    echo "📊 Service status:"
    systemctl status rawrz.service --no-pager
else
    echo "❌ Deployment failed. Checking logs..."
    journalctl -u rawrz.service --no-pager -n 20
fi

echo "Deployment complete!"
