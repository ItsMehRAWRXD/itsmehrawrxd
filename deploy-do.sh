#!/bin/bash

echo "🔧 Installing DigitalOcean CLI..."

# Install doctl (DigitalOcean CLI)
curl -sL https://github.com/digitalocean/doctl/releases/latest/download/doctl-$(uname -s)-amd64.tar.gz | tar -xzv
sudo mv doctl /usr/local/bin/

echo "✅ DigitalOcean CLI installed"
echo ""

echo "🔑 Setting up authentication..."
echo "Please run: doctl auth init"
echo "Enter your DigitalOcean API token when prompted"
echo ""

echo "🚀 Deploying to DigitalOcean App Platform..."
doctl apps create --spec .do/app.yaml

echo ""
echo "📊 Deployment Status:"
doctl apps list

echo ""
echo "🌐 Your RawrZ Platform will be available at the provided URL"
echo "🎯 Main interface: [URL]/unified"
echo "📊 Dashboard: [URL]/panel"
echo ""

echo "🔧 Post-deployment setup:"
echo "1. Check the deployment status with: doctl apps list"
echo "2. View logs with: doctl apps logs [APP_ID]"
echo "3. Update environment variables if needed"
echo "4. Scale the app if required"
