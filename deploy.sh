#!/bin/bash

# RawrZApp Digital Ocean Deployment Script
echo "🚀 RawrZApp Digital Ocean Deployment"
echo "=================================="

# Check if required files exist
if [ ! -f ".do/app.yaml" ]; then
    echo "❌ Error: .do/app.yaml not found"
    exit 1
fi

if [ ! -f "package.json" ]; then
    echo "❌ Error: package.json not found"
    exit 1
fi

echo "✅ Configuration files found"

# Check Node.js version
NODE_VERSION=$(node --version 2>/dev/null)
if [ $? -eq 0 ]; then
    echo "✅ Node.js version: $NODE_VERSION"
else
    echo "❌ Error: Node.js not found"
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
npm install

if [ $? -eq 0 ]; then
    echo "✅ Dependencies installed successfully"
else
    echo "❌ Error: Failed to install dependencies"
    exit 1
fi

# Test the application
echo "🧪 Testing application..."
npm start &
APP_PID=$!
sleep 5

# Check if app is running
if curl -f http://localhost:8080/health > /dev/null 2>&1; then
    echo "✅ Application is running and healthy"
    kill $APP_PID
else
    echo "❌ Error: Application health check failed"
    kill $APP_PID
    exit 1
fi

echo ""
echo "🎉 RawrZApp is ready for deployment!"
echo ""
echo "Next steps:"
echo "1. Push your code to GitHub repository: ItsMehRAWRXD/itsmehrawrxd"
echo "2. Go to Digital Ocean App Platform: https://cloud.digitalocean.com/apps"
echo "3. Create new app and connect your GitHub repository"
echo "4. Use the configuration from .do/app.yaml"
echo "5. Deploy and enjoy your $5/month RawrZApp!"
echo ""
echo "📖 See DEPLOYMENT.md for detailed instructions"
