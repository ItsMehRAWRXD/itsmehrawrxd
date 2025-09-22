#!/bin/bash

# Quick Deploy Script for RawrZ Security Platform
echo "🚀 RawrZ Security Platform - Quick Deploy"
echo "========================================="

# Check if token is set
if [ -z "$DIGITALOCEAN_ACCESS_TOKEN" ]; then
    echo "❌ Please set your DigitalOcean token:"
    echo ""
    echo "   export DIGITALOCEAN_ACCESS_TOKEN=dop_v1_your_token_here"
    echo ""
    echo "Then run this script again:"
    echo "   ./quick-deploy.sh"
    echo ""
    exit 1
fi

echo "✅ DigitalOcean token detected"
echo "🔧 Starting optimized deployment..."
echo ""

# Run the deployment
./deploy-with-token.sh

echo ""
echo "🎉 Quick deployment completed!"
echo "Check the output above for your app URL."