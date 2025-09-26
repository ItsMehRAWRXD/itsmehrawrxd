#!/bin/bash
# ULTIMATE FIXED - Uses corrected docker-compose.yml
echo "🚀 Starting RawrZ Platform (Fixed docker-compose)..."

# Stop any existing containers
docker-compose down 2>/dev/null || true

# Build and run with docker-compose
docker-compose up -d --build

echo "✅ RawrZ Platform is running at http://localhost:8080"
echo "📊 Memory: 1GB | CPU: 1 core | File limit: 500MB"
echo "🔧 Using fixed docker-compose.yml"
