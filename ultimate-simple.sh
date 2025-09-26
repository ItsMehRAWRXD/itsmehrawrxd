#!/bin/bash
# ULTIMATE SIMPLE - No docker-compose, just pure Docker
echo "🚀 Starting RawrZ Platform (Simple Docker)..."

# Stop any existing containers
docker stop rawrz-app 2>/dev/null || true
docker rm rawrz-app 2>/dev/null || true

# Build and run in one command
docker build -t rawrz-simple . && \
docker run -d \
  --name rawrz-app \
  --memory=1g \
  --cpus=1 \
  --restart=unless-stopped \
  -p 8080:8080 \
  -v $(pwd)/uploads:/app/uploads \
  -v $(pwd)/downloads:/app/downloads \
  -v $(pwd)/generated-stubs:/app/generated-stubs \
  -e NODE_ENV=production \
  -e PORT=8080 \
  -e MAX_FILE_SIZE=500MB \
  -e NODE_OPTIONS="--max-old-space-size=768" \
  rawrz-simple

echo "✅ RawrZ Platform is running at http://localhost:8080"
echo "📊 Memory: 1GB | CPU: 1 core | File limit: 500MB"
