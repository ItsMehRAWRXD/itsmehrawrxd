#!/bin/bash
# Optimized deployment script

echo "🚀 Deploying RawrZ Security Platform (Optimized)..."

# Build optimized image
docker build -f Dockerfile.optimized -t rawrz-optimized .

# Run with minimal resource allocation
docker run -d \
  --name rawrz-app \
  --restart=unless-stopped \
  --memory=512m \
  --cpus="0.5" \
  -p 8080:8080 \
  -e NODE_ENV=production \
  -e PORT=8080 \
  -e LOG_LEVEL=error \
  -e MAX_FILE_SIZE=10MB \
  rawrz-optimized

echo "✅ Deployment complete!"
echo "🌐 Access: http://localhost:8080"
echo "🔍 Health: http://localhost:8080/health"