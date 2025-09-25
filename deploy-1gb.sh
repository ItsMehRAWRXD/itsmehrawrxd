#!/bin/bash
# Deployment for 1GB RAM constraint

echo "🚀 Deploying for 1GB RAM constraint..."

# Build ultra-lightweight image
docker build -f Dockerfile.ultra-light -t rawrz-1gb .

# Run with strict resource limits
docker run -d \
  --name rawrz-app \
  --restart=unless-stopped \
  --memory=400m \
  --cpus="0.3" \
  --oom-kill-disable=false \
  -p 8080:8080 \
  -e NODE_ENV=production \
  -e PORT=8080 \
  -e LOG_LEVEL=error \
  -e MAX_FILE_SIZE=2MB \
  rawrz-1gb

echo "✅ Deployed with 400MB RAM limit"
echo "🌐 Access: http://localhost:8080"