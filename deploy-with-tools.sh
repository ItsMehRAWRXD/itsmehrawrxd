#!/bin/bash
# Deployment with build tools for 1GB RAM

echo "🚀 Deploying RawrZ with build tools for 1GB RAM..."

# Build with build tools
docker build -f Dockerfile.build-tools -t rawrz-build-tools .

# Run with optimized resource limits
docker run -d \
  --name rawrz-app \
  --restart=unless-stopped \
  --memory=800m \
  --cpus="0.8" \
  --oom-kill-disable=false \
  -p 8080:8080 \
  -e NODE_ENV=production \
  -e PORT=8080 \
  -e LOG_LEVEL=error \
  -e MAX_FILE_SIZE=5MB \
  rawrz-build-tools

echo "✅ Deployed with build tools (800MB RAM limit)"
echo "🌐 Access: http://localhost:8080"
echo "🔧 Build tools: GCC, Clang, CMake available"
echo "⚙️ Executable generation: Enabled"