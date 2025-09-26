#!/bin/bash

# RawrZ Platform - 1GB RAM Optimized Docker Run
# Memory: 1GB RAM | 1 Shared vCPU | 150 GB bandwidth

echo "🚀 Starting RawrZ Platform (1GB Optimized)..."

# Build the image with optimizations
docker build -t rawrz-1gb \
  --build-arg NODE_ENV=production \
  --build-arg MAX_FILE_SIZE=500MB \
  --build-arg LOG_LEVEL=warn \
  --memory=1g \
  --cpus=1 \
  .

# Run with 1GB memory limit and optimizations
docker run -d \
  --name rawrz-app \
  --memory=1g \
  --cpus=1 \
  --memory-swap=1g \
  --oom-kill-disable=false \
  --restart=unless-stopped \
  -p 8080:8080 \
  -v $(pwd)/uploads:/app/uploads \
  -v $(pwd)/downloads:/app/downloads \
  -v $(pwd)/generated-stubs:/app/generated-stubs \
  -e NODE_ENV=production \
  -e PORT=8080 \
  -e MAX_FILE_SIZE=500MB \
  -e LOG_LEVEL=warn \
  -e NODE_OPTIONS="--max-old-space-size=768" \
  rawrz-1gb

echo "✅ RawrZ Platform started successfully!"
echo "🌐 Access at: http://localhost:8080"
echo "📊 Memory limit: 1GB"
echo "💾 File size limit: 500MB"
