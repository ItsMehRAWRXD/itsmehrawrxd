#!/bin/bash

# RawrZ Security Platform - Production Startup Script

echo "🚀 Starting RawrZ Security Platform..."

# Set proper environment
export NODE_ENV=production
export PORT=${PORT:-3000}

# Ensure directories exist
mkdir -p /app/uploads /app/logs /app/temp

# Start the server with error handling
exec node api-server.js