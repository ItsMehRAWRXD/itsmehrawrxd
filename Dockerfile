# RawrZ Security Platform - Airtight Environment Dockerfile
FROM ubuntu:22.04

# Set working directory
WORKDIR /app

# Install Node.js 18 and minimal system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs \
    && apt-get install -y \
    nasm \
    gcc \
    g++ \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install PM2 for production process management
RUN npm install -g pm2

# Copy minimal package file for Docker build
COPY package-docker.json package.json

# Install core dependencies
RUN npm install --omit=dev --ignore-scripts --no-optional

# Copy application files
COPY . .

# Make startup script executable
RUN chmod +x /app/start-server.sh

# Create necessary directories
RUN mkdir -p \
    /app/uploads \
    /app/downloads \
    /app/temp \
    /app/logs \
    /app/data \
    /app/keys \
    /app/stubs \
    /app/payloads \
    /app/bots \
    /app/cve \
    /app/engines \
    /app/backups

# Create node user and set proper permissions
RUN useradd -m -s /bin/bash node && \
    chmod -R 755 /app && \
    chown -R node:node /app

# Switch to non-root user
USER node

# Expose ports
EXPOSE 3000 3001 3002 8080 8081 8082

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/api/health || exit 1

# Start the application
CMD ["/app/start-server.sh"]