# Use Node.js 18 LTS
FROM node:18-alpine

# Install system dependencies for RawrZ platform functionality
RUN apk add --no-cache \
    curl \
    bash \
    python3 \
    py3-pip \
    make \
    g++ \
    gcc \
    musl-dev \
    linux-headers \
    git \
    openssl \
    ca-certificates

# Set working directory
WORKDIR /app

# Copy package files first for better caching
COPY package*.json ./

# Install ALL dependencies (including dev dependencies for full functionality)
RUN npm ci && npm cache clean --force

# Copy source code
COPY . .

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S rawr -u 1001 -G nodejs

# Change ownership of the app directory
RUN chown -R rawr:nodejs /app
USER rawr

# Expose port
EXPOSE 8080

# Health check with better error handling
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Start the application
CMD ["npm", "start"]