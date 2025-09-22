# Optimized Dockerfile for Digital Ocean App Platform
FROM node:18-alpine

# Install dumb-init to handle signals properly
RUN apk add --no-cache dumb-init

# Create app directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install production dependencies only
RUN npm ci --only=production && \
    npm cache clean --force

# Copy application files
COPY server-optimized.js ./
COPY public ./public/

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Set ownership
RUN chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:8080/health', (r) => {r.statusCode === 200 ? process.exit(0) : process.exit(1)})"

# Use dumb-init to handle signals
ENTRYPOINT ["dumb-init", "--"]

# Start app with memory limits
CMD ["node", "--max-old-space-size=256", "--expose-gc", "server-optimized.js"]