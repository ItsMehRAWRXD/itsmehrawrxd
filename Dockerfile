# RawrZ Security Platform - Airtight Environment Dockerfile
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Install system dependencies for cryptography and advanced features
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    gcc \
    libc-dev \
    libffi-dev \
    openssl-dev \
    sqlite-dev \
    imagemagick \
    graphicsmagick \
    vips-dev \
    libpng-dev \
    libjpeg-turbo-dev \
    giflib-dev \
    libwebp-dev \
    librsvg-dev \
    pango-dev \
    cairo-dev \
    pixman-dev \
    gdk-pixbuf-dev \
    freetype-dev \
    fontconfig-dev \
    libx11-dev \
    libxext-dev \
    libxrender-dev \
    libxtst-dev \
    libxi-dev \
    mesa-dev \
    libgl1-mesa-dev \
    libglu1-mesa-dev \
    libxrandr-dev \
    libxss-dev \
    libgconf-2-4 \
    libxcomposite-dev \
    libxdamage-dev \
    libxfixes-dev \
    libxinerama-dev \
    libxcursor-dev \
    libxss-dev \
    libxtst-dev \
    libxrandr-dev \
    libasound2-dev \
    libpangocairo-1.0-0 \
    libatk1.0-0 \
    libcairo-gobject2 \
    libgtk-3-0 \
    libgdk-pixbuf2.0-0 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxi6 \
    libxrandr2 \
    libxrender1 \
    libxss1 \
    libxtst6 \
    ca-certificates \
    curl \
    wget \
    git \
    bash \
    sudo \
    nano \
    vim \
    htop \
    net-tools \
    iputils \
    tcpdump \
    nmap \
    openssh-client \
    rsync \
    unzip \
    zip \
    tar \
    gzip \
    bzip2 \
    xz \
    lz4 \
    zstd \
    jq \
    yq \
    && rm -rf /var/cache/apk/*

# Install Node.js global packages for advanced features
RUN npm install -g \
    pm2 \
    nodemon \
    typescript \
    ts-node \
    @types/node \
    eslint \
    prettier \
    jest \
    mocha \
    chai \
    supertest \
    nyc \
    cross-env \
    concurrently \
    wait-port \
    http-server \
    serve \
    live-server

# Copy package files
COPY package*.json ./

# Install all dependencies
RUN npm ci --only=production --silent

# Copy application files
COPY . .

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

# Set proper permissions
RUN chmod -R 755 /app && \
    chown -R node:node /app

# Switch to non-root user
USER node

# Expose ports
EXPOSE 3000 3001 3002 8080 8081 8082

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/api/health || exit 1

# Start the application
CMD ["node", "api-server-no-cli.js"]