# RawrZ Security Platform - Production Dockerfile (Security Hardened)
FROM node:20-alpine3.19

# Security: Update packages and install security patches + development tools
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache \
        dumb-init \
        curl \
        wget \
        bash \
        git \
        make \
        gcc \
        g++ \
        musl-dev \
        linux-headers \
        python3 \
        python3-dev \
        py3-pip \
        build-base \
        cmake \
        nasm \
        yasm \
        clang \
        llvm \
        rust \
        cargo \
        go \
        openjdk11-jre \
        openjdk11-jdk \
        maven \
        gradle \
        npm \
        yarn \
        pkgconf \
        libffi-dev \
        openssl-dev \
        zlib-dev \
        bzip2-dev \
        readline-dev \
        sqlite-dev \
        xz-dev \
        tk-dev \
        libxml2-dev \
        libxslt-dev \
        libjpeg-turbo-dev \
        freetype-dev \
        lcms2-dev \
        libwebp-dev \
        tcl-dev \
        libc6-compat \
        binutils \
        yara \
        clamav \
        clamav-libunrar && \
    rm -rf /var/cache/apk/* /tmp/*

# Install .NET SDK for Roslyn compilation
RUN curl -sSL https://dot.net/v1/dotnet-install.sh | bash /dev/stdin --channel 8.0 --install-dir /usr/share/dotnet && \
    ln -s /usr/share/dotnet/dotnet /usr/bin/dotnet && \
    dotnet --version

# Install additional Node.js tools globally
RUN npm install -g \
    typescript \
    ts-node \
    @types/node \
    pkg \
    nexe \
    esbuild \
    swc \
    tsc-alias \
    nodemon \
    pm2

# Install Python packages for advanced features using system packages
RUN apk add --no-cache \
    py3-pip \
    py3-setuptools \
    py3-wheel \
    py3-cryptography \
    py3-requests \
    py3-beautifulsoup4 \
    py3-lxml \
    py3-pillow \
    py3-numpy \
    py3-pandas \
    py3-matplotlib \
    py3-scipy \
    py3-scikit-learn && \
    pip3 install --break-system-packages \
    pyinstaller \
    cx_freeze \
    nuitka \
    cython \
    yara-python \
    clamd \
    volatility3 \
    capstone \
    unicorn \
    r2pipe \
    pwntools

# Install Rust tools properly
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    source ~/.cargo/env && \
    rustup default stable && \
    cargo install --locked cargo-audit

# Install Go tools properly (using compatible versions)
RUN go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.55.2 && \
    go install github.com/goreleaser/goreleaser@v1.25.0

# Install additional security and analysis tools
RUN apk add --no-cache \
    wine \
    wine-dev

# Install Java tools
RUN echo "export JAVA_HOME=/usr/lib/jvm/java-11-openjdk" >> /etc/profile && \
    echo "export PATH=\$PATH:\$JAVA_HOME/bin" >> /etc/profile

# Set working directory
WORKDIR /app

# Security: Create non-root user first
RUN addgroup -g 1001 -S nodejs && \
    adduser -S rawrz -u 1001 -G nodejs

# Copy package files first for better layer caching
COPY package*.json ./

# Security: Install dependencies with security audit
RUN npm ci --only=production --audit-level=high && \
    npm audit fix --force || true && \
    npm cache clean --force && \
    rm -rf ~/.npm

# Security: Remove unnecessary files and packages
RUN rm -rf /tmp/* /var/cache/apk/* /root/.npm

# Copy application code
COPY --chown=rawrz:nodejs . .

# Security: Create necessary directories with proper permissions
RUN mkdir -p logs && \
    chown -R rawrz:nodejs /app && \
    chmod -R 755 /app

# Security: Switch to non-root user
USER rawrz

# Security: Set environment variables for security and development tools
ENV NODE_ENV=production
ENV NODE_OPTIONS="--max-old-space-size=1024"
ENV NPM_CONFIG_AUDIT_LEVEL=moderate
ENV JAVA_HOME=/usr/lib/jvm/java-11-openjdk
ENV PATH=$PATH:$JAVA_HOME/bin:/usr/share/dotnet:/root/.cargo/bin:/root/go/bin
ENV DOTNET_ROOT=/usr/share/dotnet
ENV RUSTUP_HOME=/root/.rustup
ENV CARGO_HOME=/root/.cargo
ENV GOPATH=/root/go
ENV GOROOT=/usr/lib/go
ENV RUSTUP_INIT_COPY=1

# Expose port
EXPOSE 3000

# Security: Health check with proper error handling
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/api/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) }).on('error', () => process.exit(1))"

# Security: Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start the application
CMD ["node", "api-server-real.js"]