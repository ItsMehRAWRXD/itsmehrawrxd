#!/bin/bash

# RawrZ Security Platform - Digital Ocean Deployment Script
# This script automates the deployment of the RawrZ Security Platform on a Digital Ocean Droplet

set -euo pipefail  # Exit on error, undefined variables, and pipe failures

# Configuration
REPO_URL="https://github.com/ItsMehRAWRXD/itsmehrawrxd.git"
APP_DIR="/opt/rawrz-security"
SERVICE_USER="rawrz"
LOG_FILE="/var/log/rawrz-deployment.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root. Use: sudo $0"
    fi
}

# Update system packages
update_system() {
    log "Updating system packages..."
    apt update && apt upgrade -y
    apt install -y curl wget git unzip software-properties-common apt-transport-https ca-certificates gnupg lsb-release
    success "System packages updated successfully"
}

# Install Docker and Docker Compose
install_docker() {
    log "Installing Docker..."
    
    # Remove old Docker versions
    apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
    
    # Add Docker's official GPG key
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    
    # Add Docker repository
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Install Docker
    apt update
    apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
    # Start and enable Docker
    systemctl start docker
    systemctl enable docker
    
    # Install Docker Compose (standalone)
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    
    # Verify installation
    docker --version
    docker compose version
    
    success "Docker installed successfully"
}

# Install Node.js (for development and utilities)
install_nodejs() {
    log "Installing Node.js..."
    
    # Install Node.js 18.x
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt install -y nodejs
    
    # Install global packages
    npm install -g pm2 nodemon
    
    # Verify installation
    node --version
    npm --version
    
    success "Node.js installed successfully"
}

# Install additional security tools
install_security_tools() {
    log "Installing security tools..."
    
    apt install -y \
        fail2ban \
        ufw \
        htop \
        iotop \
        nethogs \
        nmap \
        tcpdump \
        wireshark-common \
        net-tools \
        iptables-persistent \
        nginx \
        certbot \
        python3-certbot-nginx
    
    success "Security tools installed successfully"
}

# Configure firewall
configure_firewall() {
    log "Configuring UFW firewall..."
    
    # Reset UFW to defaults
    ufw --force reset
    
    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (adjust port if needed)
    ufw allow 22/tcp
    
    # Allow HTTP and HTTPS
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Allow application ports
    ufw allow 3000/tcp  # Main app
    ufw allow 3001/tcp  # File processor
    ufw allow 3002/tcp  # Bot manager
    ufw allow 5432/tcp  # PostgreSQL (only from local)
    ufw allow 6379/tcp  # Redis (only from local)
    ufw allow 9090/tcp  # Prometheus
    ufw allow 3100/tcp  # Loki
    
    # Enable UFW
    ufw --force enable
    
    success "Firewall configured successfully"
}

# Create service user
create_service_user() {
    log "Creating service user..."
    
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd -r -m -s /bin/bash -d "$APP_DIR" "$SERVICE_USER"
        usermod -aG docker "$SERVICE_USER"
        success "Service user '$SERVICE_USER' created successfully"
    else
        warning "Service user '$SERVICE_USER' already exists"
    fi
}

# Clone repository
clone_repository() {
    log "Cloning repository..."
    
    # Remove existing directory if it exists
    if [[ -d "$APP_DIR" ]]; then
        rm -rf "$APP_DIR"
    fi
    
    # Clone the repository
    git clone "$REPO_URL" "$APP_DIR"
    
    # Set proper permissions
    chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR"
    chmod -R 755 "$APP_DIR"
    
    success "Repository cloned successfully"
}

# Setup environment files
setup_environment() {
    log "Setting up environment configuration..."
    
    cd "$APP_DIR"
    
    # Create production environment file
    cat > .env.production << EOF
# Production Environment Configuration
NODE_ENV=production
PORT=3000
API_PORT=3000
LOG_LEVEL=info

# Database Configuration
DB_HOST=rawrz-db
DB_PORT=5432
DB_NAME=rawrz_security
DB_USER=rawrz_user
DB_PASSWORD=rawrz_secure_password_2024

# Redis Configuration
REDIS_HOST=rawrz-redis
REDIS_PORT=6379

# Security Configuration
JWT_SECRET=$(openssl rand -hex 32)
SESSION_SECRET=$(openssl rand -hex 32)
ENCRYPTION_KEY=$(openssl rand -hex 32)

# File Upload Configuration
MAX_FILE_SIZE=100MB
UPLOAD_DIR=/app/uploads
DOWNLOAD_DIR=/app/downloads
TEMP_DIR=/app/temp

# SSL Configuration (for production)
SSL_CERT_PATH=/etc/nginx/ssl/cert.pem
SSL_KEY_PATH=/etc/nginx/ssl/key.pem

# Monitoring
PROMETHEUS_PORT=9090
LOKI_PORT=3100

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# CORS Configuration
CORS_ORIGIN=*
EOF

    # Set proper permissions for environment file
    chmod 600 .env.production
    chown "$SERVICE_USER:$SERVICE_USER" .env.production
    
    success "Environment configuration created successfully"
}

# Setup SSL certificates
setup_ssl() {
    log "Setting up SSL certificates..."
    
    # Create SSL directory
    mkdir -p /etc/nginx/ssl
    
    # Generate self-signed certificate for development (replace with real certificates in production)
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/key.pem \
        -out /etc/nginx/ssl/cert.pem \
        -subj "/C=US/ST=State/L=City/O=RawrZ Security/CN=localhost"
    
    chmod 600 /etc/nginx/ssl/key.pem
    chmod 644 /etc/nginx/ssl/cert.pem
    
    success "SSL certificates generated successfully"
}

# Configure Nginx
configure_nginx() {
    log "Configuring Nginx..."
    
    # Backup default configuration
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
    
    # Create RawrZ configuration
    cat > /etc/nginx/sites-available/rawrz-security << 'EOF'
upstream rawrz_app {
    server localhost:3000;
    server localhost:3001 backup;
}

server {
    listen 80;
    listen [::]:80;
    server_name _;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name _;
    
    # SSL Configuration
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_proxied expired no-cache no-store private must-revalidate auth;
    gzip_types text/plain text/css text/xml text/javascript application/x-javascript application/xml+rss;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;
    
    # Static files
    location /static/ {
        alias /opt/rawrz-security/public/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    # WebSocket support
    location /ws {
        proxy_pass http://rawrz_app;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Main application
    location / {
        proxy_pass http://rawrz_app;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
    
    # Health check
    location /health {
        proxy_pass http://rawrz_app/api/health;
        access_log off;
    }
}
EOF

    # Enable the site
    ln -sf /etc/nginx/sites-available/rawrz-security /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    # Test configuration
    nginx -t
    
    # Restart Nginx
    systemctl restart nginx
    systemctl enable nginx
    
    success "Nginx configured successfully"
}

# Setup Docker services
setup_docker_services() {
    log "Setting up Docker services..."
    
    cd "$APP_DIR"
    
    # Create production Docker Compose override
    cat > docker-compose.prod.yml << 'EOF'
version: '3.8'

services:
  rawrz-app:
    build: .
    restart: unless-stopped
    environment:
      - NODE_ENV=production
    volumes:
      - ./uploads:/app/uploads
      - ./downloads:/app/downloads
      - ./logs:/app/logs
      - ./data:/app/data
    networks:
      - rawrz-network
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  rawrz-db:
    restart: unless-stopped
    volumes:
      - /opt/rawrz-data/postgres:/var/lib/postgresql/data
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  rawrz-redis:
    restart: unless-stopped
    volumes:
      - /opt/rawrz-data/redis:/data
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  rawrz-nginx:
    volumes:
      - /etc/nginx/ssl:/etc/nginx/ssl:ro
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

networks:
  rawrz-network:
    driver: bridge

volumes:
  rawrz_db_data:
    external: true
  rawrz_redis_data:
    external: true
EOF

    # Create data directories
    mkdir -p /opt/rawrz-data/{postgres,redis,logs,uploads,downloads}
    chown -R "$SERVICE_USER:$SERVICE_USER" /opt/rawrz-data
    
    # Create Docker volumes
    docker volume create rawrz_db_data || true
    docker volume create rawrz_redis_data || true
    
    success "Docker services configured successfully"
}

# Create systemd services
create_systemd_services() {
    log "Creating systemd services..."
    
    # Create Docker Compose service
    cat > /etc/systemd/system/rawrz-security.service << EOF
[Unit]
Description=RawrZ Security Platform
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=true
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$APP_DIR
ExecStart=/usr/local/bin/docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
ExecStop=/usr/local/bin/docker-compose -f docker-compose.yml -f docker-compose.prod.yml down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable rawrz-security.service
    
    success "Systemd services created successfully"
}

# Setup monitoring
setup_monitoring() {
    log "Setting up monitoring..."
    
    cd "$APP_DIR"
    
    # Create monitoring directory
    mkdir -p monitoring
    
    # Create Prometheus configuration
    cat > monitoring/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  # - "first_rules.yml"
  # - "second_rules.yml"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'rawrz-app'
    static_configs:
      - targets: ['rawrz-app:3000']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']

  - job_name: 'docker'
    static_configs:
      - targets: ['localhost:9323']
EOF

    # Create Loki configuration
    cat > monitoring/loki-config.yml << 'EOF'
auth_enabled: false

server:
  http_listen_port: 3100

ingester:
  lifecycler:
    address: 127.0.0.1
    ring:
      kvstore:
        store: inmemory
      replication_factor: 1
    final_sleep: 0s

schema_config:
  configs:
    - from: 2020-10-24
      store: boltdb
      object_store: filesystem
      schema: v11
      index:
        prefix: index_
        period: 168h

storage_config:
  boltdb:
    directory: /loki/index

  filesystem:
    directory: /loki/chunks

limits_config:
  enforce_metric_name: false
  reject_old_samples: true
  reject_old_samples_max_age: 168h

chunk_store_config:
  max_look_back_period: 0s

table_manager:
  retention_deletes_enabled: false
  retention_period: 0s
EOF

    chown -R "$SERVICE_USER:$SERVICE_USER" monitoring/
    
    success "Monitoring configuration created successfully"
}

# Setup log rotation
setup_log_rotation() {
    log "Setting up log rotation..."
    
    cat > /etc/logrotate.d/rawrz-security << 'EOF'
/var/log/rawrz-deployment.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
}

/opt/rawrz-data/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 rawrz rawrz
}
EOF

    success "Log rotation configured successfully"
}

# Setup backup script
setup_backup() {
    log "Setting up backup script..."
    
    cat > /opt/backup-rawrz.sh << 'EOF'
#!/bin/bash

# RawrZ Security Platform Backup Script
BACKUP_DIR="/opt/backups/rawrz"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="rawrz_backup_$DATE"

mkdir -p "$BACKUP_DIR"

# Backup application data
cd /opt/rawrz-security
tar -czf "$BACKUP_DIR/${BACKUP_NAME}_app.tar.gz" \
    --exclude='node_modules' \
    --exclude='.git' \
    --exclude='uploads' \
    --exclude='downloads' \
    --exclude='temp' \
    .

# Backup database
docker exec rawrz-database pg_dump -U rawrz_user rawrz_security > "$BACKUP_DIR/${BACKUP_NAME}_db.sql"

# Backup uploads and important data
tar -czf "$BACKUP_DIR/${BACKUP_NAME}_data.tar.gz" /opt/rawrz-data/uploads /opt/rawrz-data/logs

# Clean up old backups (keep only last 7 days)
find "$BACKUP_DIR" -name "rawrz_backup_*" -mtime +7 -delete

echo "Backup completed: $BACKUP_NAME"
EOF

    chmod +x /opt/backup-rawrz.sh
    
    # Add to crontab (daily backup at 2 AM)
    (crontab -l 2>/dev/null; echo "0 2 * * * /opt/backup-rawrz.sh >> /var/log/rawrz-backup.log 2>&1") | crontab -
    
    success "Backup script configured successfully"
}

# Deploy application
deploy_application() {
    log "Deploying application..."
    
    cd "$APP_DIR"
    
    # Build and start services
    sudo -u "$SERVICE_USER" docker-compose -f docker-compose.yml -f docker-compose.prod.yml build
    sudo -u "$SERVICE_USER" docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
    
    # Wait for services to be ready
    log "Waiting for services to be ready..."
    sleep 30
    
    # Check if services are running
    if sudo -u "$SERVICE_USER" docker-compose -f docker-compose.yml -f docker-compose.prod.yml ps | grep -q "Up"; then
        success "Application deployed successfully"
    else
        error "Application deployment failed"
    fi
}

# Setup fail2ban
setup_fail2ban() {
    log "Configuring fail2ban..."
    
    # Configure SSH protection
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 10

[nginx-botsearch]
enabled = true
filter = nginx-botsearch
port = http,https
logpath = /var/log/nginx/access.log
maxretry = 2
EOF

    systemctl restart fail2ban
    systemctl enable fail2ban
    
    success "Fail2ban configured successfully"
}

# Main deployment function
main() {
    log "Starting RawrZ Security Platform deployment..."
    
    check_root
    update_system
    install_docker
    install_nodejs
    install_security_tools
    configure_firewall
    create_service_user
    clone_repository
    setup_environment
    setup_ssl
    configure_nginx
    setup_docker_services
    create_systemd_services
    setup_monitoring
    setup_log_rotation
    setup_backup
    setup_fail2ban
    deploy_application
    
    success "🎉 RawrZ Security Platform deployed successfully!"
    
    log "Deployment Summary:"
    log "- Application URL: https://$(curl -s ifconfig.me)"
    log "- Monitoring: https://$(curl -s ifconfig.me):9090"
    log "- Logs: https://$(curl -s ifconfig.me):3100"
    log "- Application Directory: $APP_DIR"
    log "- Service User: $SERVICE_USER"
    log "- Log File: $LOG_FILE"
    
    log "Next Steps:"
    log "1. Update DNS records to point to this server"
    log "2. Replace self-signed SSL certificates with real ones"
    log "3. Review and customize security settings"
    log "4. Set up monitoring alerts"
    log "5. Test all functionalities"
    
    log "Useful Commands:"
    log "- Check service status: sudo systemctl status rawrz-security"
    log "- View logs: sudo journalctl -u rawrz-security -f"
    log "- Restart services: sudo systemctl restart rawrz-security"
    log "- View containers: docker-compose ps"
    log "- Run backup: /opt/backup-rawrz.sh"
}

# Run main function
main "$@"