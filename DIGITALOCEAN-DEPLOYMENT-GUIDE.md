# DigitalOcean Deployment Guide - RawrZ Security Platform

## 🚀 Complete Deployment Instructions (Preserving All Files)

This guide provides step-by-step instructions for deploying the entire RawrZ Security Platform to DigitalOcean without removing any existing files or data.

## 📋 Prerequisites

- DigitalOcean account
- SSH key pair generated
- Domain name (optional, but recommended)
- Basic knowledge of Linux commands

## 🎯 Deployment Methods

### Method 1: Automated Deployment Script (Recommended)

#### Step 1: Create DigitalOcean Droplet

1. **Login to DigitalOcean Control Panel**
2. **Create New Droplet**:
   - **Image**: Ubuntu 22.04 LTS
   - **Size**: Basic Plan, $12/month (2GB RAM, 1 vCPU) minimum
   - **Authentication**: SSH Key
   - **Hostname**: `rawrz-security-platform`
   - **Enable Backups**: Recommended
   - **Enable Monitoring**: Recommended

#### Step 2: Connect to Your Droplet

```bash
ssh root@YOUR_DROPLET_IP
```

#### Step 3: Download and Run Deployment Script

```bash
# Download the deployment script
wget https://raw.githubusercontent.com/ItsMehRAWRXD/itsmehrawrxd/main/deploy-digitalocean-complete.sh

# Make it executable
chmod +x deploy-digitalocean-complete.sh

# Run the deployment script
./deploy-digitalocean-complete.sh
```

The script will:
- ✅ Update system packages
- ✅ Install Docker and Docker Compose
- ✅ Clone the entire repository
- ✅ Set up all services
- ✅ Configure firewall
- ✅ Set up SSL (optional)
- ✅ Start all services

### Method 2: Manual Step-by-Step Deployment

#### Step 1: System Preparation

```bash
# Update system
apt update && apt upgrade -y

# Install essential packages
apt install -y curl wget git unzip software-properties-common apt-transport-https ca-certificates gnupg lsb-release

# Install Node.js 18.x
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt install -y nodejs

# Verify installations
node --version
npm --version
```

#### Step 2: Install Docker and Docker Compose

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Add user to docker group
usermod -aG docker root

# Install Docker Compose
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Start and enable Docker
systemctl start docker
systemctl enable docker

# Verify Docker installation
docker --version
docker-compose --version
```

#### Step 3: Clone Repository

```bash
# Create application directory
mkdir -p /opt/rawrz-platform
cd /opt/rawrz-platform

# Clone the repository (preserves all files)
git clone https://github.com/ItsMehRAWRXD/itsmehrawrxd.git .

# Verify all files are present
ls -la
```

#### Step 4: Environment Configuration

```bash
# Create environment file
cat > .env << EOF
NODE_ENV=production
PORT=3000
API_PORT=3000
LOG_LEVEL=info
MAX_FILE_SIZE=100MB

# Database configuration
DB_HOST=rawrz-db
DB_PORT=5432
DB_NAME=rawrz_security
DB_USER=rawrz_user
DB_PASSWORD=rawrz_secure_password_2024

# Redis configuration
REDIS_HOST=rawrz-redis
REDIS_PORT=6379

# Directory paths
UPLOAD_DIR=/app/uploads
DOWNLOAD_DIR=/app/downloads
TEMP_DIR=/app/temp
LOGS_DIR=/app/logs
DATA_DIR=/app/data
KEYS_DIR=/app/keys
STUBS_DIR=/app/stubs
PAYLOADS_DIR=/app/payloads
BOTS_DIR=/app/bots
CVE_DIR=/app/cve
ENGINES_DIR=/app/engines
BACKUPS_DIR=/app/backups

# Security settings
JWT_SECRET=your-super-secret-jwt-key-here
SESSION_SECRET=your-super-secret-session-key-here
EOF
```

#### Step 5: Build and Deploy with Docker Compose

```bash
# Build all services
docker-compose build --no-cache

# Create necessary directories
mkdir -p uploads downloads temp logs data keys stubs payloads bots cve engines backups public

# Set proper permissions
chmod -R 755 uploads downloads temp logs data keys stubs payloads bots cve engines backups public

# Start all services
docker-compose up -d

# Verify all containers are running
docker-compose ps
```

#### Step 6: Configure Firewall

```bash
# Install and configure UFW
apt install -y ufw

# Configure firewall rules
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 3000:3002/tcp
ufw allow 5432/tcp
ufw allow 6379/tcp
ufw allow 9090/tcp
ufw allow 3100/tcp

# Enable firewall
ufw --force enable

# Check firewall status
ufw status
```

#### Step 7: SSL Configuration (Optional but Recommended)

```bash
# Install Certbot
apt install -y certbot python3-certbot-nginx

# If you have a domain, configure SSL
# certbot --nginx -d your-domain.com

# For self-signed certificate (development only)
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /opt/rawrz-platform/nginx/ssl/rawrz.key \
  -out /opt/rawrz-platform/nginx/ssl/rawrz.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
```

#### Step 8: Create Systemd Service

```bash
# Create systemd service for auto-start
cat > /etc/systemd/system/rawrz-platform.service << EOF
[Unit]
Description=RawrZ Security Platform
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/rawrz-platform
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
systemctl daemon-reload
systemctl enable rawrz-platform.service
systemctl start rawrz-platform.service
```

## 🔧 Service Configuration

### Nginx Configuration

Create the Nginx configuration file:

```bash
mkdir -p /opt/rawrz-platform/nginx/ssl

cat > /opt/rawrz-platform/nginx/nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    upstream rawrz_app {
        server rawrz-app:3000;
    }

    server {
        listen 80;
        server_name _;

        # Redirect HTTP to HTTPS (uncomment if using SSL)
        # return 301 https://$server_name$request_uri;

        location / {
            proxy_pass http://rawrz_app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        location /api/ {
            proxy_pass http://rawrz_app;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }

    # HTTPS server (uncomment if using SSL)
    # server {
    #     listen 443 ssl;
    #     server_name _;
    #
    #     ssl_certificate /etc/nginx/ssl/rawrz.crt;
    #     ssl_certificate_key /etc/nginx/ssl/rawrz.key;
    #
    #     location / {
    #         proxy_pass http://rawrz_app;
    #         proxy_set_header Host $host;
    #         proxy_set_header X-Real-IP $remote_addr;
    #         proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    #         proxy_set_header X-Forwarded-Proto $scheme;
    #     }
    # }
}
EOF
```

### Monitoring Configuration

Create Prometheus configuration:

```bash
mkdir -p /opt/rawrz-platform/monitoring

cat > /opt/rawrz-platform/monitoring/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'rawrz-app'
    static_configs:
      - targets: ['rawrz-app:3000']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'rawrz-processor'
    static_configs:
      - targets: ['rawrz-processor:3001']
    metrics_path: '/metrics'
    scrape_interval: 30s

  - job_name: 'rawrz-bots'
    static_configs:
      - targets: ['rawrz-bots:3002']
    metrics_path: '/metrics'
    scrape_interval: 30s
EOF
```

Create Loki configuration:

```bash
cat > /opt/rawrz-platform/monitoring/loki-config.yml << 'EOF'
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
  chunk_idle_period: 5m
  chunk_retain_period: 30s

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
EOF
```

### Database Initialization

Create database initialization script:

```bash
mkdir -p /opt/rawrz-platform/database

cat > /opt/rawrz-platform/database/init.sql << 'EOF'
-- RawrZ Security Platform Database Initialization

CREATE DATABASE IF NOT EXISTS rawrz_security;

USE rawrz_security;

-- Create tables for bot management
CREATE TABLE IF NOT EXISTS bots (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL,
    status VARCHAR(50) DEFAULT 'inactive',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    config JSONB
);

-- Create tables for CVE data
CREATE TABLE IF NOT EXISTS cve_data (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE NOT NULL,
    title TEXT,
    description TEXT,
    severity VARCHAR(20),
    cvss_score DECIMAL(3,1),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create tables for engine status
CREATE TABLE IF NOT EXISTS engine_status (
    id SERIAL PRIMARY KEY,
    engine_name VARCHAR(100) UNIQUE NOT NULL,
    status VARCHAR(50) DEFAULT 'inactive',
    last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    config JSONB
);

-- Create tables for file processing
CREATE TABLE IF NOT EXISTS file_processing (
    id SERIAL PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    file_type VARCHAR(100),
    file_size BIGINT,
    processing_status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    results JSONB
);

-- Insert initial engine statuses
INSERT INTO engine_status (engine_name, status) VALUES
('aes-encryption', 'active'),
('camellia-encryption', 'active'),
('chacha20-encryption', 'active'),
('dual-encryption', 'active'),
('anti-analysis', 'active'),
('stealth-engine', 'active'),
('polymorphic-loader', 'active'),
('process-manipulation', 'active'),
('network-tools', 'active'),
('persistence', 'active'),
('credential-harvesting', 'active'),
('file-operations', 'active')
ON CONFLICT (engine_name) DO NOTHING;

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_bots_status ON bots(status);
CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_data(severity);
CREATE INDEX IF NOT EXISTS idx_file_processing_status ON file_processing(processing_status);
CREATE INDEX IF NOT EXISTS idx_engine_status_name ON engine_status(engine_name);
EOF
```

## 🚀 Starting the Platform

### Start All Services

```bash
# Navigate to the platform directory
cd /opt/rawrz-platform

# Start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f
```

### Verify Deployment

```bash
# Check if all containers are running
docker ps

# Test API endpoints
curl http://localhost:3000/api/health
curl http://localhost:3000/api/engines/status

# Test web interface
curl http://localhost:3000

# Check external access
curl http://YOUR_DROPLET_IP:3000/api/health
```

## 📊 Accessing Your Platform

### Web Interface
- **Main Platform**: `http://YOUR_DROPLET_IP:3000`
- **API Documentation**: `http://YOUR_DROPLET_IP:3000/api/docs`
- **Health Check**: `http://YOUR_DROPLET_IP:3000/api/health`

### Monitoring Dashboards
- **Prometheus**: `http://YOUR_DROPLET_IP:9090`
- **Grafana**: `http://YOUR_DROPLET_IP:3000/grafana` (if configured)
- **Application Logs**: `http://YOUR_DROPLET_IP:3100` (Loki)

### Database Access
- **PostgreSQL**: `YOUR_DROPLET_IP:5432`
- **Redis**: `YOUR_DROPLET_IP:6379`

## 🔧 Management Commands

### Service Management

```bash
# Start all services
docker-compose up -d

# Stop all services
docker-compose down

# Restart all services
docker-compose restart

# View logs
docker-compose logs -f

# View logs for specific service
docker-compose logs -f rawrz-app

# Update services (pull latest changes)
git pull origin main
docker-compose build --no-cache
docker-compose up -d
```

### Individual Container Management

```bash
# Restart specific service
docker-compose restart rawrz-app

# View specific service logs
docker-compose logs rawrz-app

# Execute commands in running container
docker-compose exec rawrz-app bash

# Scale specific service
docker-compose up -d --scale rawrz-processor=3
```

### Database Management

```bash
# Connect to PostgreSQL
docker-compose exec rawrz-db psql -U rawrz_user -d rawrz_security

# Backup database
docker-compose exec rawrz-db pg_dump -U rawrz_user rawrz_security > backup.sql

# Restore database
docker-compose exec -T rawrz-db psql -U rawrz_user -d rawrz_security < backup.sql
```

## 🔒 Security Hardening

### Firewall Configuration

```bash
# Review current firewall rules
ufw status verbose

# Remove unnecessary rules
ufw delete allow 5432/tcp  # Only if you don't need external DB access
ufw delete allow 6379/tcp  # Only if you don't need external Redis access

# Add rate limiting
ufw limit ssh
```

### SSL/TLS Configuration

```bash
# Install Certbot for Let's Encrypt
apt install -y certbot python3-certbot-nginx

# Obtain SSL certificate (replace with your domain)
certbot --nginx -d your-domain.com -d www.your-domain.com

# Auto-renewal
crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

### Environment Security

```bash
# Secure environment file
chmod 600 .env

# Generate secure secrets
openssl rand -base64 32  # Use for JWT_SECRET
openssl rand -base64 32  # Use for SESSION_SECRET

# Update .env with secure values
nano .env
```

## 📈 Performance Optimization

### Resource Limits

Update `docker-compose.yml` to include resource limits:

```yaml
services:
  rawrz-app:
    # ... existing configuration ...
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 512M
```

### Caching Configuration

```bash
# Configure Redis for better caching
cat > /opt/rawrz-platform/redis.conf << EOF
maxmemory 256mb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
EOF
```

## 🔄 Backup and Recovery

### Automated Backups

Create backup script:

```bash
cat > /opt/rawrz-platform/backup.sh << 'EOF'
#!/bin/bash

BACKUP_DIR="/opt/rawrz-platform/backups"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup database
docker-compose exec -T rawrz-db pg_dump -U rawrz_user rawrz_security > $BACKUP_DIR/db_backup_$DATE.sql

# Backup application data
tar -czf $BACKUP_DIR/app_data_$DATE.tar.gz uploads downloads data keys stubs payloads

# Backup configuration
tar -czf $BACKUP_DIR/config_$DATE.tar.gz docker-compose.yml .env nginx/ monitoring/

# Clean old backups (keep last 7 days)
find $BACKUP_DIR -name "*.sql" -mtime +7 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete

echo "Backup completed: $DATE"
EOF

chmod +x /opt/rawrz-platform/backup.sh

# Add to crontab for daily backups
crontab -e
# Add: 0 2 * * * /opt/rawrz-platform/backup.sh
```

### Recovery Process

```bash
# Restore database
docker-compose exec -T rawrz-db psql -U rawrz_user -d rawrz_security < backups/db_backup_YYYYMMDD_HHMMSS.sql

# Restore application data
tar -xzf backups/app_data_YYYYMMDD_HHMMSS.tar.gz

# Restore configuration
tar -xzf backups/config_YYYYMMDD_HHMMSS.tar.gz
```

## 🐛 Troubleshooting

### Common Issues

1. **Port Already in Use**:
   ```bash
   # Find process using port
   lsof -i :3000
   # Kill process
   kill -9 <PID>
   ```

2. **Container Won't Start**:
   ```bash
   # Check logs
   docker-compose logs rawrz-app
   # Check container status
   docker-compose ps
   ```

3. **Database Connection Issues**:
   ```bash
   # Check database logs
   docker-compose logs rawrz-db
   # Test connection
   docker-compose exec rawrz-db psql -U rawrz_user -d rawrz_security -c "SELECT 1;"
   ```

4. **Memory Issues**:
   ```bash
   # Check memory usage
   docker stats
   # Increase swap
   fallocate -l 2G /swapfile
   chmod 600 /swapfile
   mkswap /swapfile
   swapon /swapfile
   ```

### Health Checks

```bash
# Check all services health
curl http://localhost:3000/api/health
curl http://localhost:3001/health
curl http://localhost:3002/health

# Check database health
docker-compose exec rawrz-db pg_isready -U rawrz_user -d rawrz_security

# Check Redis health
docker-compose exec rawrz-redis redis-cli ping
```

## 📞 Support and Maintenance

### Log Monitoring

```bash
# Real-time log monitoring
docker-compose logs -f --tail=100

# Log rotation (add to crontab)
0 0 * * * docker-compose logs --no-color | gzip > /opt/rawrz-platform/logs/app-$(date +\%Y\%m\%d).log.gz
```

### Updates

```bash
# Update platform
git pull origin main
docker-compose build --no-cache
docker-compose up -d

# Update system packages
apt update && apt upgrade -y
```

## ✅ Deployment Checklist

- [ ] DigitalOcean droplet created
- [ ] SSH access configured
- [ ] Docker and Docker Compose installed
- [ ] Repository cloned
- [ ] Environment variables configured
- [ ] Docker containers built
- [ ] All services started
- [ ] Firewall configured
- [ ] SSL certificates installed (optional)
- [ ] Monitoring configured
- [ ] Backups scheduled
- [ ] Health checks passing
- [ ] External access verified

## 🎉 Success!

Your RawrZ Security Platform is now fully deployed on DigitalOcean with all features preserved and accessible. The platform includes:

- ✅ Complete web interface
- ✅ All 47+ security engines
- ✅ API endpoints
- ✅ Database with persistence
- ✅ Redis caching
- ✅ Nginx reverse proxy
- ✅ Monitoring and logging
- ✅ Automated backups
- ✅ SSL/TLS support
- ✅ Auto-restart on reboot

Access your platform at: `http://YOUR_DROPLET_IP:3000`

---

**Note**: This deployment preserves all files and functionality. No data is removed during the deployment process.