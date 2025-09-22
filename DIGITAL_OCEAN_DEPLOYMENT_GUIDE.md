# Digital Ocean Deployment Guide

## 🚀 Complete Deployment Guide for RawrZ Security Platform

This comprehensive guide covers deploying the RawrZ Security Platform to Digital Ocean using our automated deployment tools.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Digital Ocean Setup](#digital-ocean-setup)
3. [Deployment Options](#deployment-options)
4. [Interactive Deployment App](#interactive-deployment-app)
5. [Automated Deployment](#automated-deployment)
6. [Manual Deployment](#manual-deployment)
7. [Configuration](#configuration)
8. [SSL/TLS Setup](#ssltls-setup)
9. [Monitoring & Logging](#monitoring--logging)
10. [Backup & Recovery](#backup--recovery)
11. [Security Hardening](#security-hardening)
12. [Troubleshooting](#troubleshooting)
13. [Maintenance](#maintenance)

## Prerequisites

### System Requirements
- **OS**: Ubuntu 20.04+ or Debian 11+
- **RAM**: 2GB minimum (4GB recommended for production)
- **Storage**: 20GB minimum (50GB recommended)
- **CPU**: 1 vCPU minimum (2 vCPU recommended)

### Network Requirements
- **Public IP**: Required for external access
- **Domain**: Recommended for SSL setup
- **Ports**: 22 (SSH), 80 (HTTP), 443 (HTTPS), 3000 (Application)

### Software Requirements
- **Docker**: 20.10+ (automatically installed)
- **Docker Compose**: 2.0+ (automatically installed)
- **Git**: For repository cloning
- **curl**: For health checks and downloads

## Digital Ocean Setup

### 1. Create a Droplet

```bash
# Using Digital Ocean CLI (doctl)
doctl compute droplet create rawrz-platform \
  --image ubuntu-20-04-x64 \
  --size s-2vcpu-4gb \
  --region nyc1 \
  --ssh-keys YOUR_SSH_KEY_ID \
  --enable-monitoring \
  --enable-ipv6 \
  --tag-name production
```

### 2. Configure DNS (Optional but Recommended)

```bash
# Point your domain to the droplet IP
# A Record: yourdomain.com -> YOUR_DROPLET_IP
# CNAME: www.yourdomain.com -> yourdomain.com
```

### 3. Initial Server Setup

```bash
# SSH into your droplet
ssh root@YOUR_DROPLET_IP

# Update system
apt update && apt upgrade -y

# Install essential packages
apt install -y curl wget git htop nano ufw fail2ban

# Configure firewall
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 3000/tcp
ufw --force enable

# Configure fail2ban for SSH protection
systemctl enable fail2ban
systemctl start fail2ban
```

## Deployment Options

### Option 1: Interactive Deployment App (Recommended)

Our interactive deployment app provides a user-friendly interface for deployment configuration.

```bash
# Download and run the deployment app
curl -fsSL https://raw.githubusercontent.com/ItsMehRAWRXD/itsmehrawrxd/main/deploy-app.js -o deploy-app.js
chmod +x deploy-app.js
node deploy-app.js
```

**Features:**
- Interactive menu system
- Configuration validation
- Real-time progress feedback
- Automatic error handling
- SSL setup assistance
- Monitoring configuration

### Option 2: Shell Script Deployment

For users who prefer traditional shell scripts:

```bash
# Download and run the deployment script
curl -fsSL https://raw.githubusercontent.com/ItsMehRAWRXD/itsmehrawrxd/main/deploy-digital-ocean.sh -o deploy.sh
chmod +x deploy.sh
./deploy.sh
```

### Option 3: GitHub Actions (Automated)

Set up automated deployment using GitHub Actions:

1. **Configure Secrets** in your GitHub repository:
   - `DIGITALOCEAN_HOST`: Your droplet IP
   - `DIGITALOCEAN_USERNAME`: SSH username
   - `DIGITALOCEAN_SSH_KEY`: Private SSH key

2. **Trigger Deployment**:
   - Push to main branch
   - Manual workflow dispatch
   - Pull request merge

## Interactive Deployment App

### Menu Options

```
📋 Deployment Options:
1. 🚀 Quick Deploy (Default Configuration)
2. ⚙️  Custom Configuration
3. 🔧 Advanced Setup with SSL
4. 📊 Monitoring & Backup Setup
5. 🐳 Docker Compose Deployment
6. 🔄 Update Existing Deployment
7. 📋 View Configuration
8. 🧪 Test Deployment
9. 🔍 System Diagnostics
0. ❌ Exit
```

### Quick Deploy Process

1. **System Check**: Verifies Digital Ocean environment
2. **System Update**: Updates packages and dependencies
3. **Docker Installation**: Installs Docker and Docker Compose
4. **Repository Setup**: Clones or updates application code
5. **Container Build**: Builds Docker image
6. **Deployment**: Starts application container
7. **Firewall Setup**: Configures security rules
8. **Health Check**: Verifies deployment success

### Custom Configuration

```bash
# App name [rawrz-security-platform]: 
# Port [3000]: 
# Domain (optional): yourdomain.com
# Repository URL [https://github.com/ItsMehRAWRXD/itsmehrawrxd.git]: 
# Environment [production]: 
# Enable SSL/TLS? (y/N): y
# Enable monitoring? (y/N): y
# Enable backups? (y/N): y
```

## Automated Deployment

### GitHub Actions Workflow

The repository includes a comprehensive GitHub Actions workflow that:

1. **Tests**: Runs automated tests
2. **Builds**: Creates Docker images
3. **Pushes**: Uploads to GitHub Container Registry
4. **Deploys**: Automatically deploys to Digital Ocean
5. **Notifies**: Sends deployment status notifications

### Workflow Configuration

```yaml
# .github/workflows/deploy-digital-ocean.yml
name: Deploy to Digital Ocean

on:
  push:
    branches: [ main, master ]
  workflow_dispatch:
    inputs:
      environment:
        description: 'Deployment environment'
        required: true
        default: 'production'
        type: choice
        options:
        - production
        - staging
        - development
```

### Required Secrets

Configure these in your GitHub repository settings:

| Secret | Description | Example |
|--------|-------------|---------|
| `DIGITALOCEAN_HOST` | Droplet IP address | `157.245.123.45` |
| `DIGITALOCEAN_USERNAME` | SSH username | `root` |
| `DIGITALOCEAN_SSH_KEY` | Private SSH key | `-----BEGIN OPENSSH PRIVATE KEY-----` |
| `SLACK_WEBHOOK` | Slack notifications | `https://hooks.slack.com/...` |

## Manual Deployment

### Step-by-Step Manual Process

```bash
# 1. Update system
apt update && apt upgrade -y

# 2. Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
usermod -aG docker $USER
systemctl enable docker
systemctl start docker

# 3. Install Docker Compose
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# 4. Create application directory
mkdir -p /opt/rawrz-platform
cd /opt/rawrz-platform

# 5. Clone repository
git clone https://github.com/ItsMehRAWRXD/itsmehrawrxd.git .

# 6. Build Docker image
docker build -t rawrz-security-platform:latest .

# 7. Create necessary directories
mkdir -p logs data uploads downloads temp keys stubs payloads bots cve engines backups

# 8. Run application
docker run -d \
  --name rawrz-app \
  --restart unless-stopped \
  -p 3000:3000 \
  -v /opt/rawrz-platform/logs:/app/logs \
  -v /opt/rawrz-platform/data:/app/data \
  -e NODE_ENV=production \
  rawrz-security-platform:latest

# 9. Configure firewall
ufw allow 3000/tcp
ufw --force enable

# 10. Verify deployment
curl -f http://localhost:3000/health
```

### Docker Compose Deployment

```bash
# Use the provided docker-compose.yml
docker-compose up -d --build

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

## Configuration

### Environment Variables

```bash
# Application Configuration
NODE_ENV=production
PORT=3000
API_PORT=3000
LOG_LEVEL=info

# Database Configuration
DB_HOST=rawrz-db
DB_PORT=5432
DB_NAME=rawrz_security
DB_USER=rawrz_user
DB_PASSWORD=your_secure_password

# Redis Configuration
REDIS_HOST=rawrz-redis
REDIS_PORT=6379

# File Upload Configuration
MAX_FILE_SIZE=100MB
UPLOAD_DIR=/app/uploads
DOWNLOAD_DIR=/app/downloads
TEMP_DIR=/app/temp

# Security Configuration
JWT_SECRET=your_jwt_secret
ENCRYPTION_KEY=your_encryption_key
SESSION_SECRET=your_session_secret
```

### Configuration File

Create `/opt/rawrz-platform/.env`:

```bash
# Copy from template
cp .env.example .env

# Edit configuration
nano .env
```

### Docker Compose Configuration

Customize `docker-compose.override.yml`:

```yaml
version: '3.8'

services:
  rawrz-app:
    environment:
      - NODE_ENV=production
      - CUSTOM_SETTING=value
    volumes:
      - ./custom-data:/app/custom-data
    ports:
      - "3001:3001"  # Additional port

  rawrz-db:
    environment:
      - POSTGRES_DB=rawrz_security
      - POSTGRES_USER=rawrz_user
      - POSTGRES_PASSWORD=your_secure_password
    volumes:
      - rawrz_db_data:/var/lib/postgresql/data

volumes:
  rawrz_db_data:
    driver: local
```

## SSL/TLS Setup

### Automatic SSL Setup (Recommended)

The deployment app automatically configures SSL using Let's Encrypt:

```bash
# Run advanced setup with SSL
./deploy-digital-ocean.sh
# Select option 3: Advanced Setup with SSL
# Enter your domain when prompted
```

### Manual SSL Setup

```bash
# 1. Install Nginx
apt install -y nginx

# 2. Install Certbot
apt install -y certbot python3-certbot-nginx

# 3. Configure Nginx
cat > /etc/nginx/sites-available/rawrz-platform << EOF
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

# 4. Enable site
ln -s /etc/nginx/sites-available/rawrz-platform /etc/nginx/sites-enabled/
nginx -t
systemctl reload nginx

# 5. Generate SSL certificate
certbot --nginx -d yourdomain.com --non-interactive --agree-tos --email admin@yourdomain.com

# 6. Test renewal
certbot renew --dry-run
```

### SSL Configuration Best Practices

```nginx
# Additional security headers
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options DENY always;
add_header X-Content-Type-Options nosniff always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# SSL configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
```

## Monitoring & Logging

### Prometheus Setup

```bash
# Create monitoring directory
mkdir -p /opt/monitoring
cd /opt/monitoring

# Create Prometheus configuration
cat > prometheus.yml << EOF
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'rawrz-app'
    static_configs:
      - targets: ['localhost:3000']
  
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']
EOF

# Create Docker Compose for monitoring
cat > docker-compose.yml << EOF
version: '3.8'
services:
  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=200h'
      - '--web.enable-lifecycle'

  grafana:
    image: grafana/grafana
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana_data:/var/lib/grafana

  node-exporter:
    image: prom/node-exporter
    ports:
      - "9100:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.rootfs=/rootfs'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'

volumes:
  prometheus_data:
  grafana_data:
EOF

# Start monitoring stack
docker-compose up -d
```

### Grafana Dashboards

Access Grafana at `http://your-server:3001`:
- **Username**: `admin`
- **Password**: `admin` (change after first login)

Import dashboards:
1. Go to Dashboards → Import
2. Use dashboard ID `1860` for Node Exporter
3. Configure Prometheus as data source: `http://prometheus:9090`

### Log Management

```bash
# Configure log rotation
cat > /etc/logrotate.d/rawrz-platform << EOF
/opt/rawrz-platform/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
    postrotate
        docker restart rawrz-app
    endscript
}
EOF

# View logs
docker logs rawrz-app -f
docker-compose logs -f rawrz-app
```

## Backup & Recovery

### Automated Backup Setup

```bash
# Create backup script
cat > /opt/backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/opt/backups"
APP_DIR="/opt/rawrz-platform"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup application data
tar -czf $BACKUP_DIR/rawrz_backup_$DATE.tar.gz \
  -C $APP_DIR \
  --exclude=node_modules \
  --exclude=.git \
  .

# Backup database
docker exec rawrz-db pg_dump -U rawrz_user rawrz_security > $BACKUP_DIR/db_backup_$DATE.sql

# Backup configuration
cp $APP_DIR/.env $BACKUP_DIR/config_$DATE.env

# Keep only last 7 days of backups
find $BACKUP_DIR -name "rawrz_backup_*.tar.gz" -mtime +7 -delete
find $BACKUP_DIR -name "db_backup_*.sql" -mtime +7 -delete
find $BACKUP_DIR -name "config_*.env" -mtime +7 -delete

echo "Backup completed: $DATE"
EOF

chmod +x /opt/backup.sh

# Add to crontab
echo "0 2 * * * /opt/backup.sh" | crontab -
```

### Manual Backup

```bash
# Application backup
tar -czf rawrz_backup_$(date +%Y%m%d_%H%M%S).tar.gz \
  -C /opt/rawrz-platform \
  --exclude=node_modules \
  --exclude=.git \
  .

# Database backup
docker exec rawrz-db pg_dump -U rawrz_user rawrz_security > db_backup_$(date +%Y%m%d_%H%M%S).sql

# Docker volumes backup
docker run --rm -v rawrz_db_data:/data -v $(pwd):/backup alpine tar czf /backup/db_volume_backup.tar.gz -C /data .
```

### Recovery Process

```bash
# Restore application
tar -xzf rawrz_backup_YYYYMMDD_HHMMSS.tar.gz -C /opt/rawrz-platform/

# Restore database
docker exec -i rawrz-db psql -U rawrz_user -d rawrz_security < db_backup_YYYYMMDD_HHMMSS.sql

# Restore Docker volumes
docker run --rm -v rawrz_db_data:/data -v $(pwd):/backup alpine tar xzf /backup/db_volume_backup.tar.gz -C /data

# Restart services
docker-compose restart
```

## Security Hardening

### System Hardening

```bash
# 1. Update system packages
apt update && apt upgrade -y

# 2. Install security tools
apt install -y ufw fail2ban rkhunter chkrootkit unattended-upgrades

# 3. Configure automatic security updates
cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
EOF

# 4. Configure fail2ban
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
EOF

systemctl enable fail2ban
systemctl start fail2ban

# 5. Configure UFW firewall
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 3000/tcp
ufw --force enable

# 6. Disable root login (optional)
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd
```

### Docker Security

```bash
# 1. Create non-root user for Docker
useradd -m -s /bin/bash dockeruser
usermod -aG docker dockeruser

# 2. Configure Docker daemon security
cat > /etc/docker/daemon.json << EOF
{
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "storage-driver": "overlay2",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOF

systemctl restart docker

# 3. Scan Docker images for vulnerabilities
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image rawrz-security-platform:latest
```

### Application Security

```bash
# 1. Set secure file permissions
chmod 600 /opt/rawrz-platform/.env
chmod 755 /opt/rawrz-platform/logs
chmod 700 /opt/rawrz-platform/keys

# 2. Configure application security headers
cat > /opt/rawrz-platform/security-config.js << EOF
module.exports = {
  helmet: {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    }
  }
};
EOF

# 3. Enable rate limiting
cat > /opt/rawrz-platform/rate-limit-config.js << EOF
module.exports = {
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
};
EOF
```

## Troubleshooting

### Common Issues

#### 1. Container Won't Start

```bash
# Check container logs
docker logs rawrz-app

# Check container status
docker ps -a

# Check system resources
free -h
df -h

# Check port availability
netstat -tlnp | grep 3000
```

#### 2. SSL Certificate Issues

```bash
# Check domain DNS
nslookup yourdomain.com

# Test certificate
openssl s_client -connect yourdomain.com:443 -servername yourdomain.com

# Check certbot logs
journalctl -u certbot

# Renew certificate manually
certbot renew --force-renewal
```

#### 3. Database Connection Issues

```bash
# Check database container
docker ps | grep rawrz-db

# Check database logs
docker logs rawrz-db

# Test database connection
docker exec -it rawrz-db psql -U rawrz_user -d rawrz_security -c "SELECT version();"

# Check network connectivity
docker network ls
docker network inspect rawrz-network
```

#### 4. Performance Issues

```bash
# Check system resources
htop
iostat 1
docker stats

# Check application logs
docker logs rawrz-app --tail 100

# Check database performance
docker exec -it rawrz-db psql -U rawrz_user -d rawrz_security -c "
SELECT 
  schemaname,
  tablename,
  attname,
  n_distinct,
  correlation
FROM pg_stats
WHERE schemaname = 'public'
ORDER BY n_distinct DESC;
"
```

### Log Analysis

```bash
# Application logs
docker logs rawrz-app --since 1h

# System logs
journalctl -u docker --since 1h

# Nginx logs (if using reverse proxy)
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# Database logs
docker logs rawrz-db --since 1h
```

### Health Checks

```bash
# Application health
curl -f http://localhost:3000/health

# Database health
docker exec rawrz-db pg_isready -U rawrz_user -d rawrz_security

# Redis health
docker exec rawrz-redis redis-cli ping

# Monitoring health
curl -f http://localhost:9090/-/healthy  # Prometheus
curl -f http://localhost:3001/api/health  # Grafana
```

## Maintenance

### Regular Maintenance Tasks

#### Daily Tasks

```bash
# Check application status
docker ps
curl -f http://localhost:3000/health

# Check disk space
df -h

# Check logs for errors
docker logs rawrz-app --since 24h | grep -i error
```

#### Weekly Tasks

```bash
# Update system packages
apt update && apt list --upgradable

# Update Docker images
docker pull rawrz-security-platform:latest
docker-compose pull

# Clean up Docker resources
docker system prune -f

# Check backup integrity
ls -la /opt/backups/
```

#### Monthly Tasks

```bash
# Full system update
apt update && apt upgrade -y

# Security audit
rkhunter --check
chkrootkit

# Performance review
docker stats --no-stream
df -h
free -h

# Review and rotate logs
logrotate -f /etc/logrotate.d/rawrz-platform
```

### Update Procedures

#### Application Updates

```bash
# 1. Backup current deployment
/opt/backup.sh

# 2. Pull latest changes
cd /opt/rawrz-platform
git pull

# 3. Rebuild and restart
docker-compose down
docker-compose up -d --build

# 4. Verify deployment
curl -f http://localhost:3000/health
```

#### System Updates

```bash
# 1. Schedule maintenance window
# 2. Backup everything
/opt/backup.sh

# 3. Update system
apt update && apt upgrade -y

# 4. Restart services if needed
systemctl restart docker
docker-compose restart

# 5. Verify everything works
curl -f http://localhost:3000/health
```

### Scaling

#### Horizontal Scaling

```bash
# Scale application containers
docker-compose up -d --scale rawrz-app=3

# Configure load balancer
cat > /etc/nginx/sites-available/rawrz-load-balancer << EOF
upstream rawrz_backend {
    server localhost:3000;
    server localhost:3001;
    server localhost:3002;
}

server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass http://rawrz_backend;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
```

#### Vertical Scaling

```bash
# Increase container resources
docker update --cpus="2.0" --memory="4g" rawrz-app

# Monitor resource usage
docker stats rawrz-app
```

---

## Support

For additional support:

1. **Check Documentation**: Review this guide thoroughly
2. **GitHub Issues**: Create an issue in the repository
3. **Logs**: Gather relevant log files
4. **System Info**: Include system specifications
5. **Error Messages**: Provide exact error messages

**Happy Deploying! 🚀**