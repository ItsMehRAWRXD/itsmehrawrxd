# RawrZ Security Platform - Digital Ocean Deployment Application

🚀 **Interactive deployment tool for Digital Ocean droplets with automated setup, SSL configuration, monitoring, and backup systems.**

## Features

- 🎯 **Interactive Interface**: User-friendly menu-driven deployment process
- 🐳 **Docker Support**: Full Docker and Docker Compose integration
- 🔒 **SSL/TLS Setup**: Automatic SSL certificate generation with Let's Encrypt
- 📊 **Monitoring**: Prometheus and Grafana monitoring stack
- 💾 **Backup System**: Automated daily backups with retention policies
- 🔧 **Custom Configuration**: Flexible configuration options
- 🧪 **Health Checks**: Built-in deployment testing and diagnostics
- 🔄 **Update Management**: Easy update and rollback capabilities

## Quick Start

### Option 1: Run as Node.js Application

```bash
# Install dependencies
npm install

# Run the deployment app
node deploy-app.js
```

### Option 2: Run as Shell Script

```bash
# Make executable and run
chmod +x deploy-digital-ocean.sh
./deploy-digital-ocean.sh
```

### Option 3: Install Globally

```bash
# Install as global npm package
npm install -g ./deploy-app-package.json

# Run from anywhere
rawrz-deploy
```

## Deployment Options

### 1. 🚀 Quick Deploy
- Default configuration
- Automatic Docker installation
- Basic firewall setup
- Production-ready deployment

### 2. ⚙️ Custom Configuration
- Custom app name and port
- Repository selection
- Environment configuration
- Feature toggles (SSL, monitoring, backups)

### 3. 🔧 Advanced Setup with SSL
- Full custom configuration
- SSL/TLS certificate setup
- Domain configuration
- Advanced security settings

### 4. 📊 Monitoring & Backup Setup
- Prometheus metrics collection
- Grafana dashboards
- Automated backup system
- Log aggregation

### 5. 🐳 Docker Compose Deployment
- Multi-service deployment
- Database and Redis setup
- Nginx reverse proxy
- Load balancing

## Configuration

### Environment Variables

```bash
# Application Configuration
APP_NAME=rawrz-security-platform
PORT=3000
DOMAIN=yourdomain.com
REPOSITORY=https://github.com/ItsMehRAWRXD/itsmehrawrxd.git

# SSL Configuration
SSL_ENABLED=true
SSL_EMAIL=admin@yourdomain.com

# Monitoring Configuration
MONITORING_ENABLED=true
GRAFANA_PASSWORD=your_secure_password

# Backup Configuration
BACKUP_ENABLED=true
BACKUP_RETENTION_DAYS=7
```

### Configuration File

The app automatically saves configuration to `/opt/deployment-config.json`:

```json
{
  "appName": "rawrz-security-platform",
  "version": "1.0.0",
  "port": 3000,
  "domain": "yourdomain.com",
  "repository": "https://github.com/ItsMehRAWRXD/itsmehrawrxd.git",
  "dockerImage": "rawrz-security-platform:latest",
  "containerName": "rawrz-app",
  "environment": "production",
  "sslEnabled": true,
  "monitoringEnabled": true,
  "backupEnabled": true,
  "autoUpdate": false
}
```

## Prerequisites

### System Requirements
- Ubuntu 20.04+ or Debian 11+
- 2GB RAM minimum (4GB recommended)
- 20GB disk space minimum
- Root or sudo access

### Network Requirements
- Open ports: 22 (SSH), 80 (HTTP), 443 (HTTPS), 3000 (App)
- Domain name (for SSL setup)
- Public IP address

## Installation Process

### 1. System Update
```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Docker Installation
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
sudo systemctl enable docker
sudo systemctl start docker
```

### 3. Docker Compose Installation
```bash
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### 4. Application Deployment
```bash
# Clone repository
sudo mkdir -p /opt/rawrz-platform
cd /opt/rawrz-platform
sudo git clone https://github.com/ItsMehRAWRXD/itsmehrawrxd.git .

# Build and deploy
sudo docker build -t rawrz-security-platform:latest .
sudo docker run -d --name rawrz-app --restart unless-stopped -p 3000:3000 rawrz-security-platform:latest
```

## Management Commands

### Container Management
```bash
# View logs
docker logs rawrz-app

# Stop application
docker stop rawrz-app

# Restart application
docker restart rawrz-app

# Remove application
docker rm -f rawrz-app
```

### Docker Compose Management
```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# View logs
docker-compose logs -f

# Restart services
docker-compose restart
```

### Backup Management
```bash
# Manual backup
/opt/backup.sh

# View backups
ls -la /opt/backups/

# Restore from backup
tar -xzf /opt/backups/rawrz_backup_YYYYMMDD_HHMMSS.tar.gz -C /opt/rawrz-platform/
```

## Monitoring

### Prometheus Metrics
- **URL**: `http://your-server:9090`
- **Metrics**: Application performance, system resources, custom metrics

### Grafana Dashboards
- **URL**: `http://your-server:3001`
- **Username**: `admin`
- **Password**: `admin` (change after first login)

### Health Checks
```bash
# Application health
curl http://localhost:3000/health

# API test
curl http://localhost:3000/api/simple-test

# Container status
docker ps | grep rawrz-app
```

## SSL/TLS Setup

### Automatic Setup (Recommended)
The deployment app automatically configures SSL using Let's Encrypt:

1. Ensure domain points to your server
2. Run advanced setup with SSL enabled
3. Enter your domain name when prompted
4. SSL certificate is automatically generated and configured

### Manual Setup
```bash
# Install certbot
sudo apt install -y certbot python3-certbot-nginx

# Generate certificate
sudo certbot --nginx -d yourdomain.com --non-interactive --agree-tos --email admin@yourdomain.com

# Test renewal
sudo certbot renew --dry-run
```

## Security Considerations

### Firewall Configuration
```bash
# Allow necessary ports
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 3000/tcp  # Application

# Enable firewall
sudo ufw enable
```

### SSL Security
- Uses Let's Encrypt certificates
- Automatic renewal setup
- Strong cipher suites
- HSTS headers

### Container Security
- Non-root user execution
- Read-only filesystem where possible
- Resource limits
- Security scanning

## Troubleshooting

### Common Issues

#### 1. Docker Build Fails
```bash
# Check Docker daemon
sudo systemctl status docker

# Restart Docker
sudo systemctl restart docker

# Check disk space
df -h
```

#### 2. SSL Certificate Issues
```bash
# Check domain DNS
nslookup yourdomain.com

# Test certificate
openssl s_client -connect yourdomain.com:443

# Check certbot logs
sudo journalctl -u certbot
```

#### 3. Application Won't Start
```bash
# Check container logs
docker logs rawrz-app

# Check port availability
sudo netstat -tlnp | grep 3000

# Check system resources
free -h
df -h
```

#### 4. Monitoring Issues
```bash
# Check Prometheus status
docker ps | grep prometheus

# Check Grafana logs
docker logs grafana

# Verify metrics endpoint
curl http://localhost:3000/metrics
```

### Log Locations
- **Application logs**: `/opt/rawrz-platform/logs/`
- **Docker logs**: `docker logs rawrz-app`
- **System logs**: `/var/log/syslog`
- **Nginx logs**: `/var/log/nginx/`

## GitHub Actions Integration

### Automated Deployment
The repository includes GitHub Actions workflows for automated deployment:

1. **Trigger**: Push to main branch or manual dispatch
2. **Build**: Docker image build and test
3. **Deploy**: Automatic deployment to Digital Ocean
4. **Notify**: Slack/email notifications

### Required Secrets
Configure these secrets in your GitHub repository:

- `DIGITALOCEAN_HOST`: Your droplet's IP address
- `DIGITALOCEAN_USERNAME`: SSH username (usually `root`)
- `DIGITALOCEAN_SSH_KEY`: Private SSH key for authentication
- `SLACK_WEBHOOK`: Slack webhook URL for notifications

## Advanced Configuration

### Custom Docker Compose
Create a custom `docker-compose.override.yml`:

```yaml
version: '3.8'
services:
  rawrz-app:
    environment:
      - CUSTOM_VAR=value
    volumes:
      - ./custom-data:/app/custom-data
    ports:
      - "3001:3001"
```

### Environment-Specific Deployments
```bash
# Development
NODE_ENV=development ./deploy-digital-ocean.sh

# Staging
NODE_ENV=staging ./deploy-digital-ocean.sh

# Production
NODE_ENV=production ./deploy-digital-ocean.sh
```

## Support

### Documentation
- [Docker Documentation](https://docs.docker.com/)
- [Digital Ocean Documentation](https://docs.digitalocean.com/)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)

### Issues and Support
- Create an issue in the GitHub repository
- Check existing issues for solutions
- Review logs and error messages

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

**Made with ❤️ by RawrZ Security Platform Team**