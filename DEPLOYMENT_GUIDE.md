# RawrZ Security Platform - Digital Ocean Deployment Guide

This guide provides step-by-step instructions for deploying the RawrZ Security Platform on Digital Ocean.

## Prerequisites

- Digital Ocean account with droplet creation permissions
- Domain name (optional but recommended)
- Basic knowledge of Linux, Docker, and SSH

## Quick Start

### 1. Create Digital Ocean Droplet

1. Log into your Digital Ocean dashboard
2. Create a new Droplet:
   - **Image**: Ubuntu 22.04 LTS
   - **Size**: Basic plan, 4 GB RAM, 2 vCPUs (minimum recommended)
   - **Datacenter**: Choose closest to your users
   - **Authentication**: SSH keys (recommended) or password
   - **Hostname**: rawrz-security-platform

### 2. Initial Server Setup

Connect to your droplet:
```bash
ssh root@YOUR_DROPLET_IP
```

Download and run the deployment script:
```bash
curl -fsSL https://raw.githubusercontent.com/ItsMehRAWRXD/itsmehrawrxd/main/deploy-digital-ocean.sh -o deploy.sh
chmod +x deploy.sh
./deploy.sh
```

The script will automatically:
- Update the system
- Install Docker and Docker Compose
- Install Node.js and security tools
- Configure firewall (UFW)
- Clone the repository
- Set up SSL certificates
- Configure Nginx reverse proxy
- Deploy the application stack
- Set up monitoring and logging
- Configure backups

### 3. Post-Deployment Configuration

After the deployment completes:

1. **Update passwords** in production:
   ```bash
   cd /opt/rawrz-security
   nano secrets/db_password.txt
   nano secrets/redis_password.txt
   nano secrets/grafana_password.txt
   ```

2. **Configure environment variables**:
   ```bash
   nano config/production.env
   ```
   Update the following:
   - `CORS_ORIGIN` - Set to your domain
   - `JWT_SECRET` - Generate a random string
   - `SESSION_SECRET` - Generate a random string
   - `ENCRYPTION_KEY` - Generate a 32-byte hex string

3. **Restart services** after configuration changes:
   ```bash
   sudo systemctl restart rawrz-security
   ```

## Manual Deployment Steps

If you prefer manual deployment or need to customize the process:

### 1. Server Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### 2. Clone Repository

```bash
sudo mkdir -p /opt/rawrz-security
sudo git clone https://github.com/ItsMehRAWRXD/itsmehrawrxd.git /opt/rawrz-security
cd /opt/rawrz-security
```

### 3. Configure Environment

```bash
# Create production environment file
cp config/production.env.example config/production.env
nano config/production.env

# Generate secure passwords
openssl rand -hex 32 > secrets/db_password.txt
openssl rand -hex 32 > secrets/redis_password.txt
openssl rand -hex 32 > secrets/grafana_password.txt
```

### 4. Deploy Services

```bash
# Build and start services
docker-compose -f docker-compose.yml -f docker-compose.production.yml up -d

# Check service status
docker-compose ps
```

## Configuration Details

### Environment Variables

Key environment variables to configure:

| Variable | Description | Example |
|----------|-------------|---------|
| `CORS_ORIGIN` | Allowed origins for CORS | `https://yourdomain.com` |
| `JWT_SECRET` | Secret for JWT tokens | Random 32+ character string |
| `SESSION_SECRET` | Secret for sessions | Random 32+ character string |
| `ENCRYPTION_KEY` | Key for encryption | 32-byte hex string |
| `DB_PASSWORD` | Database password | Strong password |
| `REDIS_PASSWORD` | Redis password | Strong password |

### SSL Certificates

The deployment script creates self-signed certificates. For production:

1. **Using Let's Encrypt** (recommended):
   ```bash
   sudo certbot --nginx -d yourdomain.com
   ```

2. **Using custom certificates**:
   - Place `cert.pem` and `key.pem` in `/etc/nginx/ssl/`
   - Update nginx configuration if needed

### Firewall Configuration

Default firewall rules:
- SSH (22/tcp) - Allow
- HTTP (80/tcp) - Allow (redirects to HTTPS)
- HTTPS (443/tcp) - Allow
- Application ports (3000-3002/tcp) - Allow
- Database ports (5432, 6379/tcp) - Allow from localhost only

## Monitoring and Maintenance

### Accessing Services

- **Main Application**: `https://YOUR_DOMAIN_OR_IP`
- **Prometheus**: `https://YOUR_DOMAIN_OR_IP:9090`
- **Grafana**: `https://YOUR_DOMAIN_OR_IP:3000` (admin/your_password)
- **Loki**: `https://YOUR_DOMAIN_OR_IP:3100`

### Log Management

View application logs:
```bash
# Service logs
sudo journalctl -u rawrz-security -f

# Docker logs
docker-compose logs -f

# Specific service logs
docker-compose logs -f rawrz-app
```

### Backup and Restore

The deployment script sets up automatic daily backups. Manual backup:
```bash
/opt/backup-rawrz.sh
```

Restore from backup:
```bash
cd /opt/rawrz-security
# Stop services
docker-compose -f docker-compose.yml -f docker-compose.production.yml down

# Restore database
docker exec -i rawrz-database psql -U rawrz_user rawrz_security < backup.sql

# Start services
docker-compose -f docker-compose.yml -f docker-compose.production.yml up -d
```

### Health Checks

Check service health:
```bash
# Overall health
curl -f https://YOUR_DOMAIN/api/health

# Individual services
docker-compose ps
docker stats
```

## Scaling and Performance

### Vertical Scaling

Upgrade your Digital Ocean droplet:
1. Power off the droplet
2. Resize in the Digital Ocean dashboard
3. Power on and verify services

### Horizontal Scaling

For high-traffic deployments:
1. Set up a load balancer
2. Deploy additional app instances
3. Use external database (Digital Ocean Managed Databases)
4. Configure Redis Cluster

### Performance Tuning

1. **Database optimization**:
   - Tune PostgreSQL settings in `database/postgresql.conf`
   - Monitor query performance
   - Add indexes as needed

2. **Redis optimization**:
   - Adjust memory policies in `config/redis.conf`
   - Monitor memory usage

3. **Nginx optimization**:
   - Tune worker processes and connections
   - Optimize caching settings
   - Enable HTTP/2 and gzip

## Security Considerations

### Regular Updates

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Update Docker images
cd /opt/rawrz-security
docker-compose pull
docker-compose up -d
```

### Security Hardening

1. **SSH Hardening**:
   - Disable password authentication
   - Change default SSH port
   - Use fail2ban

2. **Application Security**:
   - Regular security scans
   - Update dependencies
   - Monitor logs for suspicious activity

3. **Database Security**:
   - Regular password rotation
   - Network isolation
   - Backup encryption

## Troubleshooting

### Common Issues

1. **Services not starting**:
   ```bash
   # Check logs
   docker-compose logs
   sudo journalctl -u rawrz-security
   
   # Check system resources
   df -h
   free -h
   ```

2. **SSL Certificate errors**:
   ```bash
   # Regenerate self-signed certificates
   sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
     -keyout /etc/nginx/ssl/key.pem \
     -out /etc/nginx/ssl/cert.pem
   ```

3. **Database connection issues**:
   ```bash
   # Check database status
   docker exec rawrz-database pg_isready -U rawrz_user
   
   # Reset database password
   docker exec -it rawrz-database psql -U postgres
   ```

### Support

For issues and support:
- Check the GitHub repository issues
- Review application logs
- Verify configuration files
- Ensure all services are running

## GitHub Actions Deployment

The repository includes automated deployment via GitHub Actions:

### Setup

1. **Configure secrets** in your GitHub repository:
   - `DO_SSH_KEY` - Private SSH key for server access
   - `DO_PRODUCTION_HOST` - Production server IP/domain
   - `DO_STAGING_HOST` - Staging server IP/domain (optional)
   - `SLACK_WEBHOOK_URL` - Slack notifications (optional)
   - `NOTIFICATION_EMAIL` - Email for notifications (optional)

2. **Deploy automatically**:
   - Push to `main` branch triggers staging deployment
   - Manual approval required for production deployment

### Workflow Features

- Automated testing
- Security scanning
- Docker image building
- Zero-downtime deployments
- Automatic rollbacks on failure
- Health checks
- Notifications

This completes the deployment setup for the RawrZ Security Platform on Digital Ocean.