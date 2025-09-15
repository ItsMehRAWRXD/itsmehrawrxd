# RawrZ Security Platform - Deployment Guide

## Overview

This guide covers various deployment options for the RawrZ Security Platform, including Docker, Docker Compose, and Kubernetes deployments.

## Prerequisites

### System Requirements

- **Operating System**: Linux, macOS, or Windows
- **Memory**: Minimum 2GB RAM, Recommended 4GB+ RAM
- **Storage**: Minimum 10GB free space
- **CPU**: Minimum 2 cores, Recommended 4+ cores

### Software Requirements

- **Node.js**: Version 18 or higher
- **Docker**: Version 20.10 or higher (for containerized deployment)
- **Docker Compose**: Version 2.0 or higher (for multi-container deployment)
- **Kubernetes**: Version 1.20 or higher (for Kubernetes deployment)

## Deployment Options

### 1. Local Development Deployment

#### Quick Start

```bash
# Clone the repository
git clone <repository-url>
cd rawrz-security-platform

# Install dependencies
npm install

# Start the platform
npm start
```

#### With Web Interface

```bash
# Start the web server
npm run start:web

# Access the platform
# Web Interface: http://localhost:8080
# API: http://localhost:8080/api/status
```

### 2. Docker Deployment

#### Single Container

```bash
# Build the Docker image
docker build -t rawrz-security-platform .

# Run the container
docker run -d \
  --name rawrz-platform \
  -p 8080:8080 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/uploads:/app/uploads \
  -e AUTH_TOKEN=your-secure-token \
  rawrz-security-platform
```

#### With Docker Compose

```bash
# Copy environment file
cp env.example .env

# Edit configuration
nano .env

# Deploy with Docker Compose
docker-compose up -d

# Check status
docker-compose ps
```

#### Using Deployment Scripts

**Linux/macOS:**
```bash
# Make script executable
chmod +x deploy.sh

# Deploy
./deploy.sh

# Other commands
./deploy.sh stop
./deploy.sh restart
./deploy.sh logs
./deploy.sh status
./deploy.sh clean
```

**Windows:**
```cmd
# Deploy
deploy.bat

# Other commands
deploy.bat stop
deploy.bat restart
deploy.bat logs
deploy.bat status
deploy.bat clean
```

### 3. Kubernetes Deployment

#### Prerequisites

- Kubernetes cluster (local or cloud)
- kubectl configured
- Helm (optional, for advanced deployments)

#### Basic Deployment

```bash
# Create namespace
kubectl create namespace rawrz-security

# Apply configurations
kubectl apply -f k8s-deployment.yaml

# Check deployment status
kubectl get pods -n rawrz-security
kubectl get services -n rawrz-security
```

#### With Ingress

```bash
# Install NGINX Ingress Controller (if not already installed)
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.1/deploy/static/provider/cloud/deploy.yaml

# Update ingress configuration with your domain
# Edit k8s-deployment.yaml and update the host in the Ingress section

# Apply updated configuration
kubectl apply -f k8s-deployment.yaml
```

#### Scaling

```bash
# Scale the platform
kubectl scale deployment rawrz-platform --replicas=3 -n rawrz-security

# Check scaling status
kubectl get pods -n rawrz-security
```

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `NODE_ENV` | Environment mode | `production` | No |
| `PORT` | Server port | `8080` | No |
| `AUTH_TOKEN` | API authentication token | - | Yes |
| `POSTGRES_HOST` | Database host | `localhost` | No |
| `POSTGRES_PASSWORD` | Database password | - | Yes |
| `REDIS_HOST` | Redis host | `localhost` | No |
| `REDIS_PASSWORD` | Redis password | - | No |
| `LOG_LEVEL` | Logging level | `info` | No |
| `MAX_FILE_SIZE` | Maximum file upload size | `10485760` | No |

### SSL/TLS Configuration

#### Self-Signed Certificates (Development)

```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
```

#### Let's Encrypt (Production)

```bash
# Install certbot
sudo apt-get install certbot

# Generate certificate
sudo certbot certonly --standalone -d yourdomain.com

# Copy certificates
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem ssl/cert.pem
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem ssl/key.pem
```

## Security Considerations

### Production Deployment

1. **Change Default Passwords**
   ```bash
   # Generate secure passwords
   openssl rand -base64 32
   ```

2. **Configure Firewall**
   ```bash
   # Allow only necessary ports
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw enable
   ```

3. **Enable Authentication**
   ```bash
   # Set strong authentication token
   export AUTH_TOKEN=$(openssl rand -base64 32)
   ```

4. **Use HTTPS**
   - Configure SSL certificates
   - Redirect HTTP to HTTPS
   - Use secure headers

### Network Security

1. **Internal Communication**
   - Use private networks for database and Redis
   - Restrict external access to database ports

2. **API Security**
   - Implement rate limiting
   - Use authentication tokens
   - Validate all inputs

## Monitoring and Logging

### Health Checks

```bash
# Check application health
curl -f http://localhost:8080/api/status

# Check database health
docker-compose exec postgres pg_isready -U rawrz

# Check Redis health
docker-compose exec redis redis-cli ping
```

### Logging

```bash
# View application logs
docker-compose logs -f rawrz-platform

# View all service logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f postgres
```

### Monitoring

```bash
# Check resource usage
docker stats

# Check disk usage
df -h

# Check memory usage
free -h
```

## Backup and Recovery

### Database Backup

```bash
# Create backup
docker-compose exec postgres pg_dump -U rawrz rawrz > backup.sql

# Restore backup
docker-compose exec -T postgres psql -U rawrz rawrz < backup.sql
```

### File Backup

```bash
# Backup uploads
tar -czf uploads-backup.tar.gz uploads/

# Backup data
tar -czf data-backup.tar.gz data/
```

### Full System Backup

```bash
# Create full backup
tar -czf rawrz-backup-$(date +%Y%m%d).tar.gz data/ uploads/ logs/ .env
```

## Troubleshooting

### Common Issues

1. **Certificate Popup Dialogs**
   - Fixed in latest version - EV Certificate Encryptor now loads certificate store silently
   - No user interaction required during server startup
   - PowerShell commands run with -WindowStyle Hidden parameter

2. **Port Already in Use**
   ```bash
   # Find process using port
   lsof -i :8080
   
   # Kill process
   kill -9 <PID>
   ```

3. **Permission Denied**
   ```bash
   # Fix permissions
   sudo chown -R $USER:$USER data/ uploads/ logs/
   chmod -R 755 data/ uploads/ logs/
   ```

4. **Database Connection Failed**
   ```bash
   # Check database status
   docker-compose exec postgres pg_isready -U rawrz
   
   # Check logs
   docker-compose logs postgres
   ```

5. **SSL Certificate Issues**
   ```bash
   # Verify certificate
   openssl x509 -in ssl/cert.pem -text -noout
   
   # Check certificate validity
   openssl x509 -in ssl/cert.pem -checkend 0
   ```

### Performance Issues

1. **High Memory Usage**
   - Increase container memory limits
   - Optimize application settings
   - Check for memory leaks

2. **Slow Response Times**
   - Check database performance
   - Optimize queries
   - Increase server resources

3. **Connection Timeouts**
   - Check network connectivity
   - Increase timeout values
   - Optimize database connections

## Maintenance

### Regular Maintenance

1. **Update Dependencies**
   ```bash
   npm update
   docker-compose pull
   docker-compose up -d
   ```

2. **Clean Up Resources**
   ```bash
   # Remove unused containers
   docker system prune -f
   
   # Remove unused images
   docker image prune -f
   ```

3. **Monitor Logs**
   ```bash
   # Check for errors
   docker-compose logs | grep ERROR
   
   # Monitor performance
   docker stats --no-stream
   ```

### Updates

1. **Application Updates**
   ```bash
   # Pull latest changes
   git pull origin main
   
   # Rebuild and restart
   docker-compose down
   docker-compose build --no-cache
   docker-compose up -d
   ```

2. **Database Migrations**
   ```bash
   # Run migrations (if applicable)
   docker-compose exec rawrz-platform npm run migrate
   ```

## Support

For deployment issues:

1. Check the logs for error messages
2. Verify all prerequisites are met
3. Ensure proper configuration
4. Check network connectivity
5. Review security settings

### Getting Help

- Check the troubleshooting section above
- Review the logs for specific error messages
- Verify configuration against the examples
- Test with minimal configuration first

---

*Last updated: September 15, 2025*
*Deployment guide version: 1.1.0*
*Latest update: Certificate popup fix documentation added*
