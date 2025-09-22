# RawrZ Security Platform - Digital Ocean Deployment Guide

## 🚀 Quick Start

### Prerequisites
- Docker installed locally
- Digital Ocean account with App Platform enabled
- Digital Ocean CLI (`doctl`) installed and authenticated

### Step 1: Test Local Build
```bash
./test-build.sh
```

### Step 2: Deploy to Digital Ocean
```bash
./deploy-to-digitalocean.sh
```

## 🛠️ Manual Deployment Steps

### 1. Install Digital Ocean CLI
```bash
curl -sL https://github.com/digitalocean/doctl/releases/latest/download/doctl-linux-amd64.tar.gz | tar -xzf - && sudo mv doctl /usr/local/bin/
```

### 2. Authenticate with Digital Ocean
```bash
doctl auth init
```
Enter your Digital Ocean API token when prompted.

### 3. Create App Specification
```yaml
name: rawrz-security-platform
region: nyc3
services:
  - name: web
    dockerfile_path: Dockerfile
    source_dir: .
    envs:
      - key: NODE_ENV
        value: production
      - key: PORT
        value: "3000"
    health_check:
      http_path: /api/health
    instance_count: 1
    instance_size_slug: basic-xxs
    http_port: 3000
```

### 4. Deploy Using CLI
```bash
doctl apps create --spec app.yaml
```

### 5. Monitor Deployment
```bash
doctl apps list
doctl apps logs <app-id>
```

## 📊 Health Check

The application includes a health check endpoint at `/api/health` that returns:
```json
{
  "success": true,
  "status": "healthy",
  "timestamp": "2025-09-22T10:00:00.000Z",
  "uptime": 3600,
  "version": "1.0.0",
  "service": "RawrZ Security Platform - Real Only"
}
```

## 🔧 Troubleshooting

### Common Issues

1. **Container Terminated Error**
   - Check Digital Ocean logs: `doctl apps logs <app-id>`
   - Verify all required files are present
   - Ensure health check endpoint is accessible

2. **Build Failures**
   - Run `./test-build.sh` locally first
   - Check Dockerfile syntax
   - Verify all dependencies in `package-docker.json`

3. **Resource Limits**
   - Monitor CPU/memory usage in Digital Ocean console
   - Consider upgrading instance size if needed
   - Check for memory leaks in application code

### Performance Optimization

1. **Reduce Image Size**
   - Use multi-stage builds
   - Remove unnecessary packages
   - Use `.dockerignore` file

2. **Application Optimization**
   - Enable compression
   - Implement caching
   - Use environment-specific configurations

## 📋 Required Files

Ensure these files exist in your repository:
- `Dockerfile` - Container configuration
- `api-server.js` - Main application server
- `package-docker.json` - Production dependencies
- `start-server.sh` - Startup script

## 🔒 Security Considerations

1. **Environment Variables**
   - Never commit secrets to code
   - Use Digital Ocean environment variables for sensitive data
   - Rotate API keys regularly

2. **Network Security**
   - Enable HTTPS only
   - Configure firewall rules
   - Use Digital Ocean's managed databases for sensitive data

3. **Container Security**
   - Run as non-root user (configured in Dockerfile)
   - Regular security updates
   - Scan images for vulnerabilities

## 📞 Support

For issues with deployment:
1. Check Digital Ocean App Platform documentation
2. Review application logs via `doctl apps logs`
3. Test locally with `./test-build.sh` first
4. Verify all prerequisites are met

## 📈 Monitoring

Monitor your application using:
- Digital Ocean App Platform dashboard
- Built-in health checks (`/api/health`)
- Application logs via `doctl apps logs`
- Performance metrics in Digital Ocean console