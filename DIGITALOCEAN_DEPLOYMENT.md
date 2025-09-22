# Digital Ocean Deployment Guide

## 🚀 Quick Start

This application is optimized for Digital Ocean App Platform with memory leak prevention and resource optimization.

## Prerequisites

1. Digital Ocean account with API token
2. `doctl` CLI tool installed
3. Node.js 18+ (for local testing)

## Installation

### 1. Install Digital Ocean CLI

```bash
# macOS
brew install doctl

# Linux (Snap)
snap install doctl

# Windows
scoop install doctl
```

### 2. Authenticate

```bash
doctl auth init
# Enter your API token when prompted
```

## Deployment Methods

### Method 1: App Platform (Recommended) ✅

The easiest and most cost-effective method for small to medium apps.

1. **Using the CLI:**
```bash
# Deploy directly from the spec file
doctl apps create --spec .do/app.yaml
```

2. **Using the Web Console:**
   - Go to [Digital Ocean App Platform](https://cloud.digitalocean.com/apps)
   - Click "Create App"
   - Connect your GitHub repository
   - Select branch (main/master)
   - Review and deploy

### Method 2: Docker on Droplet

For more control over the environment:

1. **Create a Droplet:**
```bash
doctl compute droplet create rawrz-app \
  --image docker-20-04 \
  --size s-1vcpu-1gb \
  --region nyc1
```

2. **SSH and deploy:**
```bash
# SSH into droplet
doctl compute ssh rawrz-app

# Clone repository
git clone <your-repo-url>
cd <repo-name>

# Build and run
docker build -t rawrz-app .
docker run -d -p 80:8080 --restart=always --name rawrz rawrz-app
```

### Method 3: Kubernetes (K8s)

For scalable production deployments:

1. **Create cluster:**
```bash
doctl kubernetes cluster create rawrz-cluster \
  --node-pool "name=worker;size=s-1vcpu-2gb;count=2"
```

2. **Deploy:**
```bash
kubectl apply -f k8s-deployment.yaml
```

## Configuration

### Environment Variables

Set these in your App Platform settings or `.env` file:

```env
NODE_ENV=production
PORT=8080
NODE_OPTIONS=--max-old-space-size=256
```

### Resource Limits

The app is configured to run on minimal resources:
- **Memory:** 256MB - 512MB
- **CPU:** 0.5 - 1 vCPU
- **Instance Size:** basic-xxs or basic-xs

## Memory Leak Prevention

The application includes several memory leak prevention mechanisms:

1. **Automatic session cleanup** - Old sessions are removed every minute
2. **Request size limits** - Maximum 1MB per request
3. **Data limits** - Maximum 100 keys per session, 10KB per value
4. **Garbage collection** - Forced GC when available
5. **Memory monitoring** - Health endpoint tracks memory usage

## Monitoring

### Health Check
```bash
curl https://your-app.ondigitalocean.app/health
```

### Logs
```bash
doctl apps logs <app-id> --follow
```

### Metrics
View in Digital Ocean dashboard or use:
```bash
doctl apps list-alerts <app-id>
```

## Troubleshooting

### Container Terminated Error

If you see "Container Terminated" errors:

1. **Check memory usage:**
```bash
doctl apps logs <app-id> | grep -i memory
```

2. **Reduce memory footprint:**
   - Decrease `--max-old-space-size` to 256MB
   - Remove unnecessary dependencies
   - Enable compression

3. **Scale horizontally instead of vertically:**
```bash
doctl apps update <app-id> --spec .do/app.yaml
# Increase instance_count instead of instance_size
```

### High Memory Usage

1. Check for memory leaks in logs
2. Review session cleanup settings
3. Reduce cache sizes
4. Enable garbage collection

### Deployment Fails

1. Check build logs:
```bash
doctl apps list-deployments <app-id>
doctl apps logs <app-id> --type=build
```

2. Verify package.json is valid:
```bash
npm ci --only=production
```

3. Test locally:
```bash
docker build -t test .
docker run -p 8080:8080 test
```

## Cost Optimization

### Tips to reduce costs:

1. **Use App Platform** instead of Droplets for small apps
2. **Start with basic-xxs** ($5/month) instance size
3. **Enable auto-scaling** only when needed
4. **Use static sites** for frontend (free tier)
5. **Optimize images** and use CDN

### Recommended Setup for Production:

- **App Platform:** 1x basic-xs instance
- **Database:** Managed PostgreSQL (dev tier)
- **Storage:** Spaces for files
- **CDN:** Enable for static assets
- **Total:** ~$15-20/month

## Commands Reference

```bash
# List all apps
doctl apps list

# Get app details
doctl apps get <app-id>

# View live URL
doctl apps list --format Name,LiveURL

# Update app
doctl apps update <app-id> --spec .do/app.yaml

# Delete app
doctl apps delete <app-id>

# View billing
doctl billing-history list
```

## Support

- [Digital Ocean Documentation](https://docs.digitalocean.com/products/app-platform/)
- [Community Forum](https://www.digitalocean.com/community)
- [Support Ticket](https://cloud.digitalocean.com/support)

## License

MIT