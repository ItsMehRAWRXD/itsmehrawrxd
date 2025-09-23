# RawrZ Security Platform - Optimized Deployment Guide

## 🚀 Quick Deployment to DigitalOcean

This guide provides optimized deployment options to fix container termination issues.

### 🔧 What was Fixed

1. **Reduced Dependencies**: From 100+ to 10 essential packages
2. **Memory Optimization**: Set memory limits and monitoring
3. **Alpine Linux**: Smaller, more efficient Docker image
4. **Resource Limits**: Proper CPU/memory constraints
5. **Health Monitoring**: Automatic restart on failures

### 📋 Deployment Options

#### Option 1: DigitalOcean App Platform (Recommended)

1. **Push optimized files to your repository**
2. **Create new App Platform app**:
   ```bash
   doctl apps create --spec .do/app.yaml
   ```
3. **Or use the web interface**: Connect your repository and use `Dockerfile.optimized`

#### Option 2: DigitalOcean Droplet

1. **Create a new Droplet** (1GB RAM minimum)
2. **SSH into your droplet**
3. **Clone your repository**:
   ```bash
   git clone https://github.com/yourusername/yourrepo.git
   cd yourrepo
   ```
4. **Run deployment script**:
   ```bash
   ./deploy-digitalocean-optimized.sh
   ```

### 🔐 Environment Variables

Set these in your DigitalOcean dashboard or `.env` file:

```env
NODE_ENV=production
PORT=3000
LOG_LEVEL=info
NODE_OPTIONS=--max-old-space-size=256
```

### 📊 Resource Requirements

- **Minimum**: 512MB RAM, 0.5 CPU cores
- **Recommended**: 1GB RAM, 1 CPU core
- **Storage**: 1GB for logs and temporary files

### ⚡ Performance Optimizations

1. **Memory Management**:
   - Node.js heap limit: 256MB
   - Container limit: 512MB
   - Memory monitoring every 30 seconds

2. **Request Handling**:
   - Rate limiting: 1000 requests per 15 minutes
   - Request compression enabled
   - Response caching where appropriate

3. **Logging**:
   - Structured JSON logging
   - Log rotation (max 10MB per file, 3 files)
   - Separate error and access logs

### 🛠️ Monitoring & Maintenance

#### Health Check Endpoints:
- `GET /health` - Basic health status
- `GET /api/status` - Detailed server information

#### Monitoring Commands:
```bash
# View container stats
docker stats rawrz-optimized

# View logs
docker logs rawrz-optimized --tail 100 -f

# Check memory usage
docker exec rawrz-optimized node -e "console.log(process.memoryUsage())"

# Restart if needed
docker restart rawrz-optimized
```

### 🐛 Troubleshooting

#### Container Still Getting Terminated?

1. **Check memory usage**:
   ```bash
   docker stats rawrz-optimized --no-stream
   ```

2. **View application logs**:
   ```bash
   docker logs rawrz-optimized --tail 50
   ```

3. **Monitor system resources**:
   ```bash
   htop
   free -h
   df -h
   ```

4. **Reduce memory further** (if needed):
   ```bash
   # Edit server.optimized.js
   # Change NODE_OPTIONS to --max-old-space-size=128
   ```

#### Common Issues:

- **High Memory Usage**: Reduce concurrent connections or add swap
- **CPU Spikes**: Check for infinite loops or heavy computations
- **Port Issues**: Ensure PORT environment variable is set correctly
- **Dependencies**: Use `npm ci --only=production` for clean installs

### 🔄 Update Deployment

To update your deployment:

1. **Push changes to repository**
2. **App Platform**: Auto-deploys on push
3. **Droplet**: Re-run deployment script

### 📞 Support

If you continue having issues:

1. Check DigitalOcean status page
2. Verify your billing/resource limits
3. Contact DigitalOcean support
4. Consider upgrading to higher tier resources

### 🎯 Expected Results

With these optimizations:
- ✅ Container startup time: <30 seconds
- ✅ Memory usage: <256MB steady state
- ✅ Response time: <500ms for API calls
- ✅ Zero container terminations
- ✅ Auto-recovery from failures