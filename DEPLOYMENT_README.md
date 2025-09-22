# RawrZ Security Platform - DigitalOcean Deployment

## Quick Start

This deployment fixes the container termination issues by using an optimized Docker configuration with proper resource limits.

### Prerequisites

1. **DigitalOcean API Token**: Get one from [DigitalOcean API Tokens](https://cloud.digitalocean.com/account/api/tokens)
2. **Bash shell** (Linux/macOS/WSL)

### Deployment Steps

1. **Set your DigitalOcean token**:
   ```bash
   export DO_TOKEN=your_digitalocean_token_here
   ```

2. **Run the setup script**:
   ```bash
   ./setup-deployment.sh
   ```

That's it! The script will automatically:
- Create a DigitalOcean droplet (1GB RAM, 1 vCPU)
- Install Docker and dependencies
- Deploy the optimized application
- Configure nginx reverse proxy
- Set up health checks and monitoring

## What's Fixed

### Container Termination Issues Resolved

1. **Memory Limits**: Set to 512MB maximum (prevents OOM kills)
2. **CPU Limits**: Limited to 0.5 cores (prevents resource exhaustion)
3. **Optimized Dockerfile**: Minimal dependencies, Alpine Linux base
4. **Health Checks**: Proper timeouts and retry logic
5. **Resource Monitoring**: Built-in monitoring and restart policies

### Optimizations

- **Smaller Image**: Alpine Linux instead of Ubuntu (saves ~800MB)
- **Minimal Dependencies**: Only essential packages installed
- **Production Mode**: Node.js optimized for production
- **Security**: Non-root user, proper permissions
- **Performance**: Gzip compression, caching headers

## Cost

- **Droplet**: ~$5/month (1GB RAM, 1 vCPU, 25GB SSD)
- **Bandwidth**: 1TB included
- **Total**: ~$5/month

## Accessing Your App

After deployment, your app will be available at:
- **Direct**: `http://YOUR_DROPLET_IP:3000`
- **Via Nginx**: `http://YOUR_DROPLET_IP` (port 80)

## Management Commands

```bash
# SSH into your droplet
ssh root@YOUR_DROPLET_IP

# View application logs
docker-compose logs -f

# Restart the application
docker-compose restart

# Stop the application
docker-compose down

# Update the application
git pull && docker-compose up -d --build
```

## Troubleshooting

### If the deployment fails:

1. **Check your token**: Make sure `DO_TOKEN` is set correctly
2. **Check droplet limits**: Ensure you have space for a new droplet
3. **Check SSH**: The script waits for SSH to be ready, but sometimes takes longer

### If the app doesn't start:

1. **Check logs**: `docker-compose logs`
2. **Check health**: `curl http://localhost:3000/api/health`
3. **Check resources**: `docker stats`

### Common Issues:

- **Memory errors**: The app is limited to 512MB, which should be sufficient
- **Port conflicts**: Only port 3000 is exposed by default
- **Permission errors**: The app runs as non-root user for security

## Security Features

- Non-root user execution
- Resource limits to prevent DoS
- Health checks for automatic recovery
- Firewall configuration (only necessary ports open)
- Security headers via nginx

## Monitoring

The deployment includes:
- Health checks every 60 seconds
- Automatic restart on failure
- Resource usage monitoring
- Access logs via nginx

## Support

If you encounter issues:
1. Check the logs first: `docker-compose logs`
2. Verify the health endpoint: `http://YOUR_IP:3000/api/health`
3. Check droplet resources in DigitalOcean dashboard

The optimized configuration should prevent the container termination issues you were experiencing.