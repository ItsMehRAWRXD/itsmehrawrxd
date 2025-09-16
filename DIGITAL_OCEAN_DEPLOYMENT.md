# Digital Ocean Deployment Guide

## Health Check Issues Fixed

The following issues that were causing Digital Ocean deployment failures have been resolved:

### 1. **Authentication Required for Health Checks**
- **Problem**: The `/api/status` endpoint required authentication, but Digital Ocean health checks can't provide auth tokens
- **Solution**: Added public `/health` and `/api/health` endpoints that don't require authentication

### 2. **Server Binding Issues**
- **Problem**: Server was binding to localhost only, preventing external access
- **Solution**: Updated server to bind to `0.0.0.0` (all interfaces) by default

### 3. **Incorrect Health Check Endpoints**
- **Problem**: Docker health checks were using `/api/status` which required auth
- **Solution**: Updated all health checks to use the public `/health` endpoint

## Available Health Check Endpoints

### Public Endpoints (No Authentication Required)
- `GET /health` - Simple health check for load balancers
- `GET /api/health` - Detailed health check with system info

### Authenticated Endpoints (Require AUTH_TOKEN)
- `GET /api/status` - Full system status with detailed metrics

## Deployment Configuration

### Environment Variables
Make sure to set these environment variables in your Digital Ocean app:

```bash
NODE_ENV=production
PORT=8080
HOST=0.0.0.0
AUTH_TOKEN=your-secure-auth-token-here
```

### Health Check Configuration
In your Digital Ocean App Platform settings, configure:

- **Health Check Path**: `/health`
- **Health Check Port**: `8080`
- **Health Check Protocol**: `HTTP`
- **Health Check Interval**: `30s`
- **Health Check Timeout**: `10s`
- **Health Check Retries**: `3`

### Docker Configuration
The following files have been updated for proper health checks:

1. **Dockerfile**: Health check now uses `/health` endpoint
2. **docker-compose.yml**: Updated health check configuration
3. **server.js**: Added public health endpoints and proper host binding

## Testing Health Checks Locally

Before deploying to Digital Ocean, test the health checks locally:

```bash
# Start the server
npm start

# Test health check endpoints
node test-health-check.js

# Or test manually with curl
curl http://localhost:8080/health
curl http://localhost:8080/api/health
```

Expected responses:

```json
// GET /health
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "uptime": 123.456
}

// GET /api/health
{
  "success": true,
  "result": {
    "platform": "RawrZ Security Platform",
    "version": "2.1.0",
    "status": "healthy",
    "uptime": 123.456,
    "timestamp": "2024-01-01T00:00:00.000Z"
  }
}
```

## Digital Ocean App Platform Configuration

### 1. Create New App
- Go to Digital Ocean App Platform
- Create a new app from GitHub repository
- Select your RawrZ repository

### 2. Configure Build Settings
- **Build Command**: `npm ci --only=production`
- **Run Command**: `node server.js`
- **Source Directory**: `/`

### 3. Configure Environment Variables
Add these environment variables in the App Platform dashboard:

```
NODE_ENV=production
PORT=8080
HOST=0.0.0.0
AUTH_TOKEN=your-secure-auth-token-here
```

### 4. Configure Health Checks
In the App Platform settings:

- **Health Check Path**: `/health`
- **Health Check Port**: `8080`
- **Health Check Protocol**: `HTTP`

### 5. Configure Domains
- Add your custom domain
- Configure SSL certificates
- Set up proper DNS records

## Troubleshooting

### Health Check Still Failing?

1. **Check Logs**: View the app logs in Digital Ocean dashboard
2. **Test Locally**: Run `node test-health-check.js` to verify endpoints work
3. **Verify Environment**: Ensure `HOST=0.0.0.0` is set
4. **Check Port**: Ensure `PORT=8080` matches your configuration

### Common Issues

1. **Port Mismatch**: Make sure the health check port matches your app's port
2. **Authentication**: Ensure you're using `/health` not `/api/status` for health checks
3. **Host Binding**: Verify the server binds to `0.0.0.0` not `localhost`
4. **Startup Time**: Allow sufficient time for the app to start before health checks begin

### Debug Commands

```bash
# Test health check locally
curl -v http://localhost:8080/health

# Check if server is binding to all interfaces
netstat -tlnp | grep :8080

# Test with different hosts
curl http://0.0.0.0:8080/health
curl http://127.0.0.1:8080/health
```

## Security Considerations

- The `/health` endpoint is public and doesn't expose sensitive information
- The `/api/health` endpoint provides basic system info but no sensitive data
- The `/api/status` endpoint remains protected and requires authentication
- Consider rate limiting health check endpoints in production

## Monitoring

After successful deployment, monitor your app:

1. **Health Check Status**: Check Digital Ocean dashboard for health status
2. **Application Logs**: Monitor logs for any errors or warnings
3. **Performance Metrics**: Use Digital Ocean's built-in monitoring
4. **Custom Metrics**: Implement additional monitoring as needed

## Next Steps

1. Deploy to Digital Ocean using the updated configuration
2. Monitor the deployment logs for any issues
3. Test the deployed application endpoints
4. Set up monitoring and alerting
5. Configure custom domains and SSL certificates
