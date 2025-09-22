# Digital Ocean App Platform Deployment Guide

## 🚀 Current Deployment

Your application **orca** is currently deployed on Digital Ocean App Platform:
- **App ID**: `f7e8c6ff-12ff-4c2a-a62b-e8b537f2c8ca`
- **Console URL**: https://cloud.digitalocean.com/apps/f7e8c6ff-12ff-4c2a-a62b-e8b537f2c8ca

## 📁 Deployment Files

```
.do/
├── app.yaml          # App Platform specification
└── deploy.sh         # Deployment management script

.github/workflows/
└── deploy-digitalocean.yml  # GitHub Actions automation

.env.production.example      # Environment variables template
```

## 🛠️ Quick Start

### 1. Manual Deployment

```bash
# Make the deploy script executable
chmod +x .do/deploy.sh

# Run deployment
.do/deploy.sh deploy

# Or use the interactive menu
.do/deploy.sh
```

### 2. Automatic Deployment (GitHub Actions)

Deployments are automatically triggered when you push to the `main` branch.

**Required GitHub Secrets:**
- `DIGITALOCEAN_ACCESS_TOKEN` - Your Digital Ocean API token

To set up:
1. Go to your repository settings
2. Navigate to Secrets and variables → Actions
3. Add `DIGITALOCEAN_ACCESS_TOKEN` with your DO API token

### 3. Using doctl CLI

```bash
# Install doctl
brew install doctl  # macOS
# or
snap install doctl  # Linux

# Authenticate
doctl auth init

# Deploy
doctl apps create-deployment f7e8c6ff-12ff-4c2a-a62b-e8b537f2c8ca

# View logs
doctl apps logs f7e8c6ff-12ff-4c2a-a62b-e8b537f2c8ca
```

## 📝 Configuration

### Environment Variables

1. Copy the example file:
```bash
cp .env.production.example .env.production
```

2. Update with your values:
```env
AUTH_TOKEN=your-secure-token
DATABASE_URL=your-database-url
# ... other variables
```

3. Update in Digital Ocean:
```bash
.do/deploy.sh env
```

### App Specification

Edit `.do/app.yaml` to modify:
- Instance size and count
- Environment variables
- Health checks
- Alerts
- Build/run commands

After changes:
```bash
.do/deploy.sh update
```

## 🔧 Common Operations

### View Status
```bash
.do/deploy.sh status
```

### View Logs
```bash
# Runtime logs
.do/deploy.sh logs run

# Build logs
.do/deploy.sh logs build
```

### Scale Application
```bash
# Scale to 3 instances
.do/deploy.sh scale 3
```

### Rollback
```bash
.do/deploy.sh rollback
```

### Monitor (Live)
```bash
.do/deploy.sh monitor
```

## 🚨 Troubleshooting

### Build Failures

1. Check build logs:
```bash
doctl apps logs f7e8c6ff-12ff-4c2a-a62b-e8b537f2c8ca --type=build
```

2. Common issues:
- Missing dependencies in `package.json`
- Node version mismatch
- Build command errors

### Runtime Errors

1. Check runtime logs:
```bash
doctl apps logs f7e8c6ff-12ff-4c2a-a62b-e8b537f2c8ca --type=run
```

2. Verify environment variables:
```bash
doctl apps get f7e8c6ff-12ff-4c2a-a62b-e8b537f2c8ca --format Spec.Services[0].Envs
```

### Health Check Failures

Ensure your app responds to `/health` endpoint:
```javascript
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy' });
});
```

## 📊 Monitoring

### Metrics
View in Digital Ocean console:
- CPU usage
- Memory usage
- Response time
- Request count

### Alerts
Configured alerts (in `app.yaml`):
- Deployment failures
- High CPU usage (>85%)
- High memory usage (>85%)
- Excessive restarts

## 🔐 Security

1. **Environment Variables**: Use DO's secret management for sensitive data
2. **CORS**: Configure allowed origins in production
3. **Rate Limiting**: Enabled by default (100 req/15min)
4. **HTTPS**: Automatically provided by App Platform

## 📚 Resources

- [Digital Ocean App Platform Docs](https://docs.digitalocean.com/products/app-platform/)
- [doctl CLI Reference](https://docs.digitalocean.com/reference/doctl/)
- [App Platform Pricing](https://www.digitalocean.com/pricing/app-platform)

## 🆘 Support

For deployment issues:
1. Check deployment logs in DO console
2. Review GitHub Actions workflow runs
3. Use `.do/deploy.sh` for debugging
4. Contact Digital Ocean support if needed

---

**Last Updated**: September 2025
**Maintained By**: RawrZ Security Team