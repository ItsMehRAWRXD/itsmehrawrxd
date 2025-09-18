# RawrZApp Digital Ocean Deployment Guide

## Quick Deploy to Digital Ocean App Platform ($5/month)

### Prerequisites
- GitHub repository: `ItsMehRAWRXD/itsmehrawrxd`
- Digital Ocean account
- GitHub token and Digital Ocean token (already configured)

### Step 1: Deploy via Digital Ocean Dashboard

1. **Login to Digital Ocean**
   - Go to [Digital Ocean App Platform](https://cloud.digitalocean.com/apps)
   - Click "Create App"

2. **Connect GitHub Repository**
   - Select "GitHub" as source
   - Connect your GitHub account
   - Select repository: `ItsMehRAWRXD/itsmehrawrxd`
   - Branch: `main`

3. **Configure App Settings**
   - **App Name**: `rawrzapp`
   - **Source Directory**: `/` (root)
   - **Build Command**: `npm install`
   - **Run Command**: `npm start`
   - **Environment**: `Node.js`

4. **Set Environment Variables**
   ```
   NODE_ENV=production
   PORT=8080
   AUTH_TOKEN=rawrz-secure-token-2024
   GITHUB_TOKEN=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
   DIGITAL_OCEAN_TOKEN=dop_v1_ccce0b4c48181e9ef566a7b2a5105194256b8302af99761a57a7cad6d3007c4e
   ```

5. **Configure Instance**
   - **Instance Size**: Basic ($5/month)
   - **Instance Count**: 1
   - **HTTP Port**: 8080

6. **Deploy**
   - Click "Create Resources"
   - Wait for deployment (5-10 minutes)

### Step 2: Access Your App

Once deployed, your app will be available at:
- **URL**: `https://rawrzapp-xxxxx.ondigitalocean.app`
- **Health Check**: `https://rawrzapp-xxxxx.ondigitalocean.app/health`
- **Panel**: `https://rawrzapp-xxxxx.ondigitalocean.app/panel.html`

### Step 3: Verify Deployment

1. **Health Check**
   ```bash
   curl https://your-app-url.ondigitalocean.app/health
   ```

2. **Access Panel**
   - Open browser to your app URL
   - Navigate to `/panel.html`
   - Use auth token: `rawrz-secure-token-2024`

### Features Available

**Polymorphic Engine** - Interactive code mutation
**Stealth Engine** - Anti-detection techniques  
**Compression Engine** - Data compression
**Anti-Analysis Engine** - Protection techniques
**50+ Security Engines** - Full cybersecurity toolkit

### Troubleshooting

**Build Fails**
- Check Node.js version (requires 18+)
- Verify all dependencies in package.json

**App Won't Start**
- Check PORT environment variable
- Verify health endpoint responds

**Authentication Issues**
- Use token: `rawrz-secure-token-2024`
- Check AUTH_TOKEN environment variable

### Cost Breakdown
- **Basic Plan**: $5/month
- **512MB RAM**: Sufficient for RawrZApp
- **1 vCPU**: Handles moderate traffic
- **Automatic HTTPS**: Included
- **Custom Domain**: Optional ($12/year)

### Auto-Deploy
- Push to `main` branch = automatic deployment
- Build logs available in Digital Ocean dashboard
- Health monitoring included

### Security Notes
- All API endpoints require authentication
- Environment variables are encrypted
- HTTPS enabled by default
- No server management required
