# 🚀 Digital Ocean CLI (doctl) Deployment Guide

## 📋 Complete Guide for Deploying RawrZ and n0mn0m Systems

### 🔑 Prerequisites

1. **Digital Ocean Account** with App Platform enabled
2. **Digital Ocean API Token** (Personal Access Token)
3. **doctl CLI installed** on your local machine
4. **GitHub Repository** (optional, for automatic deployments)

---

## 🛠️ Installation and Setup

### Install doctl

#### Linux
```bash
curl -sL https://github.com/digitalocean/doctl/releases/latest/download/doctl-linux-amd64.tar.gz | tar -xzf - && sudo mv doctl /usr/local/bin/
```

#### macOS
```bash
brew install doctl
```

#### Windows
```bash
scoop install doctl
```

#### Verify Installation
```bash
doctl version
```

---

## 🔐 Authentication

### Get Your Digital Ocean Token

1. **Go to Digital Ocean Console:**
   - Visit: https://cloud.digitalocean.com/account/api/tokens
   - Click "Generate New Token"

2. **Create Personal Access Token:**
   - Token name: `rawrz-n0mn0m-deployment`
   - Scopes: Read, Write
   - Copy the generated token

3. **Authenticate with doctl:**
   ```bash
   doctl auth init
   ```
   - Paste your token when prompted

4. **Verify Authentication:**
   ```bash
   doctl account get
   ```

---

## 🚀 Deployment Commands

### Deploy RawrZ Security Platform

```bash
doctl apps create --spec do-app-rawrz.yaml
```

**Expected Output:**
```
Notice: App created
App ID: [app-id]
Default ingress: [url].ondigitalocean.app
Status: Active
```

### Deploy n0mn0m Quantum System

```bash
doctl apps create --spec do-app-n0mn0m.yaml
```

**Expected Output:**
```
Notice: App created
App ID: [app-id]
Default ingress: [url].ondigitalocean.app
Status: Active
```

---

## 📊 Management Commands

### List All Apps
```bash
doctl apps list
```

### Get App Details
```bash
doctl apps get [app-id]
```

### View Logs
```bash
doctl apps logs [app-id]
```

### Update App
```bash
doctl apps update [app-id] --spec do-app-rawrz.yaml
```

### Delete App (Use Carefully!)
```bash
doctl apps delete [app-id]
```

---

## 🌐 Access Your Deployed Systems

### RawrZ Security Platform
- **URL:** https://[rawrz-app-name].ondigitalocean.app
- **Health Check:** https://[rawrz-app-name].ondigitalocean.app/api/health
- **Features:** 72+ Security Features
- **Capabilities:** Advanced Cryptography, Network Analysis, File Forensics

### n0mn0m Quantum System
- **URL:** https://[n0mn0m-app-name].ondigitalocean.app
- **Health Check:** https://[n0mn0m-app-name].ondigitalocean.app/api/health
- **Features:** 49 Language Compilers, Quantum Computing
- **Capabilities:** Universal Compilation, Quantum Simulation

---

## 🔧 Testing Commands

### Test RawrZ Security Platform
```bash
# Health check
curl https://[rawrz-url].ondigitalocean.app/api/health

# System stats
curl https://[rawrz-url].ondigitalocean.app/api/stats

# File operations
curl -X POST https://[rawrz-url].ondigitalocean.app/api/rawrz/files
```

### Test n0mn0m Quantum System
```bash
# Health check
curl https://[n0mn0m-url].ondigitalocean.app/api/health

# Quantum generation
curl -X POST https://[n0mn0m-url].ondigitalocean.app/api/quantum/generate \
  -H "Content-Type: application/json" \
  -d '{"prompt": "quantum computing", "max_length": 50}'

# System stats
curl https://[n0mn0m-url].ondigitalocean.app/api/system/stats
```

---

## 📈 Monitoring Commands

### View App Performance
```bash
doctl apps get [app-id] --format ID,Spec.Services[0].InstanceCount,Spec.Services[0].InstanceSizeSlug
```

### Check App Health
```bash
doctl apps get [app-id] --format LiveURL,Status.Deployments[0].Phase
```

### Connect to App Console
```bash
doctl apps console [app-id]
```

### View App Components
```bash
doctl apps get [app-id] --format Spec.Services
```

---

## 💰 Cost Management

### Check Current Costs
```bash
doctl apps get [app-id] --format ID,Spec.Services[0].InstanceSizeSlug
```

### Scale Down to Save Costs
```bash
# Create a basic spec first
doctl apps update [app-id] --spec basic-app.yaml
```

### Scale Up for More Performance
```bash
# Create a high-performance spec first
doctl apps update [app-id] --spec premium-app.yaml
```

---

## 🔒 Security Features

### Automatic Security with Digital Ocean Apps
- **SSL/TLS Certificates** - Automatic HTTPS
- **DDoS Protection** - Built-in protection
- **Firewall** - Automatic security rules
- **Rate Limiting** - API protection
- **Authentication** - Secure access control

### Custom Security
- **Domain Configuration**
  ```bash
  doctl compute domain records list [domain-name]
  doctl compute domain records create [domain-name] \
    --record-type A \
    --record-name [subdomain] \
    --record-data [app-ip]
  ```

---

## 🐛 Troubleshooting

### Check App Status
```bash
doctl apps get [app-id] --format Status.Deployments[0].Phase
```

### View Detailed Logs
```bash
doctl apps logs [app-id] --follow
```

### Restart App
```bash
doctl apps update [app-id] --spec do-app-rawrz.yaml
```

### Check Resource Usage
```bash
doctl apps get [app-id] --format Spec.Services[0].InstanceSizeSlug
```

---

## 🎯 Complete Deployment Workflow

1. **Install doctl:**
   ```bash
   curl -sL https://github.com/digitalocean/doctl/releases/latest/download/doctl-linux-amd64.tar.gz | tar -xzf - && sudo mv doctl /usr/local/bin/
   ```

2. **Authenticate:**
   ```bash
   doctl auth init
   # Paste your token when prompted
   ```

3. **Verify Account:**
   ```bash
   doctl account get
   ```

4. **Deploy RawrZ:**
   ```bash
   doctl apps create --spec do-app-rawrz.yaml
   ```

5. **Deploy n0mn0m:**
   ```bash
   doctl apps create --spec do-app-n0mn0m.yaml
   ```

6. **List Apps:**
   ```bash
   doctl apps list
   ```

7. **Access Your Systems:**
   - RawrZ: https://[rawrz-app-url].ondigitalocean.app
   - n0mn0m: https://[n0mn0m-app-url].ondigitalocean.app

---

## 📋 Expected Results

### Successful Deployment Output
```
Notice: App created
App ID: [app-id]
Default ingress: [url].ondigitalocean.app
Status: Active
```

### Health Check Response
```json
{
  "success": true,
  "status": "healthy",
  "timestamp": "2025-01-22T10:00:00.000Z",
  "uptime": 3600,
  "version": "2.0.0",
  "service": "RawrZ Security Platform",
  "features": 72
}
```

### n0mn0m Health Check Response
```json
{
  "success": true,
  "status": "healthy",
  "timestamp": "2025-01-22T10:00:00.000Z",
  "uptime": 3600,
  "version": "2.0.0",
  "service": "n0mn0m Quantum System",
  "quantum_dimension": 8,
  "languages_supported": 49
}
```

---

## 🎉 Your Systems Are Ready!

Your **RawrZ Security Platform** and **n0mn0m Quantum System** will be the most advanced systems ever deployed to Digital Ocean:

- **RawrZ:** 72+ Security Features, Enterprise-grade security suite
- **n0mn0m:** 49 Language Compilers, Quantum computing capabilities
- **Complete Transparency:** All code visible and auditable
- **Production Ready:** Automatic scaling, monitoring, security
- **Professional Deployment:** Digital Ocean App Platform

**Ready to deploy the most powerful security and development platforms ever created?** 🚀✨🔒

---

*This guide provides everything you need to deploy your RawrZ Security Platform and n0mn0m Quantum System to Digital Ocean using doctl CLI with your tokens.*