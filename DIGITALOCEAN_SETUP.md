# 🌊 RawrZ Security Platform - DigitalOcean Deployment

## 🚀 **Quick DigitalOcean Setup**

### **1. Create DigitalOcean Droplet**

```bash
# Create a new droplet (Ubuntu 22.04 LTS recommended)
# Minimum specs: 2GB RAM, 1 CPU, 50GB SSD
# Location: Choose closest to your location
```

### **2. Initial Server Setup**

```bash
# SSH into your droplet
ssh root@YOUR_DROPLET_IP

# Update system
apt update && apt upgrade -y

# Install Node.js 18.x
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
apt-get install -y nodejs

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
usermod -aG docker $USER

# Install Git
apt install git -y

# Install additional tools
apt install -y curl wget unzip
```

### **3. Deploy RawrZ Platform**

```bash
# Clone the repository
git clone <your-repo-url>
cd rawrz-security-platform

# Install dependencies
npm install

# Create necessary directories
mkdir -p uploads downloads temp logs data keys stubs payloads bots cve engines backups

# Set permissions
chmod 755 uploads downloads temp logs data keys stubs payloads bots cve engines backups
```

### **4. Configure Firewall**

```bash
# Allow SSH, HTTP, and HTTPS
ufw allow ssh
ufw allow 80
ufw allow 443
ufw allow 8080
ufw allow 3000
ufw --force enable
```

### **5. Start the Application**

```bash
# Start with PM2 for process management
npm install -g pm2

# Start the application
pm2 start server.js --name "rawrz-platform"

# Save PM2 configuration
pm2 save
pm2 startup

# Check status
pm2 status
```

### **6. Access Your Platform**

```
🌐 Web Interface: http://YOUR_DROPLET_IP:8080
🔐 Encryption Suite: http://YOUR_DROPLET_IP:8080/encrypt
⚙️ Executable Generator: http://YOUR_DROPLET_IP:8080/executable-generator
📊 Health Check: http://YOUR_DROPLET_IP:8080/health
```

## 🐳 **Docker Deployment (Recommended)**

### **1. Build and Run with Docker**

```bash
# Build the main application image
docker build -t rawrz-security-platform .

# Build the compiler image
docker build -f Dockerfile.compiler -t rawrz-compiler .

# Run with all volumes
docker run -d \
  --name rawrz-app \
  -p 8080:8080 \
  -v $(pwd)/uploads:/app/uploads \
  -v $(pwd)/downloads:/app/downloads \
  -v $(pwd)/temp:/app/temp \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/keys:/app/keys \
  -v $(pwd)/stubs:/app/stubs \
  -v $(pwd)/payloads:/app/payloads \
  -v $(pwd)/bots:/app/bots \
  -v $(pwd)/cve:/app/cve \
  -v $(pwd)/engines:/app/engines \
  -v $(pwd)/backups:/app/backups \
  -v $(pwd)/public:/app/public \
  -e NODE_ENV=production \
  -e PORT=8080 \
  -e LOG_LEVEL=info \
  -e MAX_FILE_SIZE=100MB \
  rawrz-security-platform
```

### **2. Verify Deployment**

```bash
# Check if containers are running
docker ps

# Check logs
docker logs rawrz-app

# Test the application
curl http://localhost:8080/health
```

## 🔧 **Nginx Reverse Proxy (Optional)**

### **1. Install Nginx**

```bash
apt install nginx -y
systemctl start nginx
systemctl enable nginx
```

### **2. Configure Nginx**

```bash
# Create configuration file
cat > /etc/nginx/sites-available/rawrz << EOF
server {
    listen 80;
    server_name YOUR_DROPLET_IP;

    location / {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

# Enable the site
ln -s /etc/nginx/sites-available/rawrz /etc/nginx/sites-enabled/
nginx -t
systemctl reload nginx
```

### **3. Access via Domain (Optional)**

```bash
# If you have a domain, point it to your droplet IP
# Then access via: http://yourdomain.com
```

## 🔒 **Security Configuration**

### **1. Set Authentication Token**

```bash
# Set environment variable
export AUTH_TOKEN="your-secure-token-here"

# Add to .env file
echo "AUTH_TOKEN=your-secure-token-here" >> .env
```

### **2. Configure SSL (Optional)**

```bash
# Install Certbot
apt install certbot python3-certbot-nginx -y

# Get SSL certificate
certbot --nginx -d yourdomain.com

# Auto-renewal
crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

## 📊 **Monitoring & Maintenance**

### **1. System Monitoring**

```bash
# Check system resources
htop
df -h
free -h

# Check application logs
pm2 logs rawrz-platform
# or
docker logs rawrz-app
```

### **2. Backup Configuration**

```bash
# Create backup script
cat > backup.sh << EOF
#!/bin/bash
DATE=\$(date +%Y%m%d_%H%M%S)
tar -czf /root/backups/rawrz_backup_\$DATE.tar.gz \
  uploads/ downloads/ temp/ logs/ data/ keys/ \
  stubs/ payloads/ bots/ cve/ engines/ backups/
EOF

chmod +x backup.sh

# Schedule daily backups
crontab -e
# Add: 0 2 * * * /root/backup.sh
```

### **3. Auto-restart on Reboot**

```bash
# For PM2
pm2 startup
pm2 save

# For Docker
docker update --restart=always rawrz-app
```

## 🌐 **Access Methods**

### **1. Direct IP Access**
```
http://YOUR_DROPLET_IP:8080
```

### **2. Domain Access (if configured)**
```
http://yourdomain.com
```

### **3. API Access**
```bash
# Health check
curl http://YOUR_DROPLET_IP:8080/health

# With authentication
curl -H "Authorization: Bearer your-token" \
     http://YOUR_DROPLET_IP:8080/encrypt
```

## 🎯 **Quick Test Commands**

### **1. Test File Encryption**
```bash
# Create test file
echo "Hello World" > test.txt

# Encrypt via API
curl -X POST http://YOUR_DROPLET_IP:8080/api/encrypt-file \
  -F "file=@test.txt" \
  -F "algorithm=aes-256-gcm" \
  -F "extension=.secure"
```

### **2. Test Executable Generation**
```bash
# Generate calculator executable
curl -X POST http://YOUR_DROPLET_IP:8080/api/generate-executable \
  -H "Content-Type: application/json" \
  -d '{
    "name": "testcalc",
    "extension": ".exe",
    "platform": "windows-x64",
    "functionality": "calculator",
    "compiler": "gcc"
  }'
```

### **3. Test Network Tools**
```bash
# Ping test
curl "http://YOUR_DROPLET_IP:8080/ping?host=google.com"

# DNS lookup
curl "http://YOUR_DROPLET_IP:8080/dns?hostname=google.com"
```

## 🔧 **Troubleshooting**

### **1. Port Issues**
```bash
# Check if port is open
netstat -tulpn | grep :8080

# Kill process if needed
kill -9 $(lsof -t -i:8080)
```

### **2. Permission Issues**
```bash
# Fix upload directory permissions
chmod 755 uploads/
chown -R www-data:www-data uploads/
```

### **3. Docker Issues**
```bash
# Restart Docker
systemctl restart docker

# Rebuild containers
docker-compose down
docker-compose up -d
```

### **4. Memory Issues**
```bash
# Check memory usage
free -h

# Add swap if needed
fallocate -l 2G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
```

## 📱 **Mobile Access**

The platform is fully responsive and works on mobile devices:

```
📱 Mobile Interface: http://YOUR_DROPLET_IP:8080/compact
📱 Ultra-Compact: http://YOUR_DROPLET_IP:8080/ultra
```

## 🎉 **You're Ready!**

Your RawrZ Security Platform is now accessible via DigitalOcean at:

**🌐 Main Interface**: `http://YOUR_DROPLET_IP:8080`  
**🔐 Encryption Suite**: `http://YOUR_DROPLET_IP:8080/encrypt`  
**⚙️ Executable Generator**: `http://YOUR_DROPLET_IP:8080/executable-generator`  

**Features Available:**
- ✅ File encryption with custom extensions (.exe, .xll, .lnk, .dll, .pdf, etc.)
- ✅ Executable generation (mIRC bots, HTTP bots, calculators, etc.)
- ✅ Network analysis tools
- ✅ Advanced obfuscation options
- ✅ Docker-based compilation
- ✅ Mobile-responsive interfaces

**Ready to secure your digital world! 🔐**