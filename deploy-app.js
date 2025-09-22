#!/usr/bin/env node

/**
 * RawrZ Security Platform - Digital Ocean Deployment Application
 * Interactive deployment tool with configuration management and automation
 */

const fs = require('fs');
const path = require('path');
const { execSync, spawn } = require('child_process');
const readline = require('readline');

// ANSI color codes for terminal output
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    white: '\x1b[37m'
};

class DeploymentApp {
    constructor() {
        this.config = {
            appName: 'rawrz-security-platform',
            version: '1.0.0',
            port: 3000,
            domain: '',
            repository: 'https://github.com/ItsMehRAWRXD/itsmehrawrxd.git',
            dockerImage: 'rawrz-security-platform:latest',
            containerName: 'rawrz-app',
            environment: 'production',
            sslEnabled: false,
            monitoringEnabled: true,
            backupEnabled: true,
            autoUpdate: false
        };
        
        this.rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });
    }

    log(message, color = 'white') {
        console.log(`${colors[color]}${message}${colors.reset}`);
    }

    logSuccess(message) {
        this.log(`✅ ${message}`, 'green');
    }

    logError(message) {
        this.log(`❌ ${message}`, 'red');
    }

    logWarning(message) {
        this.log(`⚠️  ${message}`, 'yellow');
    }

    logInfo(message) {
        this.log(`ℹ️  ${message}`, 'cyan');
    }

    async prompt(question) {
        return new Promise((resolve) => {
            this.rl.question(question, resolve);
        });
    }

    async confirm(question) {
        const answer = await this.prompt(`${question} (y/N): `);
        return answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes';
    }

    displayBanner() {
        console.clear();
        this.log(`
${colors.cyan}╔══════════════════════════════════════════════════════════════════╗
║                   RawrZ Security Platform                           ║
║                Digital Ocean Deployment App                         ║
║                        Version ${this.config.version}                               ║
╚══════════════════════════════════════════════════════════════════╝${colors.reset}

${colors.yellow}🚀 Interactive deployment tool for Digital Ocean droplets${colors.reset}
${colors.magenta}🔧 Automated setup with Docker, SSL, and monitoring${colors.reset}
${colors.green}🛡️  Production-ready security configurations${colors.reset}

`, 'white');
    }

    async displayMenu() {
        this.log('\n📋 Deployment Options:', 'bright');
        this.log('1. 🚀 Quick Deploy (Default Configuration)', 'cyan');
        this.log('2. ⚙️  Custom Configuration', 'cyan');
        this.log('3. 🔧 Advanced Setup with SSL', 'cyan');
        this.log('4. 📊 Monitoring & Backup Setup', 'cyan');
        this.log('5. 🐳 Docker Compose Deployment', 'cyan');
        this.log('6. 🔄 Update Existing Deployment', 'cyan');
        this.log('7. 📋 View Configuration', 'cyan');
        this.log('8. 🧪 Test Deployment', 'cyan');
        this.log('9. ❌ Exit', 'red');
        
        const choice = await this.prompt('\nSelect an option (1-9): ');
        return choice.trim();
    }

    async quickDeploy() {
        this.log('\n🚀 Starting Quick Deploy...', 'bright');
        
        // Check if running on Digital Ocean
        if (!await this.checkDigitalOceanEnvironment()) {
            this.logError('This deployment tool is designed for Digital Ocean droplets');
            return;
        }

        // Update system
        await this.updateSystem();
        
        // Install Docker
        await this.installDocker();
        
        // Setup application
        await this.setupApplication();
        
        // Deploy with Docker
        await this.deployWithDocker();
        
        // Configure firewall
        await this.configureFirewall();
        
        // Display results
        await this.displayDeploymentResults();
    }

    async customConfiguration() {
        this.log('\n⚙️  Custom Configuration Setup', 'bright');
        
        this.config.appName = await this.prompt(`App name [${this.config.appName}]: `) || this.config.appName;
        this.config.port = parseInt(await this.prompt(`Port [${this.config.port}]: `)) || this.config.port;
        this.config.domain = await this.prompt(`Domain (optional): `) || '';
        this.config.repository = await this.prompt(`Repository URL [${this.config.repository}]: `) || this.config.repository;
        this.config.environment = await this.prompt(`Environment [${this.config.environment}]: `) || this.config.environment;
        
        this.config.sslEnabled = await this.confirm('Enable SSL/TLS?');
        this.config.monitoringEnabled = await this.confirm('Enable monitoring?');
        this.config.backupEnabled = await this.confirm('Enable automatic backups?');
        this.config.autoUpdate = await this.confirm('Enable auto-updates?');
        
        this.logSuccess('Configuration updated!');
        await this.saveConfiguration();
    }

    async advancedSetupWithSSL() {
        this.log('\n🔧 Advanced Setup with SSL', 'bright');
        
        // Custom configuration first
        await this.customConfiguration();
        
        if (this.config.sslEnabled) {
            await this.setupSSL();
        }
        
        if (this.config.monitoringEnabled) {
            await this.setupMonitoring();
        }
        
        if (this.config.backupEnabled) {
            await this.setupBackup();
        }
        
        // Deploy with advanced configuration
        await this.deployAdvanced();
    }

    async setupSSL() {
        this.log('\n🔒 Setting up SSL/TLS...', 'bright');
        
        if (!this.config.domain) {
            this.logWarning('Domain is required for SSL setup');
            return;
        }
        
        try {
            // Install certbot
            execSync('apt install -y certbot python3-certbot-nginx', { stdio: 'inherit' });
            
            // Generate SSL certificate
            execSync(`certbot --nginx -d ${this.config.domain} --non-interactive --agree-tos --email admin@${this.config.domain}`, { stdio: 'inherit' });
            
            this.logSuccess('SSL certificate generated successfully!');
        } catch (error) {
            this.logError(`SSL setup failed: ${error.message}`);
        }
    }

    async setupMonitoring() {
        this.log('\n📊 Setting up monitoring...', 'bright');
        
        try {
            // Create monitoring configuration
            const monitoringConfig = `
# Prometheus configuration
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'rawrz-app'
    static_configs:
      - targets: ['localhost:${this.config.port}']
`;

            fs.writeFileSync('/opt/monitoring/prometheus.yml', monitoringConfig);
            
            // Start monitoring stack
            const dockerComposeMonitoring = `
version: '3.8'
services:
  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=200h'
      - '--web.enable-lifecycle'

  grafana:
    image: grafana/grafana
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
`;

            fs.writeFileSync('/opt/monitoring/docker-compose.yml', dockerComposeMonitoring);
            
            this.logSuccess('Monitoring setup completed!');
        } catch (error) {
            this.logError(`Monitoring setup failed: ${error.message}`);
        }
    }

    async setupBackup() {
        this.log('\n💾 Setting up automatic backups...', 'bright');
        
        try {
            const backupScript = `#!/bin/bash
# Backup script for RawrZ Security Platform
BACKUP_DIR="/opt/backups"
APP_DIR="/opt/${this.config.appName}"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup application data
tar -czf $BACKUP_DIR/rawrz_backup_$DATE.tar.gz -C $APP_DIR .

# Keep only last 7 days of backups
find $BACKUP_DIR -name "rawrz_backup_*.tar.gz" -mtime +7 -delete

echo "Backup completed: rawrz_backup_$DATE.tar.gz"
`;

            fs.writeFileSync('/opt/backup.sh', backupScript);
            execSync('chmod +x /opt/backup.sh');
            
            // Add to crontab
            execSync('echo "0 2 * * * /opt/backup.sh" | crontab -');
            
            this.logSuccess('Backup system configured!');
        } catch (error) {
            this.logError(`Backup setup failed: ${error.message}`);
        }
    }

    async checkDigitalOceanEnvironment() {
        try {
            // Check for Digital Ocean metadata
            const response = await fetch('http://169.254.169.254/metadata/v1/id', { timeout: 5000 });
            return response.ok;
        } catch (error) {
            return false;
        }
    }

    async updateSystem() {
        this.log('\n📦 Updating system packages...', 'bright');
        
        try {
            execSync('apt update && apt upgrade -y', { stdio: 'inherit' });
            this.logSuccess('System updated successfully!');
        } catch (error) {
            this.logError(`System update failed: ${error.message}`);
            throw error;
        }
    }

    async installDocker() {
        this.log('\n🐳 Installing Docker...', 'bright');
        
        try {
            // Check if Docker is already installed
            try {
                execSync('docker --version', { stdio: 'pipe' });
                this.logInfo('Docker is already installed');
                return;
            } catch (error) {
                // Docker not installed, proceed with installation
            }
            
            execSync('curl -fsSL https://get.docker.com -o get-docker.sh', { stdio: 'inherit' });
            execSync('sh get-docker.sh', { stdio: 'inherit' });
            execSync('usermod -aG docker $USER', { stdio: 'inherit' });
            execSync('systemctl enable docker', { stdio: 'inherit' });
            execSync('systemctl start docker', { stdio: 'inherit' });
            
            this.logSuccess('Docker installed successfully!');
        } catch (error) {
            this.logError(`Docker installation failed: ${error.message}`);
            throw error;
        }
    }

    async setupApplication() {
        this.log('\n📁 Setting up application directory...', 'bright');
        
        try {
            const appDir = `/opt/${this.config.appName}`;
            
            // Create directory
            execSync(`mkdir -p ${appDir}`, { stdio: 'inherit' });
            process.chdir(appDir);
            
            // Clone repository if not exists
            if (!fs.existsSync('.git')) {
                execSync(`git clone ${this.config.repository} .`, { stdio: 'inherit' });
            } else {
                execSync('git pull', { stdio: 'inherit' });
            }
            
            this.logSuccess('Application setup completed!');
        } catch (error) {
            this.logError(`Application setup failed: ${error.message}`);
            throw error;
        }
    }

    async deployWithDocker() {
        this.log('\n🔨 Building and deploying with Docker...', 'bright');
        
        try {
            // Build Docker image
            execSync(`docker build -t ${this.config.dockerImage} .`, { stdio: 'inherit' });
            
            // Stop existing container
            try {
                execSync(`docker stop ${this.config.containerName}`, { stdio: 'pipe' });
                execSync(`docker rm ${this.config.containerName}`, { stdio: 'pipe' });
            } catch (error) {
                // Container doesn't exist, that's fine
            }
            
            // Run new container
            const dockerRunCmd = `docker run -d \
                --name ${this.config.containerName} \
                --restart unless-stopped \
                -p ${this.config.port}:3000 \
                -v /opt/${this.config.appName}/logs:/app/logs \
                -v /opt/${this.config.appName}/data:/app/data \
                -e NODE_ENV=${this.config.environment} \
                ${this.config.dockerImage}`;
            
            execSync(dockerRunCmd, { stdio: 'inherit' });
            
            this.logSuccess('Docker deployment completed!');
        } catch (error) {
            this.logError(`Docker deployment failed: ${error.message}`);
            throw error;
        }
    }

    async deployAdvanced() {
        this.log('\n🚀 Advanced deployment with Docker Compose...', 'bright');
        
        try {
            // Use existing docker-compose.yml
            execSync('docker-compose down', { stdio: 'inherit' });
            execSync('docker-compose up -d --build', { stdio: 'inherit' });
            
            this.logSuccess('Advanced deployment completed!');
        } catch (error) {
            this.logError(`Advanced deployment failed: ${error.message}`);
            throw error;
        }
    }

    async configureFirewall() {
        this.log('\n🔥 Configuring firewall...', 'bright');
        
        try {
            execSync(`ufw allow ${this.config.port}/tcp`, { stdio: 'inherit' });
            execSync('ufw allow ssh', { stdio: 'inherit' });
            execSync('ufw --force enable', { stdio: 'inherit' });
            
            this.logSuccess('Firewall configured!');
        } catch (error) {
            this.logError(`Firewall configuration failed: ${error.message}`);
        }
    }

    async displayDeploymentResults() {
        this.log('\n🎉 Deployment completed successfully!', 'green');
        
        try {
            const publicIP = execSync('curl -s http://checkip.amazonaws.com/', { encoding: 'utf8' }).trim();
            
            this.log('\n🌐 Access Information:', 'bright');
            this.log(`   Main Application: http://${publicIP}:${this.config.port}`, 'cyan');
            this.log(`   Health Check: http://${publicIP}:${this.config.port}/health`, 'cyan');
            this.log(`   API Test: http://${publicIP}:${this.config.port}/api/simple-test`, 'cyan');
            
            if (this.config.domain) {
                this.log(`   Domain: https://${this.config.domain}`, 'cyan');
            }
            
            this.log('\n📝 Management Commands:', 'bright');
            this.log(`   View logs: docker logs ${this.config.containerName}`, 'white');
            this.log(`   Stop app: docker stop ${this.config.containerName}`, 'white');
            this.log(`   Restart app: docker restart ${this.config.containerName}`, 'white');
            this.log(`   Remove app: docker rm -f ${this.config.containerName}`, 'white');
            
            if (this.config.monitoringEnabled) {
                this.log(`   Monitoring: http://${publicIP}:9090 (Prometheus)`, 'cyan');
                this.log(`   Dashboard: http://${publicIP}:3001 (Grafana)`, 'cyan');
            }
            
        } catch (error) {
            this.logWarning('Could not retrieve public IP address');
        }
    }

    async viewConfiguration() {
        this.log('\n📋 Current Configuration:', 'bright');
        console.log(JSON.stringify(this.config, null, 2));
    }

    async testDeployment() {
        this.log('\n🧪 Testing deployment...', 'bright');
        
        try {
            const testUrl = `http://localhost:${this.config.port}/health`;
            const response = await fetch(testUrl, { timeout: 10000 });
            
            if (response.ok) {
                this.logSuccess('Health check passed - Deployment is working!');
            } else {
                this.logError(`Health check failed - Status: ${response.status}`);
            }
        } catch (error) {
            this.logError(`Test failed: ${error.message}`);
        }
    }

    async saveConfiguration() {
        try {
            fs.writeFileSync('/opt/deployment-config.json', JSON.stringify(this.config, null, 2));
            this.logSuccess('Configuration saved!');
        } catch (error) {
            this.logError(`Failed to save configuration: ${error.message}`);
        }
    }

    async loadConfiguration() {
        try {
            if (fs.existsSync('/opt/deployment-config.json')) {
                const configData = fs.readFileSync('/opt/deployment-config.json', 'utf8');
                this.config = { ...this.config, ...JSON.parse(configData) };
                this.logSuccess('Configuration loaded!');
            }
        } catch (error) {
            this.logWarning('Could not load configuration, using defaults');
        }
    }

    async run() {
        try {
            this.displayBanner();
            await this.loadConfiguration();
            
            while (true) {
                const choice = await this.displayMenu();
                
                switch (choice) {
                    case '1':
                        await this.quickDeploy();
                        break;
                    case '2':
                        await this.customConfiguration();
                        break;
                    case '3':
                        await this.advancedSetupWithSSL();
                        break;
                    case '4':
                        await this.setupMonitoring();
                        await this.setupBackup();
                        break;
                    case '5':
                        await this.deployAdvanced();
                        break;
                    case '6':
                        await this.quickDeploy();
                        break;
                    case '7':
                        await this.viewConfiguration();
                        break;
                    case '8':
                        await this.testDeployment();
                        break;
                    case '9':
                        this.log('\n👋 Goodbye!', 'green');
                        this.rl.close();
                        process.exit(0);
                        break;
                    default:
                        this.logError('Invalid option. Please select 1-9.');
                        break;
                }
                
                await this.prompt('\nPress Enter to continue...');
            }
        } catch (error) {
            this.logError(`Application error: ${error.message}`);
            this.rl.close();
            process.exit(1);
        }
    }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
    console.log('\n\n👋 Deployment app shutting down...');
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('\n\n👋 Deployment app shutting down...');
    process.exit(0);
});

// Start the application
if (require.main === module) {
    const app = new DeploymentApp();
    app.run();
}

module.exports = DeploymentApp;