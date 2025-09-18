const fs = require('fs');
const path = require('path');

class PanelConfigManager {
    constructor() {
        this.config = {};
        this.loadConfig();
    }
    
    loadConfig() {
        // Load from .env file
        if (fs.existsSync('.env')) {
            const envContent = fs.readFileSync('.env', 'utf8');
            envContent.split('\n').forEach(line => {
                if (line.trim() && !line.startsWith('#')) {
                    const [key, ...valueParts] = line.split('=');
                    if (key && valueParts.length > 0) {
                        this.config[key.trim()] = valueParts.join('=').trim();
                    }
                }
            });
        }
        
        // Set defaults
        this.config = {
            SERVER_URL: this.config.SERVER_URL || 'http://localhost:8080',
            API_BASE_URL: this.config.API_BASE_URL || 'http://localhost:3000',
            PAYLOAD_SERVER: this.config.PAYLOAD_SERVER || 'http://payload-server.com',
            PANEL_URL: this.config.PANEL_URL || 'https://panel.example.com',
            ...this.config
        };
    }
    
    getConfig() {
        return this.config;
    }
    
    updateConfig(key, value) {
        this.config[key] = value;
        this.saveConfig();
    }
    
    saveConfig() {
        const envContent = Object.entries(this.config)
            .map(([key, value]) => key + '=' + value)
            .join('\n');
        fs.writeFileSync('.env', envContent);
    }
}

module.exports = new PanelConfigManager();
