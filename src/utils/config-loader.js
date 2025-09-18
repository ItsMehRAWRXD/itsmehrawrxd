const fs = require('fs');
const path = require('path');

class ConfigLoader {
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
            PORT: this.config.PORT || '8080',
            SERVER_URL: this.config.SERVER_URL || 'http://localhost:8080',
            API_BASE_URL: this.config.API_BASE_URL || 'http://localhost:3000',
            PAYLOAD_SERVER: this.config.PAYLOAD_SERVER || 'http://payload-server.com',
            PANEL_URL: this.config.PANEL_URL || 'https://panel.example.com',
            OPENAI_API_URL: this.config.OPENAI_API_URL || 'https://api.openai.com',
            GITHUB_API_URL: this.config.GITHUB_API_URL || 'https://api.github.com',
            JOTTI_API_URL: this.config.JOTTI_API_URL || 'https://virusscan.jotti.org',
            ...this.config
        };
    }
    
    get(key, defaultValue = null) {
        return this.config[key] || defaultValue;
    }
    
    set(key, value) {
        this.config[key] = value;
    }
    
    getAll() {
        return { ...this.config };
    }
}

module.exports = new ConfigLoader();
