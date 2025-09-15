// RawrZ OpenSSL Configuration Manager
const fs = require('fs').promises;
const path = require('path');
const { logger } = require('./logger');

class OpenSSLConfig {
    constructor(configPath = './data/openssl-config.json') {
        this.configPath = configPath;
        this.defaultConfig = {
            useOpenSSL: true,
            allowCustomAlgorithms: false,
            preferredAlgorithms: {
                openssl: 'aes-256-gcm',
                custom: 'quantum-resistant'
            },
            algorithmPreferences: {
                'serpent-256-cbc': 'aes-256-cbc',
                'serpent-192-cbc': 'aes-192-cbc',
                'serpent-128-cbc': 'aes-128-cbc',
                'twofish-256-cbc': 'camellia-256-cbc',
                'twofish-192-cbc': 'camellia-192-cbc',
                'twofish-128-cbc': 'camellia-128-cbc',
                'quantum-resistant': 'aes-256-gcm',
                'homomorphic': 'aes-256-cbc',
                'multiparty': 'aes-256-gcm',
                'steganographic': 'aes-256-ctr',
                'hybrid': 'aes-256-cbc',
                'triple': 'aes-256-gcm',
                'custom-xor': 'rc4',
                'custom-rot': 'rc4',
                'custom-vigenere': 'rc4',
                'custom-caesar': 'rc4'
            },
            autoFallback: true,
            showWarnings: true,
            lastUpdated: new Date().toISOString()
        };
        this.config = { ...this.defaultConfig };
    }

    // Load configuration from file
    async loadConfig() {
        try {
            const configData = await fs.readFile(this.configPath, 'utf8');
            this.config = { ...this.defaultConfig, ...JSON.parse(configData) };
            logger.info('OpenSSL configuration loaded successfully');
            return this.config;
        } catch (error) {
            if (error.code === 'ENOENT') {
                logger.info('OpenSSL config file not found, using defaults');
                await this.saveConfig();
                return this.config;
            }
            logger.error('Failed to load OpenSSL configuration:', error.message);
            return this.config;
        }
    }

    // Save configuration to file
    async saveConfig() {
        try {
            // Ensure data directory exists
            const dataDir = path.dirname(this.configPath);
            await fs.mkdir(dataDir, { recursive: true });
            
            this.config.lastUpdated = new Date().toISOString();
            await fs.writeFile(this.configPath, JSON.stringify(this.config, null, 2));
            logger.info('OpenSSL configuration saved successfully');
            return true;
        } catch (error) {
            logger.error('Failed to save OpenSSL configuration:', error.message);
            return false;
        }
    }

    // Get current configuration
    getConfig() {
        return { ...this.config };
    }

    // Update configuration
    async updateConfig(updates) {
        this.config = { ...this.config, ...updates };
        this.config.lastUpdated = new Date().toISOString();
        return await this.saveConfig();
    }

    // Toggle OpenSSL mode
    async setOpenSSLMode(enabled) {
        const oldValue = this.config.useOpenSSL;
        this.config.useOpenSSL = enabled;
        this.config.lastUpdated = new Date().toISOString();
        
        if (await this.saveConfig()) {
            logger.info(`OpenSSL mode ${enabled ? 'enabled' : 'disabled'} (was ${oldValue})`);
            return true;
        }
        return false;
    }

    // Toggle custom algorithms
    async setCustomAlgorithms(enabled) {
        const oldValue = this.config.allowCustomAlgorithms;
        this.config.allowCustomAlgorithms = enabled;
        this.config.lastUpdated = new Date().toISOString();
        
        if (await this.saveConfig()) {
            logger.info(`Custom algorithms ${enabled ? 'enabled' : 'disabled'} (was ${oldValue})`);
            return true;
        }
        return false;
    }

    // Set preferred algorithm for a category
    async setPreferredAlgorithm(category, algorithm) {
        if (!this.config.preferredAlgorithms) {
            this.config.preferredAlgorithms = {};
        }
        this.config.preferredAlgorithms[category] = algorithm;
        this.config.lastUpdated = new Date().toISOString();
        
        if (await this.saveConfig()) {
            logger.info(`Preferred ${category} algorithm set to ${algorithm}`);
            return true;
        }
        return false;
    }

    // Add or update algorithm preference
    async setAlgorithmPreference(customAlgorithm, opensslAlternative) {
        if (!this.config.algorithmPreferences) {
            this.config.algorithmPreferences = {};
        }
        this.config.algorithmPreferences[customAlgorithm] = opensslAlternative;
        this.config.lastUpdated = new Date().toISOString();
        
        if (await this.saveConfig()) {
            logger.info(`Algorithm preference set: ${customAlgorithm} -> ${opensslAlternative}`);
            return true;
        }
        return false;
    }

    // Get OpenSSL alternative for a custom algorithm
    getOpenSSLAlternative(customAlgorithm) {
        return this.config.algorithmPreferences[customAlgorithm] || customAlgorithm;
    }

    // Check if OpenSSL mode is enabled
    isOpenSSLMode() {
        return this.config.useOpenSSL;
    }

    // Check if custom algorithms are allowed
    areCustomAlgorithmsAllowed() {
        return this.config.allowCustomAlgorithms;
    }

    // Get preferred algorithm for category
    getPreferredAlgorithm(category) {
        return this.config.preferredAlgorithms[category];
    }

    // Reset to default configuration
    async resetToDefaults() {
        this.config = { ...this.defaultConfig };
        this.config.lastUpdated = new Date().toISOString();
        
        if (await this.saveConfig()) {
            logger.info('OpenSSL configuration reset to defaults');
            return true;
        }
        return false;
    }

    // Get configuration summary
    getConfigSummary() {
        return {
            mode: this.config.useOpenSSL ? 'OpenSSL' : 'Custom',
            customAlgorithms: this.config.allowCustomAlgorithms ? 'Enabled' : 'Disabled',
            autoFallback: this.config.autoFallback ? 'Enabled' : 'Disabled',
            preferredOpenSSL: this.config.preferredAlgorithms.openssl,
            preferredCustom: this.config.preferredAlgorithms.custom,
            algorithmMappings: Object.keys(this.config.algorithmPreferences).length,
            lastUpdated: this.config.lastUpdated
        };
    }

    // Validate configuration
    validateConfig() {
        const errors = [];
        
        if (typeof this.config.useOpenSSL !== 'boolean') {
            errors.push('useOpenSSL must be a boolean');
        }
        
        if (typeof this.config.allowCustomAlgorithms !== 'boolean') {
            errors.push('allowCustomAlgorithms must be a boolean');
        }
        
        if (!this.config.preferredAlgorithms || typeof this.config.preferredAlgorithms !== 'object') {
            errors.push('preferredAlgorithms must be an object');
        }
        
        if (!this.config.algorithmPreferences || typeof this.config.algorithmPreferences !== 'object') {
            errors.push('algorithmPreferences must be an object');
        }
        
        return {
            isValid: errors.length === 0,
            errors
        };
    }
}

module.exports = { OpenSSLConfig };
