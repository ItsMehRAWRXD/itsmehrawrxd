#!/usr/bin/env node

/**
 * RawrZ OpenSSL CLI Example
 * 
 * Command-line interface for managing OpenSSL toggle settings
 * Usage: node openssl-cli-example.js [command] [options]
 */

const { OpenSSLConfig } = require('../src/utils/openssl-config');
const { OpenSSLManager } = require('../src/utils/openssl-manager');
const { AdvancedCrypto } = require('../src/engines/advanced-crypto');
const { StubGenerator } = require('../src/engines/stub-generator');

class OpenSSLCli {
    constructor() {
        this.manager = new OpenSSLManager();
        this.isInitialized = false;
    }

    async initialize() {
        if (!this.isInitialized) {
            await this.manager.initialize();
            this.isInitialized = true;
        }
    }

    async run() {
        const args = process.argv.slice(2);
        const command = args[0] || 'help';

        try {
            await this.initialize();

            switch (command) {
                case 'status':
                    await this.showStatus();
                    break;
                case 'toggle-openssl':
                    const opensslEnabled = args[1] === 'true' || args[1] === '1';
                    await this.toggleOpenSSL(opensslEnabled);
                    break;
                case 'toggle-custom':
                    const customEnabled = args[1] === 'true' || args[1] === '1';
                    await this.toggleCustom(customEnabled);
                    break;
                case 'list-algorithms':
                    const filter = args[1] || 'all';
                    await this.listAlgorithms(filter);
                    break;
                case 'test-encryption':
                    const algorithm = args[1] || 'aes-256-gcm';
                    const data = args[2] || 'Hello, RawrZ!';
                    await this.testEncryption(algorithm, data);
                    break;
                case 'resolve-algorithm':
                    const algToResolve = args[1];
                    if (!algToResolve) {
                        console.error('❌ Algorithm name required');
                        process.exit(1);
                    }
                    await this.resolveAlgorithm(algToResolve);
                    break;
                case 'reset':
                    await this.resetToDefaults();
                    break;
                case 'help':
                default:
                    this.showHelp();
                    break;
            }
        } catch (error) {
            console.error('❌ Error:', error.message);
            process.exit(1);
        }
    }

    async showStatus() {
        console.log('🔐 RawrZ OpenSSL Configuration Status\n');
        
        const config = this.manager.getConfigSummary();
        console.log(`Mode: ${config.mode}`);
        console.log(`Custom Algorithms: ${config.customAlgorithms}`);
        console.log(`Auto Fallback: ${config.autoFallback ? 'Enabled' : 'Disabled'}`);
        console.log(`Preferred OpenSSL: ${config.preferredOpenSSL}`);
        console.log(`Preferred Custom: ${config.preferredCustom}`);
        console.log(`Algorithm Mappings: ${config.algorithmMappings}`);
        console.log(`Registered Engines: ${config.registeredEngines.join(', ')}`);
        console.log(`Available Algorithms: ${config.availableAlgorithms}`);
        console.log(`OpenSSL Algorithms: ${config.opensslAlgorithms}`);
        console.log(`Custom Algorithms: ${config.customAlgorithms}`);
        console.log(`Last Updated: ${config.lastUpdated}`);
    }

    async toggleOpenSSL(enabled) {
        console.log(`🔄 Toggling OpenSSL mode to ${enabled ? 'enabled' : 'disabled'}...`);
        
        const success = await this.manager.toggleOpenSSLMode(enabled);
        if (success) {
            console.log(`✅ OpenSSL mode ${enabled ? 'enabled' : 'disabled'} successfully`);
        } else {
            console.log('❌ Failed to toggle OpenSSL mode');
        }
    }

    async toggleCustom(enabled) {
        console.log(`🔄 Toggling custom algorithms to ${enabled ? 'enabled' : 'disabled'}...`);
        
        const success = await this.manager.toggleCustomAlgorithms(enabled);
        if (success) {
            console.log(`✅ Custom algorithms ${enabled ? 'enabled' : 'disabled'} successfully`);
        } else {
            console.log('❌ Failed to toggle custom algorithms');
        }
    }

    async listAlgorithms(filter) {
        console.log(`📋 Available Algorithms (${filter}):\n`);
        
        let algorithms = [];
        switch (filter) {
            case 'openssl':
                algorithms = this.manager.getOpenSSLAlgorithms();
                break;
            case 'custom':
                algorithms = this.manager.getCustomAlgorithms();
                break;
            default:
                algorithms = this.manager.getAvailableAlgorithms();
        }
        
        if (algorithms.length === 0) {
            console.log('No algorithms found');
            return;
        }
        
        algorithms.forEach((algorithm, index) => {
            const isOpenSSL = this.manager.getOpenSSLAlgorithms().includes(algorithm);
            const isCustom = this.manager.getCustomAlgorithms().includes(algorithm);
            
            let type = '';
            if (isOpenSSL) type = '🔒 OpenSSL';
            else if (isCustom) type = '⚠️  Custom';
            else type = '❓ Unknown';
            
            console.log(`${(index + 1).toString().padStart(3)}. ${algorithm.padEnd(25)} ${type}`);
        });
    }

    async testEncryption(algorithm, data) {
        console.log(`🔐 Testing encryption with ${algorithm}...\n`);
        
        const crypto = new AdvancedCrypto({
            useOpenSSL: this.manager.isInitialized ? this.manager.config.isOpenSSLMode() : true,
            allowCustomAlgorithms: this.manager.isInitialized ? this.manager.config.areCustomAlgorithmsAllowed() : false
        });
        
        try {
            const result = await crypto.encrypt(data, { algorithm });
            console.log(`✅ Encryption successful`);
            console.log(`Algorithm used: ${result.algorithm}`);
            console.log(`Encrypted data: ${result.encrypted.substring(0, 50)}...`);
            console.log(`Key size: ${result.key.length * 2} bits`);
            console.log(`IV size: ${result.iv.length * 2} bits`);
        } catch (error) {
            console.log(`❌ Encryption failed: ${error.message}`);
        }
    }

    async resolveAlgorithm(algorithm) {
        console.log(`🔄 Resolving algorithm: ${algorithm}\n`);
        
        const resolved = this.manager.resolveAlgorithm(algorithm);
        console.log(`Original: ${algorithm}`);
        console.log(`Resolved: ${resolved}`);
        
        if (resolved !== algorithm) {
            console.log(`⚠️  Algorithm was changed due to current configuration`);
        } else {
            console.log(`✅ Algorithm unchanged`);
        }
    }

    async resetToDefaults() {
        console.log('🔄 Resetting configuration to defaults...');
        
        const success = await this.manager.resetToDefaults();
        if (success) {
            console.log('✅ Configuration reset to defaults successfully');
        } else {
            console.log('❌ Failed to reset configuration');
        }
    }

    showHelp() {
        console.log(`
🔐 RawrZ OpenSSL CLI Tool

Usage: node openssl-cli-example.js [command] [options]

Commands:
  status                    Show current OpenSSL configuration status
  toggle-openssl [true|false]  Enable/disable OpenSSL mode
  toggle-custom [true|false]   Enable/disable custom algorithms
  list-algorithms [filter]     List available algorithms (all|openssl|custom)
  test-encryption [alg] [data] Test encryption with specified algorithm
  resolve-algorithm [alg]      Show how an algorithm would be resolved
  reset                       Reset configuration to defaults
  help                        Show this help message

Examples:
  node openssl-cli-example.js status
  node openssl-cli-example.js toggle-openssl true
  node openssl-cli-example.js list-algorithms openssl
  node openssl-cli-example.js test-encryption aes-256-gcm "Hello World"
  node openssl-cli-example.js resolve-algorithm serpent-256-cbc
  node openssl-cli-example.js reset
        `);
    }
}

// Run the CLI
if (require.main === module) {
    const cli = new OpenSSLCli();
    cli.run().catch(error => {
        console.error('❌ CLI Error:', error.message);
        process.exit(1);
    });
}

module.exports = { OpenSSLCli };
