#!/usr/bin/env node

/**
 * Cursor Automation Runner
 * Easy-to-use script to start the Cursor automation bot
 * 
 * Usage:
 *   node cursor-automation-runner.js
 *   node cursor-automation-runner.js --config custom-config.json
 *   node cursor-automation-runner.js --daemon
 */

const path = require('path');
const fs = require('fs');
const CursorAutomationBot = require('./src/engines/cursor-automation-bot');

class CursorAutomationRunner {
    constructor() {
        this.bot = null;
        this.configPath = 'cursor-automation-config.json';
        this.isDaemon = false;
    }
    
    async initialize() {
        try {
            console.log('🚀 Initializing Cursor Automation Runner...');
            
            // Parse command line arguments
            this.parseArguments();
            
            // Load configuration
            const config = await this.loadConfiguration();
            
            // Create bot instance
            this.bot = new CursorAutomationBot(config.cursorAutomation);
            
            // Set up event handlers
            this.setupEventHandlers();
            
            console.log('✅ Cursor Automation Runner initialized successfully');
            
        } catch (error) {
            console.error('❌ Failed to initialize runner:', error.message);
            process.exit(1);
        }
    }
    
    parseArguments() {
        const args = process.argv.slice(2);
        
        for (let i = 0; i < args.length; i++) {
            switch (args[i]) {
                case '--config':
                    if (i + 1 < args.length) {
                        this.configPath = args[i + 1];
                        i++;
                    }
                    break;
                case '--daemon':
                    this.isDaemon = true;
                    break;
                case '--help':
                    this.showHelp();
                    process.exit(0);
                    break;
            }
        }
    }
    
    showHelp() {
        console.log(`
Cursor Automation Runner - Auto-click "Keep all" when source is updated

Usage:
  node cursor-automation-runner.js [options]

Options:
  --config <file>    Use custom configuration file (default: cursor-automation-config.json)
  --daemon          Run in daemon mode (background)
  --help            Show this help message

Examples:
  node cursor-automation-runner.js
  node cursor-automation-runner.js --config my-config.json
  node cursor-automation-runner.js --daemon

Features:
  - Automatic detection of Cursor IDE updates
  - Auto-click "Keep all" functionality
  - Cross-platform support (Windows, macOS, Linux)
  - Configurable delays and retry mechanisms
  - Integration with existing bot infrastructure
  - Screenshot capture for debugging
  - Notification system (HTTP, IRC, Discord)
        `);
    }
    
    async loadConfiguration() {
        try {
            if (!fs.existsSync(this.configPath)) {
                console.log(`⚠️  Configuration file not found: ${this.configPath}`);
                console.log('📝 Creating default configuration...');
                await this.createDefaultConfig();
            }
            
            const configData = fs.readFileSync(this.configPath, 'utf8');
            const config = JSON.parse(configData);
            
            console.log(`📋 Loaded configuration from: ${this.configPath}`);
            return config;
            
        } catch (error) {
            console.error(`❌ Failed to load configuration: ${error.message}`);
            throw error;
        }
    }
    
    async createDefaultConfig() {
        const defaultConfig = {
            "cursorAutomation": {
                "enabled": true,
                "autoClickDelay": 1000,
                "maxRetries": 3,
                "retryDelay": 2000,
                "checkInterval": 5000,
                "enableLogging": true,
                "enableNotifications": true,
                
                "uiSettings": {
                    "buttonText": "Keep all",
                    "dialogTitle": "Source updated",
                    "timeout": 10000,
                    "confidence": 0.8
                },
                
                "integration": {
                    "enableHTTPBot": true,
                    "enableIRCBot": false,
                    "enableDiscordBot": false,
                    "webhookUrl": null,
                    "ircChannel": "#cursor-automation"
                }
            }
        };
        
        fs.writeFileSync(this.configPath, JSON.stringify(defaultConfig, null, 2));
        console.log(`✅ Created default configuration: ${this.configPath}`);
    }
    
    setupEventHandlers() {
        this.bot.on('started', () => {
            console.log('🎯 Cursor Automation Bot started successfully');
            console.log('👀 Monitoring for Cursor updates...');
        });
        
        this.bot.on('stopped', () => {
            console.log('🛑 Cursor Automation Bot stopped');
        });
        
        this.bot.on('updateHandled', (data) => {
            if (data.success) {
                console.log(`✅ Successfully handled Cursor update (${data.retries} retries)`);
            } else {
                console.log(`❌ Failed to handle Cursor update after ${data.retries} attempts: ${data.error}`);
            }
        });
        
        this.bot.on('configUpdated', (config) => {
            console.log('⚙️  Configuration updated');
        });
        
        // Handle process signals
        process.on('SIGINT', () => {
            console.log('\n🛑 Received SIGINT, shutting down gracefully...');
            this.shutdown();
        });
        
        process.on('SIGTERM', () => {
            console.log('\n🛑 Received SIGTERM, shutting down gracefully...');
            this.shutdown();
        });
        
        process.on('uncaughtException', (error) => {
            console.error('💥 Uncaught Exception:', error);
            this.shutdown();
        });
        
        process.on('unhandledRejection', (reason, promise) => {
            console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
            this.shutdown();
        });
    }
    
    async start() {
        try {
            console.log('🚀 Starting Cursor Automation Bot...');
            
            if (this.isDaemon) {
                console.log('👻 Running in daemon mode');
                // In daemon mode, we would typically fork the process
                // For now, we'll just run in the background
            }
            
            await this.bot.start();
            
            if (!this.isDaemon) {
                console.log('💡 Press Ctrl+C to stop the bot');
                // Keep the process alive
                setInterval(() => {}, 1000);
            }
            
        } catch (error) {
            console.error('❌ Failed to start bot:', error.message);
            process.exit(1);
        }
    }
    
    async shutdown() {
        try {
            if (this.bot) {
                await this.bot.stop();
            }
            console.log('👋 Goodbye!');
            process.exit(0);
        } catch (error) {
            console.error('❌ Error during shutdown:', error.message);
            process.exit(1);
        }
    }
    
    async run() {
        await this.initialize();
        await this.start();
    }
}

// Run the runner
if (require.main === module) {
    const runner = new CursorAutomationRunner();
    runner.run().catch(console.error);
}

module.exports = CursorAutomationRunner;
