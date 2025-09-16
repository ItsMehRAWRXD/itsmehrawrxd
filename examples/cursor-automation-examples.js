/**
 * Cursor Automation Bot - Usage Examples
 * 
 * This file demonstrates various ways to use the Cursor Automation Bot
 * for automatically clicking "Keep all" when Cursor IDE source is updated.
 */

const CursorAutomationBot = require('../src/engines/cursor-automation-bot');
const path = require('path');

// Example 1: Basic Usage
async function basicExample() {
    console.log('=== Basic Usage Example ===');
    
    const bot = new CursorAutomationBot();
    
    // Set up event handlers
    bot.on('started', () => {
        console.log('Bot started successfully!');
    });
    
    bot.on('updateHandled', (data) => {
        if (data.success) {
            console.log('✅ Update handled successfully!');
        } else {
            console.log('❌ Failed to handle update');
        }
    });
    
    // Start the bot
    await bot.start();
    
    // Keep running for 30 seconds
    setTimeout(async () => {
        await bot.stop();
        console.log('Bot stopped');
    }, 30000);
}

// Example 2: Custom Configuration
async function customConfigExample() {
    console.log('=== Custom Configuration Example ===');
    
    const customConfig = {
        autoClickDelay: 2000,        // Wait 2 seconds before clicking
        maxRetries: 5,               // Try up to 5 times
        retryDelay: 3000,            // Wait 3 seconds between retries
        checkInterval: 3000,         // Check every 3 seconds
        enableLogging: true,
        enableNotifications: true,
        
        uiSettings: {
            buttonText: 'Keep all',
            dialogTitle: 'Source updated',
            timeout: 15000,          // Wait up to 15 seconds for dialog
            confidence: 0.9          // Higher confidence for button detection
        },
        
        integration: {
            enableHTTPBot: true,
            webhookUrl: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK',
            enableIRCBot: false,
            enableDiscordBot: false
        }
    };
    
    const bot = new CursorAutomationBot(customConfig);
    
    // Start with custom configuration
    await bot.start();
    
    // Run for 1 minute
    setTimeout(async () => {
        await bot.stop();
    }, 60000);
}

// Example 3: Integration with Existing Bot System
async function integrationExample() {
    console.log('=== Integration Example ===');
    
    const bot = new CursorAutomationBot({
        integration: {
            enableHTTPBot: true,
            enableIRCBot: true,
            enableDiscordBot: true,
            webhookUrl: 'https://your-webhook-url.com/notifications',
            ircChannel: '#cursor-updates'
        }
    });
    
    // Handle IRC messages
    bot.on('ircMessage', (data) => {
        console.log(`IRC Message to ${data.channel}: ${data.message}`);
        // Send to your IRC bot system
    });
    
    // Handle Discord messages
    bot.on('discordMessage', (data) => {
        console.log(`Discord Message to ${data.channel}: ${data.message}`);
        // Send to your Discord bot system
    });
    
    await bot.start();
}

// Example 4: Platform-Specific Configuration
async function platformSpecificExample() {
    console.log('=== Platform-Specific Example ===');
    
    const os = require('os');
    const platform = os.platform();
    
    let config = {};
    
    switch (platform) {
        case 'win32':
            config = {
                autoClickDelay: 1500,  // Windows might need more time
                uiSettings: {
                    buttonText: 'Keep all',
                    timeout: 12000
                }
            };
            break;
            
        case 'darwin':
            config = {
                autoClickDelay: 1000,  // macOS is usually faster
                uiSettings: {
                    buttonText: 'Keep all',
                    timeout: 8000
                }
            };
            break;
            
        case 'linux':
            config = {
                autoClickDelay: 2000,  // Linux might need more time
                uiSettings: {
                    buttonText: 'Keep all',
                    timeout: 15000
                }
            };
            break;
    }
    
    const bot = new CursorAutomationBot(config);
    await bot.start();
}

// Example 5: Error Handling and Recovery
async function errorHandlingExample() {
    console.log('=== Error Handling Example ===');
    
    const bot = new CursorAutomationBot({
        maxRetries: 3,
        retryDelay: 2000,
        enableLogging: true
    });
    
    bot.on('updateHandled', (data) => {
        if (data.success) {
            console.log('✅ Update handled successfully');
        } else {
            console.log(`❌ Failed after ${data.retries} attempts: ${data.error}`);
            
            // Implement custom recovery logic
            if (data.retries >= 3) {
                console.log('🔄 Attempting manual recovery...');
                // Your custom recovery logic here
            }
        }
    });
    
    // Handle bot errors
    bot.on('error', (error) => {
        console.error('Bot error:', error);
        // Implement error recovery
    });
    
    await bot.start();
}

// Example 6: Monitoring and Statistics
async function monitoringExample() {
    console.log('=== Monitoring Example ===');
    
    const bot = new CursorAutomationBot();
    
    let updateCount = 0;
    let successCount = 0;
    let failureCount = 0;
    
    bot.on('updateHandled', (data) => {
        updateCount++;
        if (data.success) {
            successCount++;
        } else {
            failureCount++;
        }
        
        console.log(`📊 Statistics:`);
        console.log(`   Total updates: ${updateCount}`);
        console.log(`   Successful: ${successCount}`);
        console.log(`   Failed: ${failureCount}`);
        console.log(`   Success rate: ${((successCount / updateCount) * 100).toFixed(1)}%`);
    });
    
    // Periodic status reporting
    setInterval(() => {
        const status = bot.getStatus();
        console.log('📈 Bot Status:', status);
    }, 30000); // Every 30 seconds
    
    await bot.start();
}

// Example 7: Dynamic Configuration Updates
async function dynamicConfigExample() {
    console.log('=== Dynamic Configuration Example ===');
    
    const bot = new CursorAutomationBot();
    
    await bot.start();
    
    // Update configuration after 30 seconds
    setTimeout(() => {
        console.log('⚙️  Updating configuration...');
        bot.updateConfig({
            autoClickDelay: 500,  // Faster clicking
            checkInterval: 2000   // More frequent checking
        });
    }, 30000);
    
    // Update again after 60 seconds
    setTimeout(() => {
        console.log('⚙️  Updating configuration again...');
        bot.updateConfig({
            autoClickDelay: 2000,  // Slower clicking
            checkInterval: 10000   // Less frequent checking
        });
    }, 60000);
}

// Example 8: Batch Processing Multiple Instances
async function batchProcessingExample() {
    console.log('=== Batch Processing Example ===');
    
    const configs = [
        { autoClickDelay: 1000, checkInterval: 5000 },
        { autoClickDelay: 1500, checkInterval: 3000 },
        { autoClickDelay: 2000, checkInterval: 7000 }
    ];
    
    const bots = configs.map(config => new CursorAutomationBot(config));
    
    // Start all bots
    await Promise.all(bots.map(bot => bot.start()));
    
    console.log(`🚀 Started ${bots.length} automation bots`);
    
    // Stop all bots after 2 minutes
    setTimeout(async () => {
        await Promise.all(bots.map(bot => bot.stop()));
        console.log('🛑 All bots stopped');
    }, 120000);
}

// Example 9: Testing and Validation
async function testingExample() {
    console.log('=== Testing Example ===');
    
    const bot = new CursorAutomationBot({
        checkInterval: 1000,  // Check every second for testing
        enableLogging: true
    });
    
    // Test configuration
    console.log('Current config:', bot.getConfig());
    
    // Test status
    console.log('Initial status:', bot.getStatus());
    
    await bot.start();
    
    // Test status after start
    setTimeout(() => {
        console.log('Status after start:', bot.getStatus());
    }, 5000);
    
    // Test configuration update
    setTimeout(() => {
        bot.updateConfig({ autoClickDelay: 500 });
        console.log('Updated config:', bot.getConfig());
    }, 10000);
    
    // Stop after 30 seconds
    setTimeout(async () => {
        await bot.stop();
        console.log('Final status:', bot.getStatus());
    }, 30000);
}

// Example 10: Production Deployment
async function productionExample() {
    console.log('=== Production Deployment Example ===');
    
    // Load configuration from file
    const configPath = path.join(__dirname, '..', 'cursor-automation-config.json');
    const config = require(configPath);
    
    const bot = new CursorAutomationBot(config.cursorAutomation);
    
    // Production event handlers
    bot.on('started', () => {
        console.log('🚀 Production bot started');
        // Log to production logging system
    });
    
    bot.on('updateHandled', (data) => {
        if (data.success) {
            console.log('✅ Production update handled');
            // Log success to monitoring system
        } else {
            console.log('❌ Production update failed');
            // Alert monitoring system
        }
    });
    
    bot.on('error', (error) => {
        console.error('💥 Production error:', error);
        // Send alert to operations team
    });
    
    // Graceful shutdown handling
    process.on('SIGINT', async () => {
        console.log('🛑 Graceful shutdown initiated...');
        await bot.stop();
        process.exit(0);
    });
    
    process.on('SIGTERM', async () => {
        console.log('🛑 Graceful shutdown initiated...');
        await bot.stop();
        process.exit(0);
    });
    
    await bot.start();
    
    // Keep running indefinitely
    setInterval(() => {}, 1000);
}

// Run examples based on command line argument
if (require.main === module) {
    const example = process.argv[2] || 'basic';
    
    const examples = {
        basic: basicExample,
        custom: customConfigExample,
        integration: integrationExample,
        platform: platformSpecificExample,
        error: errorHandlingExample,
        monitoring: monitoringExample,
        dynamic: dynamicConfigExample,
        batch: batchProcessingExample,
        testing: testingExample,
        production: productionExample
    };
    
    if (examples[example]) {
        console.log(`Running example: ${example}`);
        examples[example]().catch(console.error);
    } else {
        console.log('Available examples:');
        Object.keys(examples).forEach(name => {
            console.log(`  - ${name}`);
        });
        console.log('\nUsage: node cursor-automation-examples.js <example-name>');
    }
}

module.exports = {
    basicExample,
    customConfigExample,
    integrationExample,
    platformSpecificExample,
    errorHandlingExample,
    monitoringExample,
    dynamicConfigExample,
    batchProcessingExample,
    testingExample,
    productionExample
};
