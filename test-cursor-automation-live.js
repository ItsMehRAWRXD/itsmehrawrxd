#!/usr/bin/env node

/**
 * Live Test for Cursor Automation Bot
 * This script tests the actual automation functionality
 */

const CursorAutomationBot = require('./src/engines/cursor-automation-bot');

async function testLiveAutomation() {
    console.log('🧪 Testing Cursor Automation Bot Live...\n');
    
    const bot = new CursorAutomationBot({
        autoClickDelay: 1000,
        maxRetries: 2,
        checkInterval: 2000,  // Check every 2 seconds for testing
        enableLogging: true,
        enableNotifications: false
    });
    
    // Set up event handlers
    bot.on('started', () => {
        console.log('✅ Bot started successfully');
    });
    
    bot.on('updateHandled', (data) => {
        if (data.success) {
            console.log(`✅ Update handled successfully using method: ${data.method}`);
        } else {
            console.log(`❌ Update handling failed: ${data.error}`);
        }
    });
    
    bot.on('error', (error) => {
        console.error('💥 Bot error:', error);
    });
    
    try {
        console.log('🚀 Starting bot for live testing...');
        await bot.start();
        
        console.log('👀 Bot is now monitoring for Cursor updates...');
        console.log('💡 To test:');
        console.log('   1. Open Cursor IDE');
        console.log('   2. Make a change to a file');
        console.log('   3. Wait for "Review file" dialog to appear');
        console.log('   4. Watch for automation response');
        console.log('\n⏰ Bot will run for 60 seconds, then stop automatically');
        
        // Run for 60 seconds
        setTimeout(async () => {
            console.log('\n🛑 Stopping bot after test period...');
            await bot.stop();
            console.log('✅ Test completed');
            process.exit(0);
        }, 60000);
        
    } catch (error) {
        console.error('❌ Failed to start bot:', error.message);
        process.exit(1);
    }
}

// Run the test
testLiveAutomation().catch(console.error);
