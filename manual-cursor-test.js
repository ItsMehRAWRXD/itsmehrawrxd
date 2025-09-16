#!/usr/bin/env node

/**
 * Manual Cursor Test
 * This script will help you test the automation manually
 */

const CursorAutomationBot = require('./src/engines/cursor-automation-bot');

async function manualTest() {
    console.log('🧪 Manual Cursor Automation Test\n');
    console.log('This test will help you verify the automation is working.\n');
    
    const bot = new CursorAutomationBot({
        autoClickDelay: 2000,  // 2 second delay
        maxRetries: 1,
        checkInterval: 1000,   // Check every second
        enableLogging: true,
        enableNotifications: false
    });
    
    // Set up event handlers
    bot.on('started', () => {
        console.log('✅ Bot started successfully');
    });
    
    bot.on('updateHandled', (data) => {
        if (data.success) {
            console.log(`✅ SUCCESS: Update handled using method: ${data.method}`);
            console.log('🎉 The automation is working correctly!');
        } else {
            console.log(`❌ FAILED: ${data.error}`);
        }
    });
    
    bot.on('error', (error) => {
        console.error('💥 Bot error:', error);
    });
    
    try {
        console.log('🚀 Starting bot...');
        await bot.start();
        
        console.log('\n📋 INSTRUCTIONS FOR TESTING:');
        console.log('1. Make sure Cursor IDE is open and visible');
        console.log('2. Make a change to any file in Cursor');
        console.log('3. Wait for the "Review file" dialog to appear');
        console.log('4. Watch this console for automation response');
        console.log('\n⏰ Bot will run for 2 minutes, then stop automatically');
        console.log('💡 If you see "SUCCESS" message, the automation is working!');
        console.log('❌ If you see "FAILED" message, there may be an issue\n');
        
        // Run for 2 minutes
        setTimeout(async () => {
            console.log('\n🛑 Stopping bot after test period...');
            await bot.stop();
            console.log('✅ Test completed');
            process.exit(0);
        }, 120000);
        
    } catch (error) {
        console.error('❌ Failed to start bot:', error.message);
        process.exit(1);
    }
}

// Run the test
manualTest().catch(console.error);
