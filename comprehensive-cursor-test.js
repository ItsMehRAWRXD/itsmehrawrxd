#!/usr/bin/env node

/**
 * Comprehensive Cursor Test
 * This script tests the automation with different dialog scenarios
 */

const CursorAutomationBot = require('./src/engines/cursor-automation-bot');

async function comprehensiveTest() {
    console.log('🧪 Comprehensive Cursor Automation Test\n');
    console.log('This test will help you verify the automation handles different dialog types.\n');
    
    const bot = new CursorAutomationBot({
        autoClickDelay: 1500,  // 1.5 second delay
        maxRetries: 3,         // Try up to 3 times
        retryDelay: 2000,      // 2 seconds between retries
        checkInterval: 2000,   // Check every 2 seconds
        enableLogging: true,
        enableNotifications: false,
        
        uiSettings: {
            buttonText: "Keep all",
            dialogTitle: "Review file",
            timeout: 15000,
            confidence: 0.8
        }
    });
    
    // Set up comprehensive event handlers
    bot.on('started', () => {
        console.log('✅ Bot started successfully');
        console.log('📊 Configuration:');
        console.log(`   - Auto click delay: ${bot.config.autoClickDelay}ms`);
        console.log(`   - Max retries: ${bot.config.maxRetries}`);
        console.log(`   - Check interval: ${bot.config.checkInterval}ms`);
        console.log(`   - Button text: "${bot.config.uiSettings.buttonText}"`);
    });
    
    bot.on('updateHandled', (data) => {
        if (data.success) {
            console.log(`\n✅ SUCCESS: Update handled successfully!`);
            console.log(`   - Method used: ${data.method}`);
            console.log(`   - Retries needed: ${data.retries}`);
            console.log('🎉 The automation is working correctly!');
        } else {
            console.log(`\n❌ FAILED: Update handling failed`);
            console.log(`   - Error: ${data.error}`);
            console.log(`   - Retries attempted: ${data.retries}`);
        }
    });
    
    bot.on('error', (error) => {
        console.error('\n💥 Bot error:', error);
    });
    
    bot.on('configUpdated', (config) => {
        console.log('⚙️  Configuration updated');
    });
    
    try {
        console.log('🚀 Starting comprehensive test...');
        await bot.start();
        
        console.log('\n📋 TESTING SCENARIOS:');
        console.log('The bot will now monitor for these dialog types:');
        console.log('   • "Review file" dialogs');
        console.log('   • "Keep all" buttons');
        console.log('   • "Undo all" buttons');
        console.log('   • "Accept" buttons');
        console.log('   • "OK" buttons');
        console.log('   • Various file change notifications');
        
        console.log('\n🎯 HOW TO TEST:');
        console.log('1. Make sure Cursor IDE is open and visible');
        console.log('2. Edit any file in Cursor (add/remove text)');
        console.log('3. Save the file or trigger a change');
        console.log('4. Wait for any dialog to appear');
        console.log('5. Watch this console for automation response');
        
        console.log('\n💡 EXPECTED BEHAVIOR:');
        console.log('   • Bot should detect the dialog');
        console.log('   • Try multiple methods to handle it');
        console.log('   • Report success or failure');
        console.log('   • Handle different button texts automatically');
        
        console.log('\n⏰ Bot will run for 3 minutes, then stop automatically');
        console.log('💡 If you see "SUCCESS" messages, the automation is working!');
        console.log('❌ If you see "FAILED" messages, check the error details\n');
        
        // Show status every 30 seconds
        const statusInterval = setInterval(() => {
            const status = bot.getStatus();
            console.log(`📊 Status: Running for ${Math.floor((Date.now() - status.uptime) / 1000)}s, Platform: ${status.platform}`);
        }, 30000);
        
        // Run for 3 minutes
        setTimeout(async () => {
            clearInterval(statusInterval);
            console.log('\n🛑 Stopping bot after test period...');
            await bot.stop();
            console.log('✅ Comprehensive test completed');
            process.exit(0);
        }, 180000);
        
    } catch (error) {
        console.error('❌ Failed to start bot:', error.message);
        process.exit(1);
    }
}

// Run the comprehensive test
comprehensiveTest().catch(console.error);
