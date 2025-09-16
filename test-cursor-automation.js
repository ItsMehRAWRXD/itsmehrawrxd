#!/usr/bin/env node

/**
 * Test Script for Cursor Automation Bot
 * 
 * This script tests the basic functionality of the Cursor Automation Bot
 * without actually running the full automation (since we can't simulate
 * the Cursor IDE update dialog in a test environment).
 */

const CursorAutomationBot = require('./src/engines/cursor-automation-bot');
const fs = require('fs');
const path = require('path');

class CursorAutomationTester {
    constructor() {
        this.testResults = [];
        this.bot = null;
    }
    
    async runTests() {
        console.log('🧪 Starting Cursor Automation Bot Tests...\n');
        
        try {
            await this.testInitialization();
            await this.testConfiguration();
            await this.testPlatformDetection();
            await this.testEventHandling();
            await this.testStatusMethods();
            await this.testErrorHandling();
            
            this.printResults();
            
        } catch (error) {
            console.error('❌ Test suite failed:', error.message);
            process.exit(1);
        }
    }
    
    async testInitialization() {
        console.log('🔧 Testing Bot Initialization...');
        
        try {
            // Test default initialization
            this.bot = new CursorAutomationBot();
            this.assert(this.bot !== null, 'Bot should initialize');
            this.assert(this.bot.config !== null, 'Config should be set');
            this.assert(this.bot.isRunning === false, 'Bot should not be running initially');
            
            // Test custom configuration
            const customConfig = {
                autoClickDelay: 2000,
                maxRetries: 5,
                enableLogging: false
            };
            
            const customBot = new CursorAutomationBot(customConfig);
            this.assert(customBot.config.autoClickDelay === 2000, 'Custom config should be applied');
            this.assert(customBot.config.maxRetries === 5, 'Custom maxRetries should be applied');
            this.assert(customBot.config.enableLogging === false, 'Custom enableLogging should be applied');
            
            this.addResult('Initialization', true, 'All initialization tests passed');
            
        } catch (error) {
            this.addResult('Initialization', false, error.message);
        }
    }
    
    async testConfiguration() {
        console.log('⚙️  Testing Configuration Management...');
        
        try {
            // Test getConfig
            const config = this.bot.getConfig();
            this.assert(typeof config === 'object', 'getConfig should return object');
            this.assert(config.autoClickDelay !== undefined, 'Config should have autoClickDelay');
            this.assert(config.maxRetries !== undefined, 'Config should have maxRetries');
            
            // Test updateConfig
            const newConfig = { autoClickDelay: 3000, testProperty: 'test' };
            this.bot.updateConfig(newConfig);
            
            const updatedConfig = this.bot.getConfig();
            this.assert(updatedConfig.autoClickDelay === 3000, 'updateConfig should update values');
            this.assert(updatedConfig.testProperty === 'test', 'updateConfig should add new properties');
            
            this.addResult('Configuration', true, 'All configuration tests passed');
            
        } catch (error) {
            this.addResult('Configuration', false, error.message);
        }
    }
    
    async testPlatformDetection() {
        console.log('🖥️  Testing Platform Detection...');
        
        try {
            const os = require('os');
            const platform = os.platform();
            
            this.assert(this.bot.config.platform === platform, 'Platform should be detected correctly');
            this.assert(this.bot.automationEngine !== null, 'Automation engine should be initialized');
            this.assert(this.bot.automationEngine.type !== undefined, 'Automation engine should have type');
            
            // Test platform-specific paths
            const paths = this.bot.config.cursorPaths[platform];
            this.assert(Array.isArray(paths), 'Platform should have cursor paths');
            this.assert(paths.length > 0, 'Platform should have at least one cursor path');
            
            this.addResult('Platform Detection', true, `Platform ${platform} detected correctly`);
            
        } catch (error) {
            this.addResult('Platform Detection', false, error.message);
        }
    }
    
    async testEventHandling() {
        console.log('📡 Testing Event Handling...');
        
        try {
            let eventReceived = false;
            let eventData = null;
            
            // Test event emission
            this.bot.on('testEvent', (data) => {
                eventReceived = true;
                eventData = data;
            });
            
            this.bot.emit('testEvent', { test: 'data' });
            
            // Give event loop a chance to process
            await new Promise(resolve => setTimeout(resolve, 10));
            
            this.assert(eventReceived === true, 'Event should be received');
            this.assert(eventData !== null, 'Event data should be received');
            this.assert(eventData.test === 'data', 'Event data should be correct');
            
            this.addResult('Event Handling', true, 'All event handling tests passed');
            
        } catch (error) {
            this.addResult('Event Handling', false, error.message);
        }
    }
    
    async testStatusMethods() {
        console.log('📊 Testing Status Methods...');
        
        try {
            // Test getStatus
            const status = this.bot.getStatus();
            this.assert(typeof status === 'object', 'getStatus should return object');
            this.assert(typeof status.isRunning === 'boolean', 'Status should have isRunning');
            this.assert(typeof status.platform === 'string', 'Status should have platform');
            this.assert(typeof status.automationEngine === 'string', 'Status should have automationEngine');
            
            this.addResult('Status Methods', true, 'All status method tests passed');
            
        } catch (error) {
            this.addResult('Status Methods', false, error.message);
        }
    }
    
    async testErrorHandling() {
        console.log('🛡️  Testing Error Handling...');
        
        try {
            // Test invalid configuration
            const invalidConfig = {
                autoClickDelay: 'invalid',
                maxRetries: -1
            };
            
            // Should not throw error, but should handle gracefully
            const invalidBot = new CursorAutomationBot(invalidConfig);
            this.assert(invalidBot !== null, 'Bot should handle invalid config gracefully');
            
            // Test error event handling
            let errorReceived = false;
            this.bot.on('error', (error) => {
                errorReceived = true;
            });
            
            this.bot.emit('error', new Error('Test error'));
            
            // Give event loop a chance to process
            await new Promise(resolve => setTimeout(resolve, 10));
            
            this.assert(errorReceived === true, 'Error event should be received');
            
            this.addResult('Error Handling', true, 'All error handling tests passed');
            
        } catch (error) {
            this.addResult('Error Handling', false, error.message);
        }
    }
    
    assert(condition, message) {
        if (!condition) {
            throw new Error(`Assertion failed: ${message}`);
        }
    }
    
    addResult(testName, passed, message) {
        this.testResults.push({
            test: testName,
            passed: passed,
            message: message
        });
        
        const icon = passed ? '✅' : '❌';
        console.log(`${icon} ${testName}: ${message}\n`);
    }
    
    printResults() {
        console.log('📋 Test Results Summary:');
        console.log('========================\n');
        
        const passed = this.testResults.filter(r => r.passed).length;
        const total = this.testResults.length;
        
        this.testResults.forEach(result => {
            const icon = result.passed ? '✅' : '❌';
            console.log(`${icon} ${result.test}: ${result.message}`);
        });
        
        console.log(`\n📊 Overall: ${passed}/${total} tests passed`);
        
        if (passed === total) {
            console.log('🎉 All tests passed! The Cursor Automation Bot is ready to use.');
        } else {
            console.log('⚠️  Some tests failed. Please check the implementation.');
            process.exit(1);
        }
    }
}

// Run tests if this file is executed directly
if (require.main === module) {
    const tester = new CursorAutomationTester();
    tester.runTests().catch(console.error);
}

module.exports = CursorAutomationTester;
