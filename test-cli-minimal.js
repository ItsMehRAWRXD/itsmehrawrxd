// Minimal CLI test to isolate the freezing issue
console.log('Starting minimal CLI test...');

try {
    // Test 1: Basic require
    console.log('1. Testing basic require...');
    const RawrZStandalone = require('./rawrz-standalone.js');
    console.log('[INFO] RawrZStandalone loaded');
    
    // Test 2: Create instance
    console.log('2. Testing instance creation...');
    const cli = new RawrZStandalone();
    console.log('[INFO] CLI instance created');
    
    // Test 3: Test redkill patterns directly
    console.log('3. Testing redkill patterns command...');
    const result = await cli.processCommand('redkill', ['patterns']);
    console.log('[INFO] Redkill patterns command completed');
    console.log('Result:', result);
    
} catch (error) {
    console.error('Test failed:', error.message);
    console.error('Stack:', error.stack);
}
