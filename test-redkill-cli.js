// Test the redkill command directly without the full CLI
const cliAntiFreeze = require('./src/utils/cli-anti-freeze');

async function testRedKillPatterns() {
    console.log('Testing redkill patterns command...');
    
    try {
        const redKiller = require('./src/engines/red-killer');
        console.log('1. Red Killer engine loaded');
        
        const result = await cliAntiFreeze.withTimeout(
            () => {
                if (!redKiller || !redKiller.avPatterns) {
                    throw new Error('Red Killer engine not properly initialized');
                }
                return { patterns: redKiller.avPatterns };
            },
            5000,
            'redkill-patterns'
        );
        
        console.log('2. Patterns retrieved successfully');
        console.log('3. Available AV patterns:', Object.keys(result.patterns).join(', '));
        console.log('Test completed successfully!');
        
    } catch (error) {
        console.error('Test failed:', error.message);
    }
}

testRedKillPatterns();
