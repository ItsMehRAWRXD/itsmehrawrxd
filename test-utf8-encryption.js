#!/usr/bin/env node

const RawrZ = require('./rawrz-standalone');

async function testUTF8Encryption() {
    console.log('Testing UTF-8 Encryption with All Engines');
    console.log('=' .repeat(50));
    
    const cli = RawrZ.getInstance();
    const testText = 'Hello World - RawrZ Security Platform Test';
    
    // Available engines to test
    const engines = [
        'advanced-crypto',
        'dual-crypto-engine', 
        'burner-encryption-engine',
        'camellia-assembly',
        'native-compiler',
        'ev-cert-encryptor',
        'red-killer',
        'red-shells'
    ];
    
    // Available algorithms
    const algorithms = ['aes256', 'aes128', 'blowfish', 'cam'];
    
    const results = {
        successful: [],
        failed: [],
        engines: {}
    };
    
    console.log('Test Text: ' + testText);
    console.log('Testing ' + algorithms.length + ' algorithms across ' + engines.length + ' engines\n');
    
    // Test each algorithm with default engine
    for (const algorithm of algorithms) {
        console.log('Testing Algorithm: ' + algorithm.toUpperCase());
        console.log('-'.repeat(30));
        
        try {
            const result = await cli.processCommand(['encrypt', algorithm, testText, '.txt']);
            
            if (result && result.success !== false) {
                console.log('SUCCESS: ' + algorithm);
                results.successful.push(algorithm);
            } else {
                console.log('FAILED: ' + algorithm + ' - ' + (result?.error || 'Unknown error'));
                results.failed.push({algorithm, error: result?.error || 'Unknown error'});
            }
        } catch (error) {
            console.log('ERROR: ' + algorithm + ' - ' + error.message);
            results.failed.push({algorithm, error: error.message});
        }
        
        // Small delay between tests
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    // Test specific engines
    console.log('\n\nTesting Specific Engines');
    console.log('=' .repeat(30));
    
    for (const engine of engines) {
        console.log('\nTesting Engine: ' + engine);
        console.log('-'.repeat(25));
        
        try {
            // Load the engine
            const loadResult = await cli.loadEngine(engine);
            if (loadResult.success) {
                console.log('Engine ' + engine + ' loaded successfully');
                results.engines[engine] = 'loaded';
                
                // Test encryption with this engine
                const testResult = await cli.processCommand(['encrypt', 'aes256', testText, '.txt']);
                if (testResult && testResult.success !== false) {
                    console.log('Encryption with ' + engine + ': SUCCESS');
                    results.engines[engine] = 'working';
                } else {
                    console.log('Encryption with ' + engine + ': FAILED');
                    results.engines[engine] = 'failed';
                }
            } else {
                console.log('Failed to load engine ' + engine + ': ' + loadResult.error);
                results.engines[engine] = 'load_failed';
            }
        } catch (error) {
            console.log('Engine ' + engine + ' error: ' + error.message);
            results.engines[engine] = 'error';
        }
        
        await new Promise(resolve => setTimeout(resolve, 2000));
    }
    
    // Test Jotti Scanner with text
    console.log('\n\nTesting Jotti Scanner');
    console.log('=' .repeat(25));
    
    try {
        const jottiResult = await cli.processCommand(['jotti', 'scan', testText]);
        if (jottiResult && jottiResult.success !== false) {
            console.log('Jotti Scanner: SUCCESS');
            console.log('Scan Results: ' + JSON.stringify(jottiResult, null, 2));
        } else {
            console.log('Jotti Scanner: FAILED - ' + (jottiResult?.error || 'Unknown error'));
        }
    } catch (error) {
        console.log('Jotti Scanner Error: ' + error.message);
    }
    
    // Summary
    console.log('\n\nTEST SUMMARY');
    console.log('=' .repeat(30));
    console.log('Successful Algorithms: ' + results.successful.length + '/' + algorithms.length);
    console.log('Failed Algorithms: ' + results.failed.length + '/' + algorithms.length);
    console.log('Engines Tested: ' + Object.keys(results.engines).length);
    
    console.log('\nWorking Algorithms:');
    results.successful.forEach(alg => console.log('   - ' + alg));
    
    if (results.failed.length > 0) {
        console.log('\nFailed Algorithms:');
        results.failed.forEach(fail => console.log('   - ' + fail.algorithm + ': ' + fail.error));
    }
    
    console.log('\nEngine Status:');
    Object.entries(results.engines).forEach(([engine, status]) => {
        const statusIcon = status === 'working' ? 'OK' : status === 'loaded' ? 'WARN' : 'FAIL';
        console.log('   ' + statusIcon + ' ' + engine + ': ' + status);
    });
    
    console.log('\nTest completed! Check the uploads directory for encrypted files.');
}

// Run the test
testUTF8Encryption().catch(console.error);
