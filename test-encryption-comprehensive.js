#!/usr/bin/env node

const RawrZ = require('./rawrz-standalone');
const path = require('path');

async function testAllEncryptionMethods() {
    console.log('[SECURE] Testing All Encryption Engines and Methods on calc.exe');
    console.log('=' .repeat(60));
    
    const cli = RawrZ.getInstance();
    const targetFile = 'C:/Windows/System32/calc.exe';
    
    // Available encryption algorithms
    const algorithms = [
        'aes256', 'aes192', 'aes128', 
        'blowfish', 'rsa2048', 'rsa4096', 
        'cam', 'chacha20', 'serpent', 'twofish'
    ];
    
    // Available engines to test
    const engines = [
        'advanced-crypto',
        'dual-crypto-engine', 
        'burner-encryption-engine',
        'camellia-assembly',
        'native-compiler'
    ];
    
    const results = {
        successful: [],
        failed: [],
        engines: {}
    };
    
    console.log(`\n[INFO] Target File: ${targetFile}`);
    console.log(`[TOOL] Testing ${algorithms.length} algorithms across ${engines.length} engines\n`);
    
    // Test each algorithm with default engine
    for (const algorithm of algorithms) {
        console.log(`\n[TEST] Testing Algorithm: ${algorithm.toUpperCase()}`);
        console.log('-'.repeat(40));
        
        try {
            const result = await cli.processCommand(['encrypt', algorithm, targetFile, '.enc']);
            
            if (result && result.success !== false) {
                console.log(`[OK] ${algorithm}: SUCCESS`);
                results.successful.push(algorithm);
            } else {
                console.log(`[ERROR] ${algorithm}: FAILED - ${result?.error || 'Unknown error'}`);
                results.failed.push({algorithm, error: result?.error || 'Unknown error'});
            }
        } catch (error) {
            console.log(`[ERROR] ${algorithm}: ERROR - ${error.message}`);
            results.failed.push({algorithm, error: error.message});
        }
        
        // Small delay between tests
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    // Test specific engines
    console.log(`\n\n[TOOL] Testing Specific Engines`);
    console.log('=' .repeat(40));
    
    for (const engine of engines) {
        console.log(`\n[TOOL] Testing Engine: ${engine}`);
        console.log('-'.repeat(30));
        
        try {
            // Load the engine
            const loadResult = await cli.loadEngine(engine);
            if (loadResult.success) {
                console.log(`[OK] Engine ${engine} loaded successfully`);
                results.engines[engine] = 'loaded';
                
                // Test encryption with this engine
                const testResult = await cli.processCommand(['encrypt', 'aes256', targetFile, '.enc']);
                if (testResult && testResult.success !== false) {
                    console.log(`[OK] Encryption with ${engine}: SUCCESS`);
                    results.engines[engine] = 'working';
                } else {
                    console.log(`[ERROR] Encryption with ${engine}: FAILED`);
                    results.engines[engine] = 'failed';
                }
            } else {
                console.log(`[ERROR] Failed to load engine ${engine}: ${loadResult.error}`);
                results.engines[engine] = 'load_failed';
            }
        } catch (error) {
            console.log(`[ERROR] Engine ${engine} error: ${error.message}`);
            results.engines[engine] = 'error';
        }
        
        await new Promise(resolve => setTimeout(resolve, 2000));
    }
    
    // Test Jotti Scanner
    console.log(`\n\n[SEARCH] Testing Jotti Scanner`);
    console.log('=' .repeat(30));
    
    try {
        const jottiResult = await cli.processCommand(['jotti', 'scan', targetFile]);
        if (jottiResult && jottiResult.success !== false) {
            console.log(`[OK] Jotti Scanner: SUCCESS`);
            console.log(`[CHART] Scan Results: ${JSON.stringify(jottiResult, null, 2)}`);
        } else {
            console.log(`[ERROR] Jotti Scanner: FAILED - ${jottiResult?.error || 'Unknown error'}`);
        }
    } catch (error) {
        console.log(`[ERROR] Jotti Scanner Error: ${error.message}`);
    }
    
    // Summary
    console.log(`\n\n[CHART] COMPREHENSIVE TEST SUMMARY`);
    console.log('=' .repeat(50));
    console.log(`[OK] Successful Algorithms: ${results.successful.length}/${algorithms.length}`);
    console.log(`[ERROR] Failed Algorithms: ${results.failed.length}/${algorithms.length}`);
    console.log(`[TOOL] Engines Tested: ${Object.keys(results.engines).length}`);
    
    console.log(`\n[OK] Working Algorithms:`);
    results.successful.forEach(alg => console.log(`   - ${alg}`));
    
    if (results.failed.length > 0) {
        console.log(`\n[ERROR] Failed Algorithms:`);
        results.failed.forEach(fail => console.log(`   - ${fail.algorithm}: ${fail.error}`));
    }
    
    console.log(`\n[TOOL] Engine Status:`);
    Object.entries(results.engines).forEach(([engine, status]) => {
        const statusIcon = status === 'working' ? '[OK]' : status === 'loaded' ? '[WARN]' : '[ERROR]';
        console.log(`   ${statusIcon} ${engine}: ${status}`);
    });
    
    console.log(`\n[TARGET] Test completed! Check the uploads directory for encrypted files.`);
}

// Run the comprehensive test
testAllEncryptionMethods().catch(console.error);
