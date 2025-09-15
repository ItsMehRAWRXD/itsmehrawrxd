#!/usr/bin/env node

const RawrZ = require('./rawrz-standalone');
const fs = require('fs');
const path = require('path');

async function testBinaryEncryption() {
    console.log('Testing Binary File Encryption with All Engines');
    console.log('=' .repeat(50));
    
    const cli = RawrZ.getInstance();
    const targetFile = 'C:/Windows/System32/calc.exe';
    
    // Test different algorithms
    const algorithms = ['aes256', 'aes128', 'blowfish'];
    
    // Test different extensions
    const extensions = ['.enc', '.exe', '.dll', '.bin'];
    
    console.log('Target File: ' + targetFile);
    console.log('Testing ' + algorithms.length + ' algorithms with ' + extensions.length + ' extensions');
    
    const results = {
        successful: [],
        failed: []
    };
    
    // Test each algorithm with each extension
    for (const algorithm of algorithms) {
        console.log('\nTesting Algorithm: ' + algorithm.toUpperCase());
        console.log('-'.repeat(30));
        
        for (const extension of extensions) {
            try {
                console.log('  Testing ' + algorithm + ' with ' + extension + '...');
                
                const result = await cli.processCommand(['encrypt', algorithm, targetFile, extension]);
                
                if (result && result.success !== false) {
                    console.log('    SUCCESS: ' + algorithm + ' + ' + extension);
                    results.successful.push({algorithm, extension, result});
                    
                    // Check if file was created
                    const outputFile = result.output || result.filename;
                    if (outputFile && fs.existsSync(outputFile)) {
                        const stats = fs.statSync(outputFile);
                        console.log('    File size: ' + stats.size + ' bytes');
                    }
                } else {
                    console.log('    FAILED: ' + algorithm + ' + ' + extension + ' - ' + (result?.error || 'Unknown error'));
                    results.failed.push({algorithm, extension, error: result?.error || 'Unknown error'});
                }
            } catch (error) {
                console.log('    ERROR: ' + algorithm + ' + ' + extension + ' - ' + error.message);
                results.failed.push({algorithm, extension, error: error.message});
            }
            
            // Small delay between tests
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }
    
    // Test decryption
    console.log('\n\nTesting Decryption');
    console.log('=' .repeat(20));
    
    if (results.successful.length > 0) {
        console.log('Testing decryption of first successful file...');
        
        const firstSuccess = results.successful[0];
        console.log('Decrypting: ' + firstSuccess.algorithm + ' + ' + firstSuccess.extension);
        
        try {
            const outputFile = firstSuccess.result.output || firstSuccess.result.filename;
            const decryptResult = await cli.processCommand(['decrypt', firstSuccess.algorithm, outputFile, '.decrypted']);
            
            if (decryptResult && decryptResult.success !== false) {
                console.log('  Decryption successful');
                
                const decryptedFile = decryptResult.output || decryptResult.filename;
                if (decryptedFile && fs.existsSync(decryptedFile)) {
                    const stats = fs.statSync(decryptedFile);
                    console.log('  Decrypted file size: ' + stats.size + ' bytes');
                    
                    // Compare with original
                    const originalStats = fs.statSync(targetFile);
                    if (stats.size === originalStats.size) {
                        console.log('  File sizes match - decryption successful!');
                    } else {
                        console.log('  File sizes differ - may be corrupted');
                    }
                }
            } else {
                console.log('  Decryption failed: ' + (decryptResult?.error || 'Unknown error'));
            }
        } catch (error) {
            console.log('  Decryption error: ' + error.message);
        }
    }
    
    // Test Jotti scanning
    console.log('\n\nTesting Jotti Scanner');
    console.log('=' .repeat(25));
    
    if (results.successful.length > 0) {
        console.log('Testing Jotti scan on first successful file...');
        
        const firstSuccess = results.successful[0];
        const outputFile = firstSuccess.result.output || firstSuccess.result.filename;
        
        try {
            const jottiResult = await cli.processCommand(['jotti', 'scan', outputFile]);
            
            if (jottiResult && jottiResult.success !== false) {
                console.log('  Jotti scan successful');
                console.log('  Scan results: ' + JSON.stringify(jottiResult, null, 2));
            } else {
                console.log('  Jotti scan failed: ' + (jottiResult?.error || 'Unknown error'));
            }
        } catch (error) {
            console.log('  Jotti scan error: ' + error.message);
        }
    }
    
    // Summary
    console.log('\n\nTEST SUMMARY');
    console.log('=' .repeat(30));
    console.log('Successful combinations: ' + results.successful.length);
    console.log('Failed combinations: ' + results.failed.length);
    
    console.log('\nWorking combinations:');
    results.successful.forEach(success => {
        console.log('  - ' + success.algorithm + ' + ' + success.extension);
    });
    
    if (results.failed.length > 0) {
        console.log('\nFailed combinations:');
        results.failed.forEach(fail => {
            console.log('  - ' + fail.algorithm + ' + ' + fail.extension + ': ' + fail.error);
        });
    }
    
    console.log('\nBinary encryption testing completed!');
}

// Run the test
testBinaryEncryption().catch(console.error);
