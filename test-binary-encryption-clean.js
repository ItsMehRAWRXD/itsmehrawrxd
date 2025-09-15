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
    const algorithms = ['aes256', 'aes128', 'blowfish', 'cam'];
    
    // Test different extensions
    const extensions = ['.enc', '.exe', '.dll', '.bin', '.dat'];
    
    console.log('Target File: ' + targetFile);
    console.log('Testing ' + algorithms.length + ' algorithms with ' + extensions.length + ' extensions');
    
    const results = {
        successful: [],
        failed: [],
        files: []
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
                        results.files.push({
                            algorithm,
                            extension,
                            filename: outputFile,
                            size: stats.size
                        });
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
    
    if (results.files.length > 0) {
        console.log('Testing decryption of first successful file...');
        
        const firstFile = results.files[0];
        console.log('Decrypting: ' + firstFile.algorithm + ' + ' + firstFile.extension);
        
        try {
            const decryptResult = await cli.processCommand(['decrypt', firstFile.algorithm, firstFile.filename, '.decrypted']);
            
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
    
    if (results.files.length > 0) {
        console.log('Testing Jotti scan on first successful file...');
        
        const firstFile = results.files[0];
        
        try {
            const jottiResult = await cli.processCommand(['jotti', 'scan', firstFile.filename]);
            
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
    
    // Test all engines
    console.log('\n\nTesting All Engines');
    console.log('=' .repeat(25));
    
    const engines = [
        'advanced-crypto',
        'dual-crypto-engine', 
        'burner-encryption-engine',
        'camellia-assembly'
    ];
    
    for (const engine of engines) {
        console.log('\nTesting Engine: ' + engine);
        
        try {
            // Load the engine
            const loadResult = await cli.loadEngine(engine);
            if (loadResult.success) {
                console.log('  Engine loaded successfully');
                
                // Test encryption with this engine
                const testResult = await cli.processCommand(['encrypt', 'aes256', targetFile, '.test']);
                if (testResult && testResult.success !== false) {
                    console.log('  Encryption with ' + engine + ': SUCCESS');
                } else {
                    console.log('  Encryption with ' + engine + ': FAILED');
                }
            } else {
                console.log('  Failed to load engine: ' + loadResult.error);
            }
        } catch (error) {
            console.log('  Engine error: ' + error.message);
        }
        
        await new Promise(resolve => setTimeout(resolve, 2000));
    }
    
    // Summary
    console.log('\n\nTEST SUMMARY');
    console.log('=' .repeat(30));
    console.log('Successful combinations: ' + results.successful.length);
    console.log('Failed combinations: ' + results.failed.length);
    console.log('Files created: ' + results.files.length);
    
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
    
    console.log('\nCreated files:');
    results.files.forEach(file => {
        console.log('  - ' + file.algorithm + ' + ' + file.extension + ': ' + file.filename + ' (' + file.size + ' bytes)');
    });
    
    console.log('\nBinary encryption testing completed!');
}

// Run the test
testBinaryEncryption().catch(console.error);
