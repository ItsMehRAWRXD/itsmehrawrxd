#!/usr/bin/env node

const RawrZ = require('./rawrz-standalone');
const fs = require('fs');
const path = require('path');

async function testAllEnginesAndExtensions() {
    console.log('Testing All Encryption Engines with Different File Extensions');
    console.log('=' .repeat(60));
    
    const cli = RawrZ.getInstance();
    const targetFile = 'C:/Windows/System32/calc.exe';
    
    // Test different extensions
    const extensions = [
        '.enc', '.exe', '.dll', '.sys', '.scr', '.com', 
        '.bat', '.cmd', '.ps1', '.vbs', '.js', '.bin', 
        '.dat', '.txt', '.encrypted', '.secure', '.locked'
    ];
    
    // Test different algorithms
    const algorithms = ['aes256', 'aes128', 'blowfish', 'cam', 'chacha20', 'serpent', 'twofish'];
    
    // All available engines
    const engines = [
        'advanced-crypto',
        'dual-crypto-engine', 
        'burner-encryption-engine',
        'camellia-assembly',
        'native-compiler',
        'ev-cert-encryptor',
        'polymorphic-engine',
        'compression-engine'
    ];
    
    const results = {
        successful: [],
        failed: [],
        files: [],
        engines: {}
    };
    
    console.log('Target File: ' + targetFile);
    console.log('Testing ' + extensions.length + ' extensions with ' + algorithms.length + ' algorithms across ' + engines.length + ' engines\n');
    
    // Test each extension with each algorithm
    for (const extension of extensions) {
        console.log('Testing Extension: ' + extension);
        console.log('-'.repeat(40));
        
        for (const algorithm of algorithms) {
            try {
                console.log('  Testing ' + algorithm.toUpperCase() + ' with ' + extension + '...');
                
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
                    console.log('    ' + algorithm + ' + ' + extension + ': FAILED - ' + (result?.error || 'Unknown error'));
                    results.failed.push({algorithm, extension, error: result?.error || 'Unknown error'});
                }
            } catch (error) {
                console.log('    ' + algorithm + ' + ' + extension + ': ERROR - ' + error.message);
                results.failed.push({algorithm, extension, error: error.message});
            }
            
            // Small delay between tests
            await new Promise(resolve => setTimeout(resolve, 500));
        }
    }
    
    // Test decryption of some files
    console.log('\n\nTesting Decryption');
    console.log('=' .repeat(30));
    
    if (results.files.length > 0) {
        console.log('\nTesting decryption of ' + Math.min(3, results.files.length) + ' files...');
        
        for (let i = 0; i < Math.min(3, results.files.length); i++) {
            const file = results.files[i];
            console.log('\nDecrypting: ' + file.filename);
            
            try {
                const decryptResult = await cli.processCommand(['decrypt', file.algorithm, file.filename, '.decrypted']);
                
                if (decryptResult && decryptResult.success !== false) {
                    console.log('   Decryption successful');
                    
                    // Check if decrypted file exists
                    const decryptedFile = decryptResult.output || decryptResult.filename;
                    if (decryptedFile && fs.existsSync(decryptedFile)) {
                        const stats = fs.statSync(decryptedFile);
                        console.log('  Decrypted file size: ' + stats.size + ' bytes');
                        
                        // Compare with original
                        const originalStats = fs.statSync(targetFile);
                        if (stats.size === originalStats.size) {
                            console.log('   File sizes match - decryption successful!');
                        } else {
                            console.log('  WARNING: File sizes differ - may be corrupted');
                        }
                    }
                } else {
                    console.log('   Decryption failed: ' + (decryptResult?.error || 'Unknown error'));
                }
            } catch (error) {
                console.log('   Decryption error: ' + error.message);
            }
        }
    }
    
    // Test Jotti scanning on encrypted files
    console.log('\n\nTesting Jotti Scanner on Encrypted Files');
    console.log('=' .repeat(45));
    
    if (results.files.length > 0) {
        console.log('\nScanning ' + Math.min(2, results.files.length) + ' encrypted files with Jotti...');
        
        for (let i = 0; i < Math.min(2, results.files.length); i++) {
            const file = results.files[i];
            console.log('\nJotti scan: ' + file.filename);
            
            try {
                const jottiResult = await cli.processCommand(['jotti', 'scan', file.filename]);
                
                if (jottiResult && jottiResult.success !== false) {
                    console.log('   Jotti scan successful');
                    console.log('  Scan results: ' + JSON.stringify(jottiResult, null, 2));
                } else {
                    console.log('   Jotti scan failed: ' + (jottiResult?.error || 'Unknown error'));
                }
            } catch (error) {
                console.log('   Jotti scan error: ' + error.message);
            }
        }
    }
    
    // Summary
    console.log('\n\nEXTENSION TEST SUMMARY');
    console.log('=' .repeat(50));
    console.log(' Successful combinations: ' + results.successful.length);
    console.log(' Failed combinations: ' + results.failed.length);
    console.log('Files created: ' + results.files.length);
    
    console.log('\n Working combinations:');
    results.successful.forEach(success => {
        console.log('   - ' + success.algorithm + ' + ' + success.extension);
    });
    
    if (results.failed.length > 0) {
        console.log('\n Failed combinations:');
        results.failed.forEach(fail => {
            console.log('   - ' + fail.algorithm + ' + ' + fail.extension + ': ' + fail.error);
        });
    }
    
    console.log('\nCreated files:');
    results.files.forEach(file => {
        console.log('   - ' + file.algorithm + ' + ' + file.extension + ': ' + file.filename + ' (' + file.size + ' bytes)');
    });
    
    console.log('\nExtension testing completed! Check the uploads directory for all files.');
}

// Run the extension test
testAllEnginesAndExtensions().catch(console.error);
