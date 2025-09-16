/**
 * Simple calc.exe encryption and Jotti scan with real names
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

async function simpleEncryptCalc() {
    console.log('=== SIMPLE CALC.EXE ENCRYPTION AND JOTTI SCAN ===\n');
    
    try {
        // Load Jotti scanner
        console.log('Loading Jotti scanner...');
        const jottiScanner = require('./src/engines/jotti-scanner');
        await jottiScanner.initialize();
        console.log('[OK] Jotti scanner loaded\n');
        
        // Read calc.exe
        console.log('Reading calc.exe...');
        const calcPath = path.join(__dirname, 'calc.exe');
        const calcData = await fs.readFile(calcPath);
        console.log(`[OK] Read ${calcData.length} bytes from calc.exe\n`);
        
        // Real-looking names
        const realNames = [
            'WindowsUpdateService.exe',
            'SystemMaintenance.exe', 
            'PerformanceOptimizer.exe',
            'MemoryManager.exe',
            'ErrorHandler.exe'
        ];
        
        const algorithms = [
            'aes-256-gcm',
            'aes-256-cbc', 
            'aes-128-gcm',
            'aes-128-cbc',
            'chacha20-poly1305'
        ];
        
        const results = [];
        
        for (let i = 0; i < 5; i++) {
            const algorithm = algorithms[i];
            const realName = realNames[i];
            
            console.log(`\n--- Encrypting with ${algorithm} as ${realName} ---`);
            
            try {
                // Simple encryption
                let encrypted;
                let key, iv, authTag;
                
                if (algorithm.includes('gcm')) {
                    key = crypto.randomBytes(32);
                    iv = crypto.randomBytes(12);
                    const cipher = crypto.createCipheriv(algorithm, key, iv);
                    encrypted = cipher.update(calcData);
                    encrypted = Buffer.concat([encrypted, cipher.final()]);
                    authTag = cipher.getAuthTag();
                } else if (algorithm.includes('cbc')) {
                    key = crypto.randomBytes(32);
                    iv = crypto.randomBytes(16);
                    const cipher = crypto.createCipheriv(algorithm, key, iv);
                    encrypted = cipher.update(calcData);
                    encrypted = Buffer.concat([encrypted, cipher.final()]);
                } else if (algorithm === 'chacha20-poly1305') {
                    key = crypto.randomBytes(32);
                    iv = crypto.randomBytes(12);
                    const cipher = crypto.createCipheriv(algorithm, key, iv);
                    encrypted = cipher.update(calcData);
                    encrypted = Buffer.concat([encrypted, cipher.final()]);
                    authTag = cipher.getAuthTag();
                }
                
                // Save encrypted file with real name
                const encryptedPath = path.join(__dirname, 'uploads', realName);
                await fs.writeFile(encryptedPath, encrypted);
                console.log(`[OK] Saved encrypted file: ${realName} (${encrypted.length} bytes)`);
                
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
        
        if (results.length > 0) {
            // Best results
            const bestFUD = results.reduce((best, current) => 
                current.fudScore > best.fudScore ? current : best
            );
            
            console.log(`\n[INFO] Best FUD Score: ${bestFUD.fudScore}% (${bestFUD.filename} with ${bestFUD.algorithm})`);
            console.log(`[INFO] Lowest Detection: ${Math.min(...results.map(r => r.detectionRate))}%`);
        }
        
        console.log('\n[OK] Encryption and scanning completed!');
        
    } catch (error) {
        console.error('[ERROR] Failed:', error.message);
        console.error(error.stack);
    }
}

simpleEncryptCalc();
