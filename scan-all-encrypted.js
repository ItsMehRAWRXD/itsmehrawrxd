/**
 * Scan all encrypted files with Jotti scanner
 */

const { exec } = require('child_process');
const { promisify } = require('util');
const fs = require('fs').promises;
const path = require('path');

const execAsync = promisify(exec);

async function scanAllEncryptedFiles() {
    console.log('=== COMPREHENSIVE ENCRYPTED FILE SCANNING ===\n');
    
    try {
        // Load the Jotti scanner engine
        console.log('Loading Jotti scanner engine...');
        await execAsync('node rawrz-standalone.js engines load jotti-scanner');
        console.log('✓ Jotti scanner loaded\n');
        
        // Get all encrypted files from uploads directory
        const uploadsDir = path.join(__dirname, 'uploads');
        const files = await fs.readdir(uploadsDir);
        const encryptedFiles = files.filter(f => f.startsWith('encrypted_'));
        
        console.log(`Found ${encryptedFiles.length} encrypted files to scan:`);
        encryptedFiles.forEach((file, index) => {
            console.log(`  ${index + 1}. ${file}`);
        });
        console.log('');
        
        const scanResults = [];
        
        // Scan each file
        for (let i = 0; i < encryptedFiles.length; i++) {
            const file = encryptedFiles[i];
            console.log(`[${i + 1}/${encryptedFiles.length}] Scanning ${file}...`);
            
            try {
                const { stdout: scanResult } = await execAsync(`node rawrz-standalone.js use jotti-scanner scan "uploads/${file}"`);
                
                // Clean up the scan result
                const cleanResult = scanResult
                    .replace(/\[INFO\].*?\n/g, '')
                    .replace(/\[OK\].*?\n/g, '')
                    .replace(/\[DEBUG\].*?\n/g, '')
                    .trim();
                
                scanResults.push({
                    filename: file,
                    result: cleanResult,
                    success: true
                });
                
                console.log(`[${i + 1}/${encryptedFiles.length}] ✓ ${file}:`);
                console.log(cleanResult);
                console.log('---');
                
            } catch (error) {
                console.log(`[${i + 1}/${encryptedFiles.length}] ✗ Error scanning ${file}: ${error.message}`);
                scanResults.push({
                    filename: file,
                    result: `ERROR: ${error.message}`,
                    success: false
                });
            }
            
            console.log(''); // Empty line for readability
        }
        
        // Summary
        console.log('=== SCAN RESULTS SUMMARY ===\n');
        const successfulScans = scanResults.filter(r => r.success).length;
        const failedScans = scanResults.filter(r => !r.success).length;
        
        console.log(`Total files scanned: ${scanResults.length}`);
        console.log(`Successful scans: ${successfulScans}`);
        console.log(`Failed scans: ${failedScans}`);
        console.log('');
        
        // Show results by file type
        const resultsByExtension = {};
        scanResults.forEach(result => {
            const ext = path.extname(result.filename);
            if (!resultsByExtension[ext]) {
                resultsByExtension[ext] = [];
            }
            resultsByExtension[ext].push(result);
        });
        
        console.log('Results by file extension:');
        Object.entries(resultsByExtension).forEach(([ext, results]) => {
            console.log(`\n${ext.toUpperCase()} files (${results.length}):`);
            results.forEach(result => {
                const status = result.success ? '✓' : '✗';
                console.log(`  ${status} ${result.filename}`);
                if (result.success && result.result) {
                    console.log(`    ${result.result.substring(0, 100)}...`);
                }
            });
        });
        
        return scanResults;
        
    } catch (error) {
        console.error('Error:', error.message);
        return [];
    }
}

scanAllEncryptedFiles();
