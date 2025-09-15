/**
 * Load Jotti scanner and scan encrypted files
 */

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

async function scanEncryptedFiles() {
    console.log('=== SCANNING ENCRYPTED FILES ===\n');
    
    try {
        // Load the Jotti scanner engine
        console.log('Loading Jotti scanner engine...');
        await execAsync('node rawrz-standalone.js engines load jotti-scanner');
        console.log('✓ Jotti scanner loaded\n');
        
        // Find all encrypted files
        const { stdout } = await execAsync('dir encrypted_* /b');
        const files = stdout.trim().split('\n').filter(f => f.trim());
        
        console.log(`Found ${files.length} encrypted files to scan:`);
        files.forEach(file => console.log(`  - ${file}`));
        console.log('');
        
        // Scan each file
        for (const file of files) {
            if (file.trim()) {
                console.log(`[SCAN] Scanning ${file}...`);
                try {
                    const { stdout: scanResult } = await execAsync(`node rawrz-standalone.js use jotti-scanner scan "${file}"`);
                    console.log(`[SCAN] ✓ ${file}:`);
                    console.log(scanResult);
                    console.log('---');
                } catch (error) {
                    console.log(`[SCAN] ✗ Error scanning ${file}: ${error.message}`);
                }
            }
        }
        
    } catch (error) {
        console.error('Error:', error.message);
    }
}

scanEncryptedFiles();
