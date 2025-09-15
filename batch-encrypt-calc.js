/**
 * Batch encrypt calc.exe with all available encryption methods
 */

const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

async function batchEncryptCalc() {
    console.log('Starting batch encryption of calc.exe with all methods...\n');
    
    const encryptionMethods = [
        'aes256',
        'aes192', 
        'aes128',
        'blowfish',
        'rc4',
        'cam',
        'rsa2048',
        'rsa4096'
    ];
    
    const encryptedFiles = [];
    
    for (const method of encryptionMethods) {
        try {
            console.log(`[${method.toUpperCase()}] Encrypting calc.exe...`);
            
            const command = `node rawrz-standalone.js encrypt ${method} "C:\\Windows\\System32\\calc.exe" .enc`;
            const { stdout, stderr } = await execAsync(command);
            
            // Extract filename from output
            const filenameMatch = stdout.match(/encrypted_calc_.*\.enc/);
            if (filenameMatch) {
                const filename = filenameMatch[0];
                encryptedFiles.push({ method, filename });
                console.log(`[${method.toUpperCase()}] ✓ Success: ${filename}`);
            } else {
                console.log(`[${method.toUpperCase()}] ✗ Failed to extract filename`);
            }
            
        } catch (error) {
            console.log(`[${method.toUpperCase()}] ✗ Error: ${error.message}`);
        }
        
        console.log(''); // Empty line for readability
    }
    
    console.log('=== BATCH ENCRYPTION COMPLETE ===');
    console.log(`Successfully encrypted ${encryptedFiles.length} files:`);
    encryptedFiles.forEach(({ method, filename }) => {
        console.log(`  - ${method}: ${filename}`);
    });
    
    return encryptedFiles;
}

// Run the batch encryption
batchEncryptCalc().catch(console.error);
