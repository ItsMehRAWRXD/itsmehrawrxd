/**
 * Batch encrypt calc.exe with all methods, convert to random extensions, and Jotti scan them
 */

const fs = require('fs').promises;
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');
const crypto = require('crypto');

const execAsync = promisify(exec);

// Random extensions to use
const randomExtensions = [
    '.exe', '.dll', '.sys', '.scr', '.com', '.bat', '.cmd', '.ps1', 
    '.vbs', '.js', '.jar', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.ppt', '.pptx', '.zip', '.rar', '.7z', '.tar', '.gz', '.bin',
    '.dat', '.tmp', '.log', '.txt', '.xml', '.json', '.html', '.css'
];

async function batchEncryptAndScan() {
    console.log('=== BATCH ENCRYPTION AND SCANNING ===\n');
    
    const encryptionMethods = [
        'aes256',
        'aes192', 
        'aes128',
        'blowfish',
        'rc4',
        'cam'
    ];
    
    const encryptedFiles = [];
    
    // Step 1: Encrypt calc.exe with all methods
    console.log('STEP 1: Encrypting calc.exe with all methods...\n');
    
    for (const method of encryptionMethods) {
        try {
            console.log(`[${method.toUpperCase()}] Encrypting calc.exe...`);
            
            const command = `node rawrz-standalone.js encrypt ${method} "C:\\Windows\\System32\\calc.exe" .enc`;
            const { stdout, stderr } = await execAsync(command);
            
            // Extract filename from output
            const filenameMatch = stdout.match(/encrypted_calc_.*\.enc/);
            if (filenameMatch) {
                const originalFilename = filenameMatch[0];
                const randomExt = randomExtensions[Math.floor(Math.random() * randomExtensions.length)];
                const newFilename = originalFilename.replace('.enc', randomExt);
                
                // Rename file to random extension
                await fs.rename(originalFilename, newFilename);
                
                encryptedFiles.push({ 
                    method, 
                    originalFilename, 
                    newFilename,
                    extension: randomExt
                });
                console.log(`[${method.toUpperCase()}] ✓ Success: ${newFilename}`);
            } else {
                console.log(`[${method.toUpperCase()}] ✗ Failed to extract filename`);
            }
            
        } catch (error) {
            console.log(`[${method.toUpperCase()}] ✗ Error: ${error.message}`);
        }
        
        console.log(''); // Empty line for readability
    }
    
    console.log('=== ENCRYPTION COMPLETE ===');
    console.log(`Successfully encrypted ${encryptedFiles.length} files:`);
    encryptedFiles.forEach(({ method, newFilename, extension }) => {
        console.log(`  - ${method}: ${newFilename} (${extension})`);
    });
    
    console.log('\n=== STEP 2: BATCH JOTTI SCANNING ===\n');
    
    // Step 2: Batch scan all encrypted files with Jotti
    const scanResults = [];
    
    for (const file of encryptedFiles) {
        try {
            console.log(`[SCAN] Scanning ${file.newFilename} (${file.method})...`);
            
            const command = `node rawrz-standalone.js jotti ${file.newFilename}`;
            const { stdout, stderr } = await execAsync(command);
            
            // Parse scan results
            const cleanResult = stdout.replace(/\[INFO\].*?\n/g, '').replace(/\[OK\].*?\n/g, '').trim();
            
            scanResults.push({
                method: file.method,
                filename: file.newFilename,
                extension: file.extension,
                result: cleanResult
            });
            
            console.log(`[SCAN] ✓ Completed: ${file.newFilename}`);
            
        } catch (error) {
            console.log(`[SCAN] ✗ Error scanning ${file.newFilename}: ${error.message}`);
            scanResults.push({
                method: file.method,
                filename: file.newFilename,
                extension: file.extension,
                result: `ERROR: ${error.message}`
            });
        }
        
        console.log(''); // Empty line for readability
    }
    
    console.log('=== SCAN RESULTS SUMMARY ===\n');
    
    scanResults.forEach(({ method, filename, extension, result }) => {
        console.log(`[${method.toUpperCase()}] ${filename} (${extension}):`);
        console.log(result);
        console.log('---');
    });
    
    // Step 3: Cleanup - remove encrypted files
    console.log('\n=== STEP 3: CLEANUP ===\n');
    
    for (const file of encryptedFiles) {
        try {
            await fs.unlink(file.newFilename);
            console.log(`[CLEANUP] ✓ Removed: ${file.newFilename}`);
        } catch (error) {
            console.log(`[CLEANUP] ✗ Failed to remove ${file.newFilename}: ${error.message}`);
        }
    }
    
    console.log('\n=== BATCH OPERATION COMPLETE ===');
    console.log(`Processed ${encryptedFiles.length} files`);
    console.log(`Scanned ${scanResults.length} files`);
    
    return { encryptedFiles, scanResults };
}

// Run the batch operation
batchEncryptAndScan().catch(console.error);
