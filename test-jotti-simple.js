/**
 * Simple Jotti scanner test
 */

const path = require('path');
const fs = require('fs').promises;

async function testJottiScanner() {
    console.log('=== SIMPLE JOTTI SCANNER TEST ===\n');
    
    try {
        // Load the Jotti scanner directly
        console.log('Loading Jotti scanner...');
        const jottiScanner = require('./src/engines/jotti-scanner');
        console.log('✓ Jotti scanner loaded\n');
        
        // Get scanner info
        console.log('Scanner Info:');
        const info = jottiScanner.getScannerInfo();
        console.log(`  Name: ${info.name}`);
        console.log(`  Version: ${info.version}`);
        console.log(`  Status: ${info.status}`);
        console.log(`  Max File Size: ${info.maxFileSize} bytes`);
        console.log(`  Supported Engines: ${info.supportedEngines.length}`);
        console.log('');
        
        // Find encrypted files
        const uploadsDir = path.join(__dirname, 'uploads');
        const files = await fs.readdir(uploadsDir);
        const encryptedFiles = files.filter(f => f.startsWith('encrypted_'));
        
        console.log(`Found ${encryptedFiles.length} encrypted files:`);
        encryptedFiles.slice(0, 5).forEach((file, index) => {
            console.log(`  ${index + 1}. ${file}`);
        });
        if (encryptedFiles.length > 5) {
            console.log(`  ... and ${encryptedFiles.length - 5} more`);
        }
        console.log('');
        
        // Test scan on first file
        if (encryptedFiles.length > 0) {
            const testFile = path.join(uploadsDir, encryptedFiles[0]);
            console.log(`Testing scan on: ${encryptedFiles[0]}`);
            
            const result = await jottiScanner.scanFile(testFile);
            
            console.log('\nScan Result:');
            console.log(`  Success: ${result.success}`);
            if (result.success) {
                console.log(`  File Size: ${result.fileSize} bytes`);
                console.log(`  Job ID: ${result.jobId}`);
                console.log(`  Summary: ${JSON.stringify(result.summary, null, 2)}`);
                
                if (result.results && result.results.summary) {
                    console.log(`  Detection Rate: ${result.results.summary.detectionRate}%`);
                    console.log(`  Status: ${result.results.summary.status}`);
                    console.log(`  Detected: ${result.results.summary.detected}/${result.results.summary.total}`);
                }
            } else {
                console.log(`  Error: ${result.error}`);
            }
        }
        
        console.log('\n✓ Test completed successfully!');
        
    } catch (error) {
        console.error('✗ Test failed:', error.message);
        console.error(error.stack);
    }
}

testJottiScanner();
