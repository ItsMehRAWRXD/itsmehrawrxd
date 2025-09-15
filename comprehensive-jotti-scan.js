/**
 * Comprehensive Jotti scanner test for all encrypted files
 */

const path = require('path');
const fs = require('fs').promises;

async function comprehensiveJottiScan() {
    console.log('=== COMPREHENSIVE JOTTI SCANNER RESULTS ===\n');
    
    try {
        // Load the Jotti scanner directly
        console.log('Loading Jotti scanner...');
        const jottiScanner = require('./src/engines/jotti-scanner');
        console.log('✓ Jotti scanner loaded\n');
        
        // Find encrypted files
        const uploadsDir = path.join(__dirname, 'uploads');
        const files = await fs.readdir(uploadsDir);
        const encryptedFiles = files.filter(f => f.startsWith('encrypted_'));
        
        console.log(`Found ${encryptedFiles.length} encrypted files to scan\n`);
        
        const scanResults = [];
        let fudCount = 0;
        let lowDetectionCount = 0;
        let mediumDetectionCount = 0;
        let highDetectionCount = 0;
        let errorCount = 0;
        
        // Scan each file
        for (let i = 0; i `< encryptedFiles.length; i++) {
            const file = encryptedFiles[i];
            const filePath = path.join(uploadsDir, file);
            
            console.log(`[${i + 1}/${encryptedFiles.length}] Scanning ${file}...`);
            
            try {
                const result = await jottiScanner.scanFile(filePath);
                
                if (result.success) {
                    const summary = result.summary;
                    scanResults.push({
                        filename: file,
                        success: true,
                        detectionRate: summary.detectionRate,
                        status: summary.status,
                        fudScore: summary.fudScore,
                        detected: summary.detected,
                        total: summary.engines
                    });
                    
                    // Count by status
                    if (summary.status === 'FUD') fudCount++;
                    else if (summary.status === 'Low Detection') lowDetectionCount++;
                    else if (summary.status === 'Medium Detection') mediumDetectionCount++;
                    else if (summary.status === 'High Detection') highDetectionCount++;
                    
                    console.log(`  ✓ ${summary.status}: ${summary.detectionRate}% detection (${summary.detected}/${summary.engines} engines) - FUD Score: ${summary.fudScore}`);
                } else {
                    scanResults.push({
                        filename: file,
                        success: false,
                        error: result.error
                    });
                    errorCount++;
                    console.log(`  ✗ Error: ${result.error}`);
                }
                
            } catch (error) {
                scanResults.push({
                    filename: file,
                    success: false,
                    error: error.message
                });
                errorCount++;
                console.log(`  ✗ Error: ${error.message}`);
            }
            
            console.log(''); // Empty line for readability
        }
        
        // Summary
        console.log('=== COMPREHENSIVE SCAN RESULTS ===\n');
        console.log(`Total files scanned: ${scanResults.length}`);
        console.log(`Successful scans: ${scanResults.length - errorCount}`);
        console.log(`Failed scans: ${errorCount}`);
        console.log('');
        
        console.log('Detection Status Summary:');
        console.log(`  FUD (0% detection): ${fudCount} files`);
        console.log(`  Low Detection (<10%): ${lowDetectionCount} files`);
        console.log(`  Medium Detection (10-30%): ${mediumDetectionCount} files`);
        console.log(`  High Detection (>`30%): ${highDetectionCount} files`);
        console.log(`  Errors: ${errorCount} files`);
        console.log('');
        
        // Show results by encryption method
        const resultsByMethod = {};
        scanResults.forEach(result => {
            if (result.success) {
                // Extract encryption method from filename
                const match = result.filename.match(/encrypted_.*?_(.+?)_\d{4}-\d{2}-\d{2}T/);
                const method = match ? match[1] : 'unknown';
                
                if (!resultsByMethod[method]) {
                    resultsByMethod[method] = {
                        total: 0,
                        fud: 0,
                        low: 0,
                        medium: 0,
                        high: 0,
                        avgDetectionRate: 0,
                        avgFudScore: 0
                    };
                }
                
                resultsByMethod[method].total++;
                if (result.status === 'FUD') resultsByMethod[method].fud++;
                else if (result.status === 'Low Detection') resultsByMethod[method].low++;
                else if (result.status === 'Medium Detection') resultsByMethod[method].medium++;
                else if (result.status === 'High Detection') resultsByMethod[method].high++;
                
                resultsByMethod[method].avgDetectionRate += result.detectionRate;
                resultsByMethod[method].avgFudScore += result.fudScore;
            }
        });
        
        // Calculate averages
        Object.keys(resultsByMethod).forEach(method => {
            const data = resultsByMethod[method];
            data.avgDetectionRate = (data.avgDetectionRate / data.total).toFixed(1);
            data.avgFudScore = Math.round(data.avgFudScore / data.total);
        });
        
        console.log('Results by Encryption Method:');
        Object.entries(resultsByMethod).forEach(([method, data]) => {
            console.log(`\n${method.toUpperCase()}:`);
            console.log(`  Total files: ${data.total}`);
            console.log(`  FUD: ${data.fud} (${((data.fud/data.total)*100).toFixed(1)}%)`);
            console.log(`  Low Detection: ${data.low} (${((data.low/data.total)*100).toFixed(1)}%)`);
            console.log(`  Medium Detection: ${data.medium} (${((data.medium/data.total)*100).toFixed(1)}%)`);
            console.log(`  High Detection: ${data.high} (${((data.high/data.total)*100).toFixed(1)}%)`);
            console.log(`  Average Detection Rate: ${data.avgDetectionRate}%`);
            console.log(`  Average FUD Score: ${data.avgFudScore}/100`);
        });
        
        // Show best performing files
        console.log('\n=== BEST PERFORMING FILES (Lowest Detection) ===');
        const successfulScans = scanResults.filter(r => r.success);
        successfulScans.sort((a, b) => a.detectionRate - b.detectionRate);
        
        successfulScans.slice(0, 10).forEach((result, index) => {
            console.log(`${index + 1}. ${result.filename}`);
            console.log(`   Status: ${result.status}`);
            console.log(`   Detection Rate: ${result.detectionRate}%`);
            console.log(`   FUD Score: ${result.fudScore}/100`);
            console.log(`   Detected: ${result.detected}/${result.total} engines`);
            console.log('');
        });
        
        return scanResults;
        
    } catch (error) {
        console.error('✗ Comprehensive scan failed:', error.message);
        console.error(error.stack);
        return [];
    }
}

comprehensiveJottiScan();
