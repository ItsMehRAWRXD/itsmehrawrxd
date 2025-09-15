/**
 * Test a few renamed files to confirm FUD results
 */

const path = require('path');
const fs = require('fs').promises;

async function testRenamedFiles() {
    console.log('=== TESTING RENAMED FILES FOR FUD ===\n');
    
    try {
        // Load the Jotti scanner
        console.log('Loading Jotti scanner...');
        const jottiScanner = require('./src/engines/jotti-scanner');
        console.log('[INFO] Jotti scanner loaded\n');
        
        // Test a few renamed files
        const testFiles = [
            'WindowsUpdateService.exe',
            'SystemMaintenance.dll',
            'PerformanceOptimizer.bin',
            'MemoryManager.dat',
            'ErrorHandler.enc',
            'LoggingSystem.exe',
            'WindowsService.dll',
            'MicrosoftUpdate.bin',
            'SystemRepair.dat',
            'MaintenanceTool.enc'
        ];
        
        const uploadsDir = path.join(__dirname, 'uploads');
        let fudCount = 0;
        let totalTested = 0;
        
        console.log(`Testing ${testFiles.length} renamed files...\n`);
        
        for (let i = 0; i `< testFiles.length; i++) {
            const fileName = testFiles[i];
            const filePath = path.join(uploadsDir, fileName);
            
            try {
                // Check if file exists
                await fs.access(filePath);
                
                console.log(`[${i + 1}/${testFiles.length}] Testing ${fileName}...`);
                
                const result = await jottiScanner.scanFile(filePath);
                
                if (result.success) {
                    const summary = result.summary;
                    totalTested++;
                    
                    if (summary.status === 'FUD') {
                        fudCount++;
                        console.log(`  [INFO] FUD: ${summary.detectionRate}% detection (${summary.detected}/${summary.engines} engines) - FUD Score: ${summary.fudScore}`);
                    } else {
                        console.log(`  [WARN] ${summary.status}: ${summary.detectionRate}% detection (${summary.detected}/${summary.engines} engines) - FUD Score: ${summary.fudScore}`);
                    }
                } else {
                    console.log(`  [INFO] Error: ${result.error}`);
                }
                
            } catch (error) {
                console.log(`  [INFO] File not found: ${fileName}`);
            }
            
            console.log('');
        }
        
        // Summary
        console.log('=== RENAMED FILES TEST RESULTS ===\n');
        console.log(`Files tested: ${totalTested}`);
        console.log(`FUD files: ${fudCount}`);
        console.log(`FUD success rate: ${totalTested >` 0 ? ((fudCount / totalTested) * 100).toFixed(1) : 0}%`);
        
        if (fudCount === totalTested && totalTested > 0) {
            console.log('\n[SUCCESS] PERFECT FUD SUCCESS! All renamed files achieved 0% detection!');
        } else if (fudCount > 0) {
            console.log(`\n[OK] Good FUD success! ${fudCount}/${totalTested} files achieved 0% detection.`);
        } else {
            console.log('\n[ERROR] No FUD success. Files still being detected.');
        }
        
    } catch (error) {
        console.error('[INFO] Test failed:', error.message);
        console.error(error.stack);
    }
}

testRenamedFiles();
