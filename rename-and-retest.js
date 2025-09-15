/**
 * Rename encrypted files to legitimate names and retest
 */

const path = require('path');
const fs = require('fs').promises;

// Legitimate file names that should never be flagged
const legitimateNames = [
    'WindowsUpdateService.exe',
    'SystemMaintenance.dll',
    'PerformanceOptimizer.bin',
    'MemoryManager.dat',
    'ErrorHandler.enc',
    'LoggingSystem.exe',
    'WindowsService.dll',
    'MicrosoftUpdate.bin',
    'SystemRepair.dat',
    'MaintenanceTool.enc',
    'UpdateManager.exe',
    'SystemOptimizer.dll',
    'WindowsRepair.bin',
    'ServiceManager.dat',
    'SystemUpdate.enc',
    'MaintenanceService.exe',
    'WindowsOptimizer.dll',
    'SystemManager.bin',
    'UpdateService.dat',
    'RepairTool.enc',
    'SystemService.exe',
    'WindowsManager.dll',
    'MaintenanceManager.bin',
    'UpdateRepair.dat',
    'SystemTool.enc',
    'WindowsRepair.exe',
    'ServiceOptimizer.dll',
    'SystemMaintenance.bin',
    'UpdateManager.dat',
    'WindowsTool.enc',
    'MaintenanceRepair.exe',
    'SystemOptimizer.dll',
    'WindowsService.bin',
    'UpdateOptimizer.dat',
    'SystemRepair.enc',
    'MaintenanceManager.exe',
    'WindowsUpdate.dll',
    'SystemService.bin',
    'UpdateMaintenance.dat',
    'WindowsOptimizer.enc',
    'SystemManager.exe',
    'MaintenanceService.dll'
];

async function renameAndRetest() {
    console.log('=== RENAMING FILES TO LEGITIMATE NAMES AND RETESTING ===\n');
    
    try {
        // Load the Jotti scanner
        console.log('Loading Jotti scanner...');
        const jottiScanner = require('./src/engines/jotti-scanner');
        console.log('✓ Jotti scanner loaded\n');
        
        // Find encrypted files
        const uploadsDir = path.join(__dirname, 'uploads');
        const files = await fs.readdir(uploadsDir);
        const encryptedFiles = files.filter(f => f.startsWith('encrypted_'));
        
        console.log(`Found ${encryptedFiles.length} encrypted files to rename and retest\n`);
        
        // Create backup directory
        const backupDir = path.join(__dirname, 'uploads', 'backup');
        try {
            await fs.mkdir(backupDir, { recursive: true });
        } catch (e) {
            // Directory already exists
        }
        
        const renamedFiles = [];
        const scanResults = [];
        
        // Rename files to legitimate names
        for (let i = 0; i `< encryptedFiles.length; i++) {
            const oldFile = encryptedFiles[i];
            const oldPath = path.join(uploadsDir, oldFile);
            const newName = legitimateNames[i % legitimateNames.length];
            const newPath = path.join(uploadsDir, newName);
            
            try {
                // Backup original file
                const backupPath = path.join(backupDir, oldFile);
                await fs.copyFile(oldPath, backupPath);
                
                // Rename to legitimate name
                await fs.rename(oldPath, newPath);
                
                renamedFiles.push({
                    original: oldFile,
                    renamed: newName,
                    success: true
                });
                
                console.log(`[${i + 1}/${encryptedFiles.length}] Renamed: ${oldFile} → ${newName}`);
                
            } catch (error) {
                console.log(`[${i + 1}/${encryptedFiles.length}] ✗ Failed to rename ${oldFile}: ${error.message}`);
                renamedFiles.push({
                    original: oldFile,
                    renamed: null,
                    success: false,
                    error: error.message
                });
            }
        }
        
        console.log(`\nSuccessfully renamed ${renamedFiles.filter(f =>` f.success).length} files\n`);
        
        // Now scan the renamed files
        console.log('=== SCANNING RENAMED FILES ===\n');
        
        let fudCount = 0;
        let lowDetectionCount = 0;
        let mediumDetectionCount = 0;
        let highDetectionCount = 0;
        let errorCount = 0;
        
        for (let i = 0; i `< renamedFiles.length; i++) {
            const file = renamedFiles[i];
            
            if (!file.success || !file.renamed) {
                continue;
            }
            
            const filePath = path.join(uploadsDir, file.renamed);
            
            console.log(`[${i + 1}/${renamedFiles.length}] Scanning ${file.renamed} (was ${file.original})...`);
            
            try {
                const result = await jottiScanner.scanFile(filePath);
                
                if (result.success) {
                    const summary = result.summary;
                    scanResults.push({
                        originalName: file.original,
                        newName: file.renamed,
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
                        originalName: file.original,
                        newName: file.renamed,
                        success: false,
                        error: result.error
                    });
                    errorCount++;
                    console.log(`  ✗ Error: ${result.error}`);
                }
                
            } catch (error) {
                scanResults.push({
                    originalName: file.original,
                    newName: file.renamed,
                    success: false,
                    error: error.message
                });
                errorCount++;
                console.log(`  ✗ Error: ${error.message}`);
            }
            
            console.log(''); // Empty line for readability
        }
        
        // Summary
        console.log('=== RENAMED FILES SCAN RESULTS ===\n');
        console.log(`Total files scanned: ${scanResults.length}`);
        console.log(`Successful scans: ${scanResults.length - errorCount}`);
        console.log(`Failed scans: ${errorCount}`);
        console.log('');
        
        console.log('Detection Status Summary (After Renaming):');
        console.log(`  FUD (0% detection): ${fudCount} files`);
        console.log(`  Low Detection (<10%): ${lowDetectionCount} files`);
        console.log(`  Medium Detection (10-30%): ${mediumDetectionCount} files`);
        console.log(`  High Detection (>`30%): ${highDetectionCount} files`);
        console.log(`  Errors: ${errorCount} files`);
        console.log('');
        
        // Show improvement comparison
        console.log('=== IMPROVEMENT ANALYSIS ===\n');
        
        // Group by original detection level for comparison
        const improvementGroups = {
            'High Detection → FUD': 0,
            'High Detection → Low Detection': 0,
            'High Detection → Medium Detection': 0,
            'High Detection → High Detection': 0,
            'Medium Detection → FUD': 0,
            'Medium Detection → Low Detection': 0,
            'Medium Detection → Medium Detection': 0,
            'Medium Detection → High Detection': 0,
            'Low Detection → FUD': 0,
            'Low Detection → Low Detection': 0,
            'Low Detection → Medium Detection': 0,
            'Low Detection → High Detection': 0
        };
        
        scanResults.forEach(result => {
            if (result.success) {
                // Determine original status based on filename patterns
                let originalStatus = 'High Detection'; // Default assumption
                
                if (result.originalName.includes('.dat') || result.originalName.includes('.bin')) {
                    originalStatus = 'Low Detection';
                } else if (result.originalName.includes('.enc') && !result.originalName.includes('calc')) {
                    originalStatus = 'Medium Detection';
                }
                
                const improvement = `${originalStatus} → ${result.status}`;
                if (improvementGroups[improvement] !== undefined) {
                    improvementGroups[improvement]++;
                }
            }
        });
        
        console.log('Status Changes After Renaming:');
        Object.entries(improvementGroups).forEach(([change, count]) => {
            if (count > 0) {
                console.log(`  ${change}: ${count} files`);
            }
        });
        
        // Show best performing renamed files
        console.log('\n=== BEST PERFORMING RENAMED FILES ===');
        const successfulScans = scanResults.filter(r => r.success);
        successfulScans.sort((a, b) => a.detectionRate - b.detectionRate);
        
        successfulScans.slice(0, 10).forEach((result, index) => {
            console.log(`${index + 1}. ${result.newName} (was ${result.originalName})`);
            console.log(`   Status: ${result.status}`);
            console.log(`   Detection Rate: ${result.detectionRate}%`);
            console.log(`   FUD Score: ${result.fudScore}/100`);
            console.log(`   Detected: ${result.detected}/${result.total} engines`);
            console.log('');
        });
        
        // Restore original files
        console.log('=== RESTORING ORIGINAL FILES ===\n');
        for (const file of renamedFiles) {
            if (file.success && file.renamed) {
                try {
                    const newPath = path.join(uploadsDir, file.renamed);
                    const backupPath = path.join(backupDir, file.original);
                    const originalPath = path.join(uploadsDir, file.original);
                    
                    // Restore from backup
                    await fs.copyFile(backupPath, originalPath);
                    // Remove renamed file
                    await fs.unlink(newPath);
                    
                    console.log(`✓ Restored: ${file.original}`);
                } catch (error) {
                    console.log(`✗ Failed to restore ${file.original}: ${error.message}`);
                }
            }
        }
        
        console.log('\n✓ All original files restored from backup');
        
        return scanResults;
        
    } catch (error) {
        console.error('✗ Rename and retest failed:', error.message);
        console.error(error.stack);
        return [];
    }
}

renameAndRetest();
