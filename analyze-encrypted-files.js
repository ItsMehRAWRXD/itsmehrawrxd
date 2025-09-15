/**
 * Analyze encrypted files to show they are distinct
 */

const { exec } = require('child_process');
const { promisify } = require('util');
const fs = require('fs').promises;
const path = require('path');

const execAsync = promisify(exec);

async function analyzeEncryptedFiles() {
    console.log('=== ENCRYPTED FILES ANALYSIS ===\n');
    
    try {
        // Get all encrypted files
        const uploadsDir = path.join(__dirname, 'uploads');
        const files = await fs.readdir(uploadsDir);
        const encryptedFiles = files.filter(f => f.startsWith('encrypted_'));
        
        console.log(`Found ${encryptedFiles.length} encrypted files\n`);
        
        // Get file info and hashes
        const fileAnalysis = [];
        
        for (const file of encryptedFiles) {
            const filePath = path.join(uploadsDir, file);
            const stats = await fs.stat(filePath);
            
            // Get MD5 hash using certutil (built into Windows)
            const { stdout: hashOutput } = await execAsync(`certutil -hashfile "${filePath}" MD5`);
            const hashMatch = hashOutput.match(/MD5 hash of .*:\s*([A-F0-9]+)/);
            const hash = hashMatch ? hashMatch[1] : 'Unknown';
            
            // Extract algorithm from filename or determine from size
            let algorithm = 'Unknown';
            if (file.includes('calc_')) {
                // These are calc.exe files - determine algorithm by size
                if (stats.size === 65820) algorithm = 'AES256';
                else if (stats.size === 65822) algorithm = 'AES128';
                else if (stats.size === 65817) algorithm = 'CAM';
            } else if (file.includes('test_')) {
                algorithm = 'AES256';
            }
            
            fileAnalysis.push({
                filename: file,
                size: stats.size,
                hash: hash,
                algorithm: algorithm,
                extension: path.extname(file)
            });
        }
        
        // Sort by size
        fileAnalysis.sort((a, b) => a.size - b.size);
        
        // Display results
        console.log('ENCRYPTED FILES ANALYSIS:');
        console.log('='.repeat(80));
        console.log('Filename'.padEnd(50) + 'Size'.padEnd(10) + 'Algorithm'.padEnd(10) + 'MD5 Hash');
        console.log('-'.repeat(80));
        
        fileAnalysis.forEach(file => {
            const shortName = file.filename.length > 45 ? 
                file.filename.substring(0, 42) + '...' : 
                file.filename;
            console.log(
                shortName.padEnd(50) + 
                file.size.toString().padEnd(10) + 
                file.algorithm.padEnd(10) + 
                file.hash
            );
        });
        
        // Group by algorithm
        console.log('\n\nFILES BY ALGORITHM:');
        console.log('='.repeat(50));
        
        const byAlgorithm = {};
        fileAnalysis.forEach(file => {
            if (!byAlgorithm[file.algorithm]) {
                byAlgorithm[file.algorithm] = [];
            }
            byAlgorithm[file.algorithm].push(file);
        });
        
        Object.entries(byAlgorithm).forEach(([algorithm, files]) => {
            console.log(`\n${algorithm} (${files.length} files):`);
            files.forEach(file => {
                console.log(`  - ${file.filename} (${file.size} bytes, ${file.extension})`);
            });
        });
        
        // Check for duplicates
        console.log('\n\nDUPLICATE CHECK:');
        console.log('='.repeat(50));
        
        const hashCounts = {};
        fileAnalysis.forEach(file => {
            hashCounts[file.hash] = (hashCounts[file.hash] || 0) + 1;
        });
        
        const duplicates = Object.entries(hashCounts).filter(([hash, count]) => count > 1);
        
        if (duplicates.length === 0) {
            console.log('✓ All encrypted files are DISTINCT (no duplicate hashes)');
        } else {
            console.log(`✗ Found ${duplicates.length} duplicate hashes:`);
            duplicates.forEach(([hash, count]) => {
                console.log(`  Hash ${hash}: ${count} files`);
            });
        }
        
        // Summary
        console.log('\n\nSUMMARY:');
        console.log('='.repeat(50));
        console.log(`Total encrypted files: ${fileAnalysis.length}`);
        console.log(`Unique algorithms: ${Object.keys(byAlgorithm).length}`);
        console.log(`File extensions used: ${[...new Set(fileAnalysis.map(f => f.extension))].join(', ')}`);
        console.log(`Size range: ${Math.min(...fileAnalysis.map(f => f.size))} - ${Math.max(...fileAnalysis.map(f => f.size))} bytes`);
        console.log(`All files distinct: ${duplicates.length === 0 ? 'YES' : 'NO'}`);
        
        return fileAnalysis;
        
    } catch (error) {
        console.error('Error:', error.message);
        return [];
    }
}

analyzeEncryptedFiles();
