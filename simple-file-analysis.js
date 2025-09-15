/**
 * Simple analysis of encrypted files to show differences
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

async function analyzeFiles() {
    console.log('=== ENCRYPTED FILES DIFFERENCE ANALYSIS ===\n');
    
    try {
        const uploadsDir = path.join(__dirname, 'uploads');
        const files = await fs.readdir(uploadsDir);
        const encryptedFiles = files.filter(f => f.startsWith('encrypted_'));
        
        console.log(`Found ${encryptedFiles.length} encrypted files\n`);
        
        // Analyze files
        const fileData = [];
        
        for (const file of encryptedFiles) {
            const filePath = path.join(uploadsDir, file);
            const content = await fs.readFile(filePath);
            const hash = crypto.createHash('md5').update(content).digest('hex');
            
            // Determine algorithm by size and filename
            let algorithm = 'Unknown';
            if (file.includes('calc_')) {
                if (content.length === 65820) algorithm = 'AES256';
                else if (content.length === 65822) algorithm = 'AES128';
                else if (content.length === 65817) algorithm = 'CAM';
            } else if (file.includes('test_') || file.includes('Hello') || file.includes('ChaCha')) {
                algorithm = 'AES256';
            }
            
            fileData.push({
                name: file,
                size: content.length,
                hash: hash,
                algorithm: algorithm,
                extension: path.extname(file),
                firstBytes: content.slice(0, 16).toString('hex')
            });
        }
        
        // Sort by size
        fileData.sort((a, b) => a.size - b.size);
        
        // Show detailed analysis
        console.log('DETAILED FILE ANALYSIS:');
        console.log('='.repeat(100));
        console.log('Filename'.padEnd(45) + 'Size'.padEnd(8) + 'Algorithm'.padEnd(10) + 'MD5 Hash'.padEnd(35) + 'First 16 bytes');
        console.log('-'.repeat(100));
        
        fileData.forEach(file => {
            const shortName = file.name.length > 42 ? 
                file.name.substring(0, 39) + '...' : 
                file.name;
            console.log(
                shortName.padEnd(45) + 
                file.size.toString().padEnd(8) + 
                file.algorithm.padEnd(10) + 
                file.hash.padEnd(35) + 
                file.firstBytes
            );
        });
        
        // Check for duplicates
        console.log('\n\nDUPLICATE ANALYSIS:');
        console.log('='.repeat(60));
        
        const hashGroups = {};
        fileData.forEach(file => {
            if (!hashGroups[file.hash]) {
                hashGroups[file.hash] = [];
            }
            hashGroups[file.hash].push(file);
        });
        
        const duplicates = Object.entries(hashGroups).filter(([hash, files]) => files.length > 1);
        
        if (duplicates.length === 0) {
            console.log('✓ ALL FILES ARE UNIQUE - No duplicate hashes found!');
        } else {
            console.log(`✗ Found ${duplicates.length} groups of duplicate files:`);
            duplicates.forEach(([hash, files]) => {
                console.log(`\nHash: ${hash} (${files.length} files)`);
                files.forEach(file => {
                    console.log(`  - ${file.name} (${file.size} bytes, ${file.algorithm})`);
                });
            });
        }
        
        // Show algorithm distribution
        console.log('\n\nALGORITHM DISTRIBUTION:');
        console.log('='.repeat(40));
        
        const algorithmCounts = {};
        fileData.forEach(file => {
            algorithmCounts[file.algorithm] = (algorithmCounts[file.algorithm] || 0) + 1;
        });
        
        Object.entries(algorithmCounts).forEach(([algorithm, count]) => {
            console.log(`${algorithm}: ${count} files`);
        });
        
        // Show size distribution
        console.log('\n\nSIZE DISTRIBUTION:');
        console.log('='.repeat(40));
        
        const sizeGroups = {};
        fileData.forEach(file => {
            if (!sizeGroups[file.size]) {
                sizeGroups[file.size] = [];
            }
            sizeGroups[file.size].push(file);
        });
        
        Object.entries(sizeGroups).forEach(([size, files]) => {
            console.log(`${size} bytes: ${files.length} files (${files[0].algorithm})`);
        });
        
        // Show extension distribution
        console.log('\n\nEXTENSION DISTRIBUTION:');
        console.log('='.repeat(40));
        
        const extensionCounts = {};
        fileData.forEach(file => {
            extensionCounts[file.extension] = (extensionCounts[file.extension] || 0) + 1;
        });
        
        Object.entries(extensionCounts).forEach(([ext, count]) => {
            console.log(`${ext}: ${count} files`);
        });
        
        // Summary
        console.log('\n\nSUMMARY:');
        console.log('='.repeat(40));
        console.log(`Total files: ${fileData.length}`);
        console.log(`Unique hashes: ${Object.keys(hashGroups).length}`);
        console.log(`Duplicate groups: ${duplicates.length}`);
        console.log(`Algorithms used: ${Object.keys(algorithmCounts).length}`);
        console.log(`Extensions used: ${Object.keys(extensionCounts).length}`);
        console.log(`Size range: ${Math.min(...fileData.map(f => f.size))} - ${Math.max(...fileData.map(f => f.size))} bytes`);
        
        if (duplicates.length === 0) {
            console.log('\n🎉 SUCCESS: All encrypted files are completely distinct!');
            console.log('   Each file has a unique MD5 hash, proving they are different.');
        } else {
            console.log('\n⚠️  WARNING: Some files are identical (same hash)');
        }
        
    } catch (error) {
        console.error('Error:', error.message);
    }
}

analyzeFiles();
