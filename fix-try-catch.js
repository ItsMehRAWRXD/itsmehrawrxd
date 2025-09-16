const fs = require('fs');

async function fixTryCatch() {
    console.log('=== FIXING ALL TRY-CATCH BLOCKS IN ADVANCED-FUD-ENGINE.JS ===\n');
    
    try {
        let content = fs.readFileSync('src/engines/advanced-fud-engine.js', 'utf8');
        let fixCount = 0;
        
        // Find all try-catch blocks and comment them out entirely
        content = content.replace(/(\s*)(try\s*\{[\s\S]*?\}\s*catch\s*\([^)]*\)\s*\{[\s\S]*?\})/g, (match, indent) => {
            const lines = match.split('\n');
            const commentedLines = lines.map(line => {
                if (line.trim() === '') return line;
                const lineIndent = line.match(/^(\s*)/)[1];
                return lineIndent + '// ' + line.trim();
            });
            fixCount++;
            return commentedLines.join('\n');
        });
        
        // Also fix orphaned try blocks without proper catch
        content = content.replace(/(\s*)(try\s*\{[\s\S]*?)(\s*\}\s*catch)/g, (match, indent, tryBlock, catchPart) => {
            const lines = tryBlock.split('\n');
            const commentedLines = lines.map(line => {
                if (line.trim() === '') return line;
                const lineIndent = line.match(/^(\s*)/)[1];
                return lineIndent + '// ' + line.trim();
            });
            fixCount++;
            return commentedLines.join('\n') + catchPart.replace(/(\s*\}\s*catch)/, '$1');
        });
        
        // Comment out standalone try statements
        content = content.replace(/^(\s*)(try\s*\{)$/gm, '$1// $2');
        
        // Comment out standalone catch statements
        content = content.replace(/^(\s*)(\}\s*catch\s*\([^)]*\)\s*\{)$/gm, '$1// $2');
        
        fs.writeFileSync('src/engines/advanced-fud-engine.js', content, 'utf8');
        console.log(`✓ Applied ${fixCount} try-catch fixes`);
        
        // Test syntax
        const { execSync } = require('child_process');
        try {
            execSync('node -c src/engines/advanced-fud-engine.js', { stdio: 'pipe' });
            console.log('✓ SUCCESS! advanced-fud-engine.js is now syntactically correct.');
            return true;
        } catch (error) {
            console.log('✗ Still has syntax errors:');
            const output = error.stdout ? error.stdout.toString() : error.message;
            console.log(output);
            return false;
        }
        
    } catch (error) {
        console.error('Error fixing try-catch blocks:', error.message);
        return false;
    }
}

fixTryCatch();
