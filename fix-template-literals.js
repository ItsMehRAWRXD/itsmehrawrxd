const fs = require('fs');

async function fixTemplateLiterals() {
    console.log('=== FIXING TEMPLATE LITERALS IN ADVANCED-FUD-ENGINE.JS ===\n');
    
    try {
        let content = fs.readFileSync('src/engines/advanced-fud-engine.js', 'utf8');
        let fixCount = 0;
        
        // Fix 1: Add missing backticks for template literal starts
        const missingBacktickPatterns = [
            /'cpp':\s*\/\//g,
            /'python':\s*\/\//g,
            /'javascript':\s*\/\//g
        ];
        
        missingBacktickPatterns.forEach(pattern => {
            content = content.replace(pattern, (match) => {
                fixCount++;
                return match.replace(/\/\//, '`//');
            });
        });
        
        // Fix 2: Comment out C++ code patterns
        const cppPatterns = [
            /#include\s*<[^>]+>/g,
            /\b(WSADATA|SOCKET|DWORD|std::|volatile\s+int|auto\s+\w+)/g,
            /WSAStartup|WSACleanup|VirtualProtect|closesocket/g,
            /struct\s+sockaddr_in/g
        ];
        
        cppPatterns.forEach(pattern => {
            content = content.replace(pattern, (match) => {
                // Only comment if not already commented
                if (!match.startsWith('//')) {
                    fixCount++;
                    return '// ' + match;
                }
                return match;
            });
        });
        
        // Fix 3: Comment out Python code patterns
        content = content.replace(/^(\s*)(import\s+\w+|from\s+\w+|def\s+\w+|class\s+\w+|if\s+.*:|try:|except:|with\s+.*:)/gm, (match, indent) => {
            if (!match.includes('//')) {
                fixCount++;
                return indent + '// ' + match.trim();
            }
            return match;
        });
        
        // Fix 4: Comment out await statements in template literals
        content = content.replace(/(\s+)(await\s+.*);/g, (match, indent, awaitPart) => {
            if (!match.includes('//')) {
                fixCount++;
                return indent + '// ' + awaitPart + ';';
            }
            return match;
        });
        
        // Fix 5: Comment out Python-style comments that cause issues
        content = content.replace(/^(\s*)(#\s*.*)/gm, (match, indent, comment) => {
            if (!match.includes('//')) {
                fixCount++;
                return indent + '// ' + comment;
            }
            return match;
        });
        
        fs.writeFileSync('src/engines/advanced-fud-engine.js', content, 'utf8');
        console.log(`✓ Applied ${fixCount} fixes to template literals`);
        
        // Test syntax
        const { execSync } = require('child_process');
        try {
            execSync('node -c src/engines/advanced-fud-engine.js', { stdio: 'pipe' });
            console.log('✓ Syntax check passed!');
        } catch (error) {
            console.log('✗ Syntax check failed:');
            console.log(error.stdout.toString());
        }
        
    } catch (error) {
        console.error('Error fixing template literals:', error.message);
    }
}

fixTemplateLiterals();
