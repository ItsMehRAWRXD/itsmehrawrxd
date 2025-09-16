const fs = require('fs');

async function fixCppCode() {
    console.log('=== FIXING REMAINING C++ CODE IN ADVANCED-FUD-ENGINE.JS ===\n');
    
    try {
        let content = fs.readFileSync('src/engines/advanced-fud-engine.js', 'utf8');
        let fixCount = 0;
        
        // More comprehensive C++ patterns
        const cppPatterns = [
            // C++ function calls and operators
            /\b(inet_pton|htons|sendto|closesocket|WSAStartup|WSACleanup|VirtualProtect)\s*\(/g,
            // C++ struct access with &
            /&\w+\.\w+/g,
            // C++ variable declarations
            /\b(WSADATA|SOCKET|DWORD|struct\s+sockaddr_in)\s+\w+/g,
            // C++ specific syntax
            /\w+\.\w+\s*=\s*AF_INET/g,
            /\w+\.\w+\s*=\s*htons\(/g,
            // File operations
            /std::ifstream\s+\w+/g,
            /std::string\s+\w+/g,
            /std::getline\(/g,
            /file\.close\(\)/g,
            // Random and timing
            /std::random_device\s+\w+/g,
            /std::mt19937\s+\w+/g,
            /std::uniform_int_distribution/g,
            /std::this_thread::sleep_for/g,
            /std::chrono::/g,
            // Memory operations
            /PAGE_EXECUTE_READWRITE/g
        ];
        
        // Apply fixes line by line to preserve context
        const lines = content.split('\n');
        const fixedLines = lines.map(line => {
            let originalLine = line;
            
            // Skip lines that are already commented
            if (line.trim().startsWith('//')) {
                return line;
            }
            
            // Check if line contains C++ patterns
            for (const pattern of cppPatterns) {
                if (pattern.test(line)) {
                    // Comment out the line
                    const indent = line.match(/^(\s*)/)[1];
                    line = indent + '// ' + line.trim();
                    fixCount++;
                    break; // Only comment once per line
                }
            }
            
            return line;
        });
        
        content = fixedLines.join('\n');
        fs.writeFileSync('src/engines/advanced-fud-engine.js', content, 'utf8');
        console.log(`✓ Applied ${fixCount} fixes to C++ code`);
        
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
        console.error('Error fixing C++ code:', error.message);
    }
}

fixCppCode();
