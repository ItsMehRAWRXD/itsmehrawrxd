const fs = require('fs');

function findUnmatchedBraces() {
    console.log('=== FINDING UNMATCHED BRACES IN ADVANCED-FUD-ENGINE.JS ===\n');
    
    try {
        const content = fs.readFileSync('src/engines/advanced-fud-engine.js', 'utf8');
        const lines = content.split('\n');
        
        let braceStack = [];
        let parenStack = [];
        let bracketStack = [];
        let templateStack = [];
        
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const lineNum = i + 1;
            
            // Skip commented lines
            if (line.trim().startsWith('//')) continue;
            
            for (let j = 0; j < line.length; j++) {
                const char = line[j];
                const pos = `${lineNum}:${j + 1}`;
                
                switch (char) {
                    case '{':
                        braceStack.push(pos);
                        break;
                    case '}':
                        if (braceStack.length === 0) {
                            console.log(`Extra closing brace at ${pos}: ${line.trim()}`);
                        } else {
                            braceStack.pop();
                        }
                        break;
                    case '(':
                        parenStack.push(pos);
                        break;
                    case ')':
                        if (parenStack.length === 0) {
                            console.log(`Extra closing paren at ${pos}: ${line.trim()}`);
                        } else {
                            parenStack.pop();
                        }
                        break;
                    case '[':
                        bracketStack.push(pos);
                        break;
                    case ']':
                        if (bracketStack.length === 0) {
                            console.log(`Extra closing bracket at ${pos}: ${line.trim()}`);
                        } else {
                            bracketStack.pop();
                        }
                        break;
                    case '`':
                        if (templateStack.length > 0 && templateStack[templateStack.length - 1] === pos) {
                            // This shouldn't happen, but just in case
                            templateStack.pop();
                        } else if (templateStack.length > 0) {
                            templateStack.pop(); // Closing template literal
                        } else {
                            templateStack.push(pos); // Opening template literal
                        }
                        break;
                }
            }
        }
        
        console.log(`\nUnmatched opening braces: ${braceStack.length}`);
        braceStack.forEach(pos => console.log(`  Opening brace at ${pos}`));
        
        console.log(`\nUnmatched opening parentheses: ${parenStack.length}`);
        parenStack.forEach(pos => console.log(`  Opening paren at ${pos}`));
        
        console.log(`\nUnmatched opening brackets: ${bracketStack.length}`);
        bracketStack.forEach(pos => console.log(`  Opening bracket at ${pos}`));
        
        console.log(`\nUnmatched template literals: ${templateStack.length}`);
        templateStack.forEach(pos => console.log(`  Opening template literal at ${pos}`));
        
        if (braceStack.length === 0 && parenStack.length === 0 && bracketStack.length === 0 && templateStack.length === 0) {
            console.log('\n✓ All braces, parentheses, brackets, and template literals appear to be matched.');
        } else {
            console.log('\n✗ Found unmatched syntax elements.');
        }
        
    } catch (error) {
        console.error('Error analyzing file:', error.message);
    }
}

findUnmatchedBraces();
