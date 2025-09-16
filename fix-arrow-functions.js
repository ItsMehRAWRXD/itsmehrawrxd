const fs = require('fs');
const path = require('path');

console.log('Fixing malformed arrow function syntax...');

// Get all source files
const srcDir = 'src';
const files = [];

function getAllFiles(dir) {
    const items = fs.readdirSync(dir);
    for (const item of items) {
        const fullPath = path.join(dir, item);
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) {
            getAllFiles(fullPath);
        } else if (item.endsWith('.js')) {
            files.push(fullPath);
        }
    }
}

getAllFiles(srcDir);

let totalFixed = 0;

files.forEach(file => {
    let content = fs.readFileSync(file, 'utf8');
    const originalContent = content;
    
    // Fix malformed arrow functions: =>` { to => {
    content = content.replace(/=>`\s*\{/g, '=> {');
    
    // Fix malformed arrow functions: =>` expression to => expression
    content = content.replace(/=>`\s+([^{][^`]*?)(?=\s*[,;\)\]\}])/g, '=> $1');
    
    // Fix specific patterns found
    content = content.replace(/=>`\s*key\.toString\('hex'\)/g, "=> key.toString('hex')");
    content = content.replace(/=>`\s*file\.endsWith\('\.cpp'\)/g, "=> file.endsWith('.cpp')");
    content = content.replace(/=>`\s*chunks\.push\(chunk\)/g, '=> chunks.push(chunk)');
    content = content.replace(/=>`\s*setTimeout\(resolve, delay\)/g, '=> setTimeout(resolve, delay)');
    content = content.replace(/=>`\s*line\.trim\(\)\.length > 0\)\.length/g, '=> line.trim().length > 0).length');
    content = content.replace(/=>`\s*s\.length > 4\)/g, '=> s.length > 4)');
    content = content.replace(/=>`\s*byte \^ key\)/g, '=> byte ^ key)');
    content = content.replace(/=>`\s*char\.charCodeAt\(0\)\.toString\(2\)\.padStart\(8, '0'\)\)\.join\(''\)/g, "=> char.charCodeAt(0).toString(2).padStart(8, '0')).join('')");
    content = content.replace(/=>`\s*setTimeout\(resolve, randomDelay\)/g, '=> setTimeout(resolve, randomDelay)');
    
    if (content !== originalContent) {
        fs.writeFileSync(file, content, 'utf8');
        console.log(`Fixed arrow functions in ${file}`);
        totalFixed++;
    }
});

console.log(`Fixed arrow functions in ${totalFixed} files`);
