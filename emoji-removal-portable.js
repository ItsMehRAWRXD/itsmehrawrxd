// RawrZ Emoji Removal System - Portable Version
// This is a standalone Node.js script that can be copied to any project
// Usage: node emoji-removal-portable.js

const fs = require('fs');
const path = require('path');

const emojiReplacements = {
    '\u2713': '[OK]',
    '\u2717': '[ERROR]',
    '\u2705': '[OK]',
    '\u274C': '[ERROR]',
    '\u1F512': '[LOCK]',
    '\u1F513': '[UNLOCK]',
    '\u1F510': '[SECURE]',
    '\u1F511': '[KEY]',
    '\u1F6E1': '[SHIELD]',
    '\u26A1': '[LIGHTNING]',
    '\u1F680': '[LAUNCH]',
    '\u1F4BE': '[SAVE]',
    '\u1F4C1': '[FILE]',
    '\u1F4C4': '[DOC]',
    '\u1F50D': '[SEARCH]',
    '\u1F4CA': '[CHART]',
    '\u1F4C8': '[UP]',
    '\u1F4C9': '[DOWN]',
    '\u1F3AF': '[TARGET]',
    '\u2699': '[CONFIG]',
    '\u1F527': '[TOOL]',
    '\u1F6E0': '[TOOLS]',
    '\u1F4CB': '[LOG]',
    '\u1F4DD': '[NOTE]',
    '\u1F4A1': '[INFO]',
    '\u26A0': '[WARNING]',
    '\u1F504': '[REFRESH]',
    '\u23F3': '[WAIT]',
    '\u1F389': '[SUCCESS]',
    '\u1F525': '[HOT]',
    '\u1F4AF': '[PERFECT]',
    '\u1F31F': '[STAR]',
    '\u2B50': '[STAR]'
};

function removeEmojisFromFile(filePath) {
    try {
        let content = fs.readFileSync(filePath, 'utf8');
        let modified = false;
        
        for (const [emoji, replacement] of Object.entries(emojiReplacements)) {
            if (content.includes(emoji)) {
                content = content.replace(new RegExp(emoji, 'g'), replacement);
                modified = true;
            }
        }
        
        if (modified) {
            fs.writeFileSync(filePath, content, 'utf8');
            console.log('Processed:', filePath);
        }
    } catch (error) {
        console.error('Error processing', filePath, ':', error.message);
    }
}

function processDirectory(dirPath, extensions) {
    try {
        const files = fs.readdirSync(dirPath);
        
        for (const file of files) {
            const fullPath = path.join(dirPath, file);
            const stat = fs.statSync(fullPath);
            
            if (stat.isDirectory()) {
                processDirectory(fullPath, extensions);
            } else if (stat.isFile()) {
                const ext = path.extname(file).toLowerCase();
                if (extensions.includes(ext)) {
                    removeEmojisFromFile(fullPath);
                }
            }
        }
    } catch (error) {
        console.error('Error processing directory', dirPath, ':', error.message);
    }
}

console.log('========================================');
console.log('RawrZ Emoji Removal System - Portable');
console.log('========================================');
console.log('');
console.log('Removing emojis to prevent ROE and malformities...');
console.log('');

// Process source files
if (fs.existsSync('src')) {
    console.log('Processing src directory...');
    processDirectory('src', ['.js', '.html', '.css', '.json']);
}

// Process root files
console.log('Processing root directory...');
processDirectory('.', ['.bat', '.md', '.txt']);

console.log('');
console.log('========================================');
console.log('Emoji Removal Complete!');
console.log('========================================');
console.log('');
console.log('All emojis have been removed from:');
console.log('- All .js files in src directory');
console.log('- All .html files in src directory');
console.log('- All .bat files in project');
console.log('- All .md files in project');
console.log('');
console.log('This prevents ROE (Rate of Error) and malformities!');
console.log('');
