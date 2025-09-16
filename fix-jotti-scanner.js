const fs = require('fs');
const path = require('path');

console.log('Fixing jotti-scanner.js syntax errors...');

const filePath = 'src/engines/jotti-scanner.js';
let content = fs.readFileSync(filePath, 'utf8');

// Fix malformed operators (backticks instead of angle brackets)
content = content.replace(/>`/g, '>');
content = content.replace(/<`/g, '<');
content = content.replace(/>=`/g, '>=');
content = content.replace(/<=`/g, '<=');

// Fix malformed template literals by replacing with string concatenation
content = content.replace(/`\$\{([^}]+)\}`/g, "' + $1 + '");
content = content.replace(/`\$\{([^}]+)\}([^`]*)\$\{([^}]+)\}`/g, "' + $1 + '$2' + $3 + '");

// Fix specific patterns found in the file
content = content.replace(/`\$\{this\.baseUrl\}\$\{this\.resultsEndpoint\}\/jobId`/g, "this.baseUrl + this.resultsEndpoint + '/jobId'");
content = content.replace(/`\$\{this\.baseUrl\}\/en\/filescanresult\/jobId`/g, "this.baseUrl + '/en/filescanresult/jobId'");

// Fix malformed RegExp with template literals
content = content.replace(/new RegExp\(`\$\{([^}]+)\}([^`]+)`/g, "new RegExp($1 + '$2'");

// Fix any remaining malformed template literals in function calls
content = content.replace(/fetch\(`\$\{([^}]+)\}([^`]*)\$\{([^}]+)\}`/g, "fetch($1 + '$2' + $3 + '");

console.log('Fixed malformed operators and template literals');

// Write the fixed content back
fs.writeFileSync(filePath, content, 'utf8');

console.log('jotti-scanner.js has been fixed!');
