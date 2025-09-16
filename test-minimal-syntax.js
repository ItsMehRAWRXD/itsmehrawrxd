// Minimal test to identify remaining syntax issues
const fs = require('fs');

function testMinimalSyntax() {
    console.log('=== TESTING MINIMAL SYNTAX STRUCTURE ===\n');
    
    try {
        const content = fs.readFileSync('src/engines/advanced-fud-engine.js', 'utf8');
        
        // Create a minimal version with just the class structure
        const minimalContent = `
const { promisify } = require('util');
const { exec } = require('child_process');
const { logger } = require('../utils/logger');

const execAsync = promisify(exec);

class AdvancedFUDEngine {
    constructor() {
        this.initialized = false;
    }
    
    async initialize() {
        this.initialized = true;
        return true;
    }
}

// Create and export instance
const advancedFUDEngine = new AdvancedFUDEngine();
module.exports = advancedFUDEngine;
`;
        
        // Test the minimal version
        fs.writeFileSync('test-minimal.js', minimalContent, 'utf8');
        
        const { execSync } = require('child_process');
        try {
            execSync('node -c test-minimal.js', { stdio: 'pipe' });
            console.log('✓ Minimal syntax structure is valid');
            
            // Now test with just the problematic method
            const problematicMethod = `
    async obfuscateAllAPICalls(code, language) {
        return code.replace(/(\\w+)\\(/g, (match, apiName) => {
            return match;
        });
    }
`;
            
            const testContent = minimalContent.replace('async initialize() {', 
                problematicMethod + '\n    async initialize() {');
            
            fs.writeFileSync('test-method.js', testContent, 'utf8');
            execSync('node -c test-method.js', { stdio: 'pipe' });
            console.log('✓ Problematic method syntax is valid');
            
        } catch (error) {
            console.log('✗ Syntax error in minimal test:');
            console.log(error.stdout.toString());
        }
        
        // Clean up test files
        try {
            fs.unlinkSync('test-minimal.js');
            fs.unlinkSync('test-method.js');
        } catch (e) {}
        
    } catch (error) {
        console.error('Error in minimal syntax test:', error.message);
    }
}

testMinimalSyntax();
