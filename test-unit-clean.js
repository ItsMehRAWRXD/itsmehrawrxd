#!/usr/bin/env node

/**
 * Unit Test Suite for Individual RawrZ Engines
 * Quick tests for individual engine functionality
 */

const fs = require('fs').promises;
const path = require('path');

class UnitTestSuite {
    constructor() {
        this.results = {
            passed: 0,
            failed: 0,
            total: 0,
            tests: []
        };
    }

    async run() {
        console.log('RawrZ Engine Unit Tests');
        console.log('=' .repeat(50));
        
        // Test individual engines
        await this.testEngine('Core Engine', './rawrz-standalone');
        await this.testEngine('HTTP Bot Generator', './src/engines/http-bot-generator');
        await this.testEngine('Stub Generator', './src/engines/stub-generator');
        await this.testEngine('Advanced Stub Generator', './src/engines/advanced-stub-generator');
        await this.testEngine('Anti-Analysis', './src/engines/anti-analysis');
        await this.testEngine('Hot Patchers', './src/engines/hot-patchers');
        await this.testEngine('Network Tools', './src/engines/network-tools');
        await this.testEngine('Health Monitor', './src/engines/health-monitor');
        await this.testEngine('Digital Forensics', './src/engines/digital-forensics');
        await this.testEngine('Jotti Scanner', './src/engines/jotti-scanner');
        await this.testEngine('Private Virus Scanner', './src/engines/private-virus-scanner');
        await this.testEngine('Malware Analysis', './src/engines/malware-analysis');
        await this.testEngine('Reverse Engineering', './src/engines/reverse-engineering');
        await this.testEngine('Camellia Assembly', './src/engines/camellia-assembly');
        await this.testEngine('Dual Generators', './src/engines/dual-generators');
        await this.testEngine('Stealth Engine', './src/engines/stealth-engine');
        await this.testEngine('Advanced Crypto', './src/engines/advanced-crypto');
        await this.testEngine('Burner Encryption', './src/engines/burner-encryption-engine');
        await this.testEngine('Dual Crypto', './src/engines/dual-crypto-engine');
        await this.testEngine('Custom RawrZ Crypto', './src/engines/custom-rawrz-crypto');
        await this.testEngine('Polymorphic Engine', './src/engines/polymorphic-engine');
        await this.testEngine('Template Generator', './src/engines/template-generator');
        await this.testEngine('Mutex Engine', './src/engines/mutex-engine');
        await this.testEngine('OpenSSL Management', './src/engines/openssl-management');
        await this.testEngine('Compression Engine', './src/engines/compression-engine');
        await this.testEngine('API Status', './src/engines/api-status');
        await this.testEngine('RawrZ Engine 2', './src/engines/RawrZEngine2');
        
        this.generateReport();
    }

    async testEngine(engineName, enginePath) {
        this.results.total++;
        
        try {
            console.log('Testing ' + engineName + '...');
            
            // Check if file exists
            const fullPath = path.resolve(enginePath + '.js');
            await fs.access(fullPath);
            
            // Try to require the module
            const EngineClass = require(enginePath);
            
            // Check if it's a class or has expected methods
            if (typeof EngineClass === 'function') {
                const engine = new EngineClass();
                
                // Test basic properties
                const hasName = engine.name && typeof engine.name === 'string';
                const hasVersion = engine.version && typeof engine.version === 'string';
                
                // Test initialization if method exists
                let initSuccess = true;
                if (typeof engine.initialize === 'function') {
                    try {
                        await engine.initialize({});
                    } catch (error) {
                        initSuccess = false;
                    }
                }
                
                if (hasName && hasVersion && initSuccess) {
                    console.log('  PASS: ' + engineName + ' - OK');
                    this.results.passed++;
                    this.results.tests.push({
                        name: engineName,
                        status: 'PASSED',
                        error: null
                    });
                } else {
                    console.log('  FAIL: ' + engineName + ' - Missing properties or init failed');
                    this.results.failed++;
                    this.results.tests.push({
                        name: engineName,
                        status: 'FAILED',
                        error: 'Missing properties or initialization failed'
                    });
                }
            } else {
                console.log('  FAIL: ' + engineName + ' - Not a class');
                this.results.failed++;
                this.results.tests.push({
                    name: engineName,
                    status: 'FAILED',
                    error: 'Not a class'
                });
            }
            
        } catch (error) {
            console.log('  FAIL: ' + engineName + ' - ' + error.message);
            this.results.failed++;
            this.results.tests.push({
                name: engineName,
                status: 'FAILED',
                error: error.message
            });
        }
    }

    generateReport() {
        const successRate = ((this.results.passed / this.results.total) * 100).toFixed(2);
        
        console.log('\n' + '='.repeat(50));
        console.log('UNIT TEST REPORT');
        console.log('='.repeat(50));
        console.log('Success Rate: ' + successRate + '%');
        console.log('Passed: ' + this.results.passed);
        console.log('Failed: ' + this.results.failed);
        console.log('Total Tests: ' + this.results.total);
        
        if (this.results.failed > 0) {
            console.log('\nFAILED TESTS:');
            this.results.tests
                .filter(test => test.status === 'FAILED')
                .forEach(test => {
                    console.log('  • ' + test.name + ': ' + test.error);
                });
        }
        
        process.exit(this.results.failed > 0 ? 1 : 0);
    }
}

// Run the unit tests
if (require.main === module) {
    const testSuite = new UnitTestSuite();
    testSuite.run().catch(console.error);
}

module.exports = UnitTestSuite;
