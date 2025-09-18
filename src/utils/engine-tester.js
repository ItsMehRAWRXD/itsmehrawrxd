const fs = require('fs');
const path = require('path');

class EngineTester {
    constructor() {
        this.enginesDir = './src/engines';
        this.results = {};
    }
    
    async testAllEngines() {
        console.log('🧪 Testing all RawrZ engines...');
        
        const engineFiles = fs.readdirSync(this.enginesDir).filter(file => file.endsWith('.js'));
        
        for (const file of engineFiles) {
            const engineName = file.replace('.js', '');
            console.log(`\n🔍 Testing ${engineName}...`);
            
            try {
                const enginePath = path.join(this.enginesDir, file);
                const engine = require(enginePath);
                
                // Test basic functionality
                const tests = await this.runEngineTests(engine, engineName);
                this.results[engineName] = tests;
                
                console.log(`✅ ${engineName}: ${tests.passed}/${tests.total} tests passed`);
            } catch (error) {
                console.log(`❌ ${engineName}: Test failed - ${error.message}`);
                this.results[engineName] = { error: error.message, passed: 0, total: 0 };
            }
        }
        
        this.generateReport();
    }
    
    async runEngineTests(engine, engineName) {
        const tests = { passed: 0, total: 0, details: [] };
        
        // Test 1: Check if engine has required methods
        const requiredMethods = ['initialize', 'getStatus'];
        for (const method of requiredMethods) {
            tests.total++;
            if (typeof engine[method] === 'function') {
                tests.passed++;
                tests.details.push(`✅ ${method} method exists`);
            } else {
                tests.details.push(`❌ ${method} method missing`);
            }
        }
        
        // Test 2: Test initialization
        if (typeof engine.initialize === 'function') {
            tests.total++;
            try {
                await engine.initialize();
                tests.passed++;
                tests.details.push('✅ Engine initialized successfully');
            } catch (error) {
                tests.details.push(`❌ Engine initialization failed: ${error.message}`);
            }
        }
        
        // Test 3: Test status method
        if (typeof engine.getStatus === 'function') {
            tests.total++;
            try {
                const status = engine.getStatus();
                if (status && typeof status === 'object') {
                    tests.passed++;
                    tests.details.push('✅ Status method works correctly');
                } else {
                    tests.details.push('❌ Status method returned invalid data');
                }
            } catch (error) {
                tests.details.push(`❌ Status method failed: ${error.message}`);
            }
        }
        
        return tests;
    }
    
    generateReport() {
        console.log('\n' + '=' .repeat(80));
        console.log('🧪 ENGINE TESTING REPORT');
        console.log('=' .repeat(80));
        
        const totalEngines = Object.keys(this.results).length;
        const passedEngines = Object.values(this.results).filter(r => r.passed > 0).length;
        const totalTests = Object.values(this.results).reduce((sum, r) => sum + (r.total || 0), 0);
        const passedTests = Object.values(this.results).reduce((sum, r) => sum + (r.passed || 0), 0);
        
        console.log(`\n📊 Summary:`);
        console.log(`   Engines tested: ${totalEngines}`);
        console.log(`   Engines passed: ${passedEngines}`);
        console.log(`   Total tests: ${totalTests}`);
        console.log(`   Tests passed: ${passedTests}`);
        console.log(`   Success rate: ${totalTests > 0 ? Math.round((passedTests / totalTests) * 100) : 0}%`);
        
        console.log('\n📋 Detailed Results:');
        Object.entries(this.results).forEach(([engine, result]) => {
            if (result.error) {
                console.log(`\n❌ ${engine}: ${result.error}`);
            } else {
                console.log(`\n✅ ${engine}: ${result.passed}/${result.total} tests passed`);
                result.details.forEach(detail => {
                    console.log(`   ${detail}`);
                });
            }
        });
        
        console.log('\n' + '=' .repeat(80));
    }
}

module.exports = new EngineTester();
