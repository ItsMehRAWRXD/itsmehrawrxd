#!/usr/bin/env node

/**
 * Comprehensive Stub Generator Test Suite
 * Tests all stub generators for functionality and error handling
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

// Import all stub generators
const StubGenerator = require('./src/engines/stub-generator');
const AdvancedStubGenerator = require('./src/engines/advanced-stub-generator');
const CamelliaAssemblyEngine = require('./src/engines/camellia-assembly');
const advancedCrypto = require('./src/engines/advanced-crypto');
const dualCryptoEngine = require('./src/engines/dual-crypto-engine');

class StubGeneratorTester {
    constructor() {
        this.stubGenerator = new StubGenerator();
        this.advancedStubGenerator = new AdvancedStubGenerator();
        this.camelliaEngine = new CamelliaAssemblyEngine();
        this.advancedCrypto = advancedCrypto;
        this.dualCryptoEngine = dualCryptoEngine;
        
        this.testResults = [];
        this.outputDir = './stub_test_output';
    }

    async initialize() {
        console.log('🚀 Initializing Stub Generator Test Suite...');
        
        try {
            // Initialize all engines
            await this.stubGenerator.initialize();
            await this.advancedStubGenerator.initialize();
            await this.camelliaEngine.initialize();
            await this.advancedCrypto.initialize();
            await this.dualCryptoEngine.initialize();
            
            // Create output directory
            await fs.mkdir(this.outputDir, { recursive: true });
            
            console.log('✅ All engines initialized successfully');
            return true;
        } catch (error) {
            console.error('❌ Initialization failed:', error.message);
            return false;
        }
    }

    async testStubGenerator() {
        console.log('\n📝 Testing Basic Stub Generator...');
        
        try {
            const testData = Buffer.from('Test payload for stub generation', 'utf8');
            const options = {
                encryptionMethod: 'aes-256-gcm',
                stubType: 'cpp',
                includeAntiDebug: true,
                includeAntiVM: true,
                obfuscationLevel: 'basic'
            };
            
            const result = await this.stubGenerator.generateStub(testData, options);
            
            // Save result
            const outputPath = path.join(this.outputDir, 'basic_stub_result.json');
            await fs.writeFile(outputPath, JSON.stringify(result, null, 2));
            
            console.log('✅ Basic Stub Generator test passed');
            console.log(`   Output saved to: ${outputPath}`);
            
            this.testResults.push({
                generator: 'StubGenerator',
                status: 'PASS',
                outputPath: outputPath,
                result: result
            });
            
            return true;
        } catch (error) {
            console.error('❌ Basic Stub Generator test failed:', error.message);
            this.testResults.push({
                generator: 'StubGenerator',
                status: 'FAIL',
                error: error.message
            });
            return false;
        }
    }

    async testAdvancedStubGenerator() {
        console.log('\n🔥 Testing Advanced Stub Generator...');
        
        try {
            const options = {
                templateId: 'godlike-stub',
                language: 'cpp',
                platform: 'windows',
                encryptionMethods: ['camellia-256-cbc', 'aes-256-gcm'],
                packingMethod: 'custom',
                obfuscationLevel: 'godlike',
                customFeatures: ['anti-debug', 'anti-vm', 'polymorphic'],
                serverUrl: 'http://localhost:8080',
                botId: crypto.randomUUID()
            };
            
            const result = await this.advancedStubGenerator.generateStub(options);
            
            // Save result
            const outputPath = path.join(this.outputDir, 'advanced_stub_result.json');
            await fs.writeFile(outputPath, JSON.stringify(result, null, 2));
            
            console.log('✅ Advanced Stub Generator test passed');
            console.log(`   Output saved to: ${outputPath}`);
            
            this.testResults.push({
                generator: 'AdvancedStubGenerator',
                status: 'PASS',
                outputPath: outputPath,
                result: result
            });
            
            return true;
        } catch (error) {
            console.error('❌ Advanced Stub Generator test failed:', error.message);
            this.testResults.push({
                generator: 'AdvancedStubGenerator',
                status: 'FAIL',
                error: error.message
            });
            return false;
        }
    }

    async testCamelliaAssemblyEngine() {
        console.log('\n⚡ Testing Camellia Assembly Engine...');
        
        try {
            const testData = Buffer.from('Test data for Camellia encryption', 'utf8');
            const key = crypto.randomBytes(32);
            const iv = crypto.randomBytes(16);
            
            // Test different formats
            const formats = ['assembly', 'cpp', 'csharp', 'c'];
            const results = {};
            
            for (const format of formats) {
                try {
                    const stubOptions = {
                        algorithm: 'camellia-256-cbc',
                        key: key,
                        iv: iv,
                        format: format
                    };
                    
                    const stub = this.camelliaEngine.generateStub(stubOptions);
                    results[format] = stub;
                    
                    // Save individual format results
                    const outputPath = path.join(this.outputDir, `camellia_${format}_stub.${format === 'assembly' ? 'asm' : format === 'csharp' ? 'cs' : 'cpp'}`);
                    await fs.writeFile(outputPath, stub);
                    
                    console.log(`   ✅ ${format.toUpperCase()} stub generated`);
                } catch (formatError) {
                    console.log(`   ❌ ${format.toUpperCase()} stub failed: ${formatError.message}`);
                    results[format] = { error: formatError.message };
                }
            }
            
            // Save combined results
            const outputPath = path.join(this.outputDir, 'camellia_assembly_results.json');
            await fs.writeFile(outputPath, JSON.stringify(results, null, 2));
            
            console.log('✅ Camellia Assembly Engine test completed');
            console.log(`   Output saved to: ${outputPath}`);
            
            this.testResults.push({
                generator: 'CamelliaAssemblyEngine',
                status: 'PASS',
                outputPath: outputPath,
                result: results
            });
            
            return true;
        } catch (error) {
            console.error('❌ Camellia Assembly Engine test failed:', error.message);
            this.testResults.push({
                generator: 'CamelliaAssemblyEngine',
                status: 'FAIL',
                error: error.message
            });
            return false;
        }
    }

    async testAdvancedCrypto() {
        console.log('\n🔐 Testing Advanced Crypto Stub Generation...');
        
        try {
            const testData = Buffer.from('Test data for advanced crypto', 'utf8');
            const key = crypto.randomBytes(32);
            const iv = crypto.randomBytes(16);
            
            const options = {
                format: 'exe',
                executableType: 'windows',
                algorithm: 'aes-256-gcm',
                key: key,
                iv: iv,
                authTag: crypto.randomBytes(16)
            };
            
            const result = await this.advancedCrypto.generateStub(testData, options);
            
            // Save result
            const outputPath = path.join(this.outputDir, 'advanced_crypto_stub.json');
            await fs.writeFile(outputPath, JSON.stringify(result, null, 2));
            
            console.log('✅ Advanced Crypto stub generation test passed');
            console.log(`   Output saved to: ${outputPath}`);
            
            this.testResults.push({
                generator: 'AdvancedCrypto',
                status: 'PASS',
                outputPath: outputPath,
                result: result
            });
            
            return true;
        } catch (error) {
            console.error('❌ Advanced Crypto stub generation test failed:', error.message);
            this.testResults.push({
                generator: 'AdvancedCrypto',
                status: 'FAIL',
                error: error.message
            });
            return false;
        }
    }

    async testDualCryptoEngine() {
        console.log('\n🔄 Testing Dual Crypto Engine...');
        
        try {
            const testData = Buffer.from('Test data for dual crypto', 'utf8');
            const keys = {
                primary: crypto.randomBytes(32),
                secondary: crypto.randomBytes(32)
            };
            const ivs = {
                primary: crypto.randomBytes(16),
                secondary: crypto.randomBytes(16)
            };
            
            const options = {
                algorithm: 'dual-aes-camellia',
                keys: keys,
                ivs: ivs,
                fileType: 'exe'
            };
            
            const result = this.dualCryptoEngine.generateDualStub(options);
            
            // Save result
            const outputPath = path.join(this.outputDir, 'dual_crypto_stub.json');
            await fs.writeFile(outputPath, JSON.stringify(result, null, 2));
            
            console.log('✅ Dual Crypto Engine test passed');
            console.log(`   Output saved to: ${outputPath}`);
            
            this.testResults.push({
                generator: 'DualCryptoEngine',
                status: 'PASS',
                outputPath: outputPath,
                result: result
            });
            
            return true;
        } catch (error) {
            console.error('❌ Dual Crypto Engine test failed:', error.message);
            this.testResults.push({
                generator: 'DualCryptoEngine',
                status: 'FAIL',
                error: error.message
            });
            return false;
        }
    }

    async testJSONFormatting() {
        console.log('\n📋 Testing JSON Formatting...');
        
        try {
            // Test all results for valid JSON
            let allValid = true;
            
            for (const result of this.testResults) {
                if (result.status === 'PASS' && result.result) {
                    try {
                        JSON.stringify(result.result);
                        console.log(`   ✅ ${result.generator} JSON is valid`);
                    } catch (jsonError) {
                        console.log(`   ❌ ${result.generator} JSON is invalid: ${jsonError.message}`);
                        allValid = false;
                    }
                }
            }
            
            if (allValid) {
                console.log('✅ All JSON formatting tests passed');
                return true;
            } else {
                console.log('❌ Some JSON formatting tests failed');
                return false;
            }
        } catch (error) {
            console.error('❌ JSON formatting test failed:', error.message);
            return false;
        }
    }

    async generateTestReport() {
        console.log('\n📊 Generating Test Report...');
        
        const report = {
            timestamp: new Date().toISOString(),
            totalTests: this.testResults.length,
            passedTests: this.testResults.filter(r => r.status === 'PASS').length,
            failedTests: this.testResults.filter(r => r.status === 'FAIL').length,
            successRate: (this.testResults.filter(r => r.status === 'PASS').length / this.testResults.length * 100).toFixed(2) + '%',
            results: this.testResults,
            summary: {
                generators: {
                    'StubGenerator': this.testResults.find(r => r.generator === 'StubGenerator')?.status || 'NOT_TESTED',
                    'AdvancedStubGenerator': this.testResults.find(r => r.generator === 'AdvancedStubGenerator')?.status || 'NOT_TESTED',
                    'CamelliaAssemblyEngine': this.testResults.find(r => r.generator === 'CamelliaAssemblyEngine')?.status || 'NOT_TESTED',
                    'AdvancedCrypto': this.testResults.find(r => r.generator === 'AdvancedCrypto')?.status || 'NOT_TESTED',
                    'DualCryptoEngine': this.testResults.find(r => r.generator === 'DualCryptoEngine')?.status || 'NOT_TESTED'
                }
            }
        };
        
        const reportPath = path.join(this.outputDir, 'stub_generator_test_report.json');
        await fs.writeFile(reportPath, JSON.stringify(report, null, 2));
        
        console.log(`✅ Test report generated: ${reportPath}`);
        console.log(`📊 Test Summary:`);
        console.log(`   Total Tests: ${report.totalTests}`);
        console.log(`   Passed: ${report.passedTests}`);
        console.log(`   Failed: ${report.failedTests}`);
        console.log(`   Success Rate: ${report.successRate}`);
        
        return report;
    }

    async runAllTests() {
        try {
            console.log('🚀 RawrZ Stub Generator Test Suite');
            console.log('===================================\n');
            
            // Initialize
            const initialized = await this.initialize();
            if (!initialized) {
                throw new Error('Failed to initialize test suite');
            }
            
            // Run all tests
            await this.testStubGenerator();
            await this.testAdvancedStubGenerator();
            await this.testCamelliaAssemblyEngine();
            await this.testAdvancedCrypto();
            await this.testDualCryptoEngine();
            
            // Test JSON formatting
            await this.testJSONFormatting();
            
            // Generate final report
            const report = await this.generateTestReport();
            
            console.log('\n🎉 All tests completed!');
            console.log(`📁 Output directory: ${this.outputDir}`);
            console.log(`📊 Success rate: ${report.successRate}`);
            
            if (report.failedTests > 0) {
                console.log(`⚠️  ${report.failedTests} test(s) failed - check the report for details`);
                process.exit(1);
            } else {
                console.log('✅ All tests passed successfully!');
                process.exit(0);
            }
            
        } catch (error) {
            console.error('\n❌ Test suite failed:', error.message);
            console.error(error.stack);
            process.exit(1);
        }
    }
}

// Run the test suite
if (require.main === module) {
    const tester = new StubGeneratorTester();
    tester.runAllTests().catch(console.error);
}

module.exports = StubGeneratorTester;
