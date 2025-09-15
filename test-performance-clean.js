#!/usr/bin/env node

/**
 * Performance Test Suite for RawrZ Security Platform
 * Tests performance, memory usage, and scalability
 */

const fs = require('fs').promises;
const path = require('path');
const { performance } = require('perf_hooks');

class PerformanceTestSuite {
    constructor() {
        this.results = {
            tests: [],
            benchmarks: {
                initialization: [],
                encryption: [],
                decryption: [],
                generation: [],
                analysis: []
            }
        };
    }

    async run() {
        console.log('RawrZ Performance Test Suite');
        console.log('=' .repeat(60));
        
        await this.testInitializationPerformance();
        await this.testEncryptionPerformance();
        await this.testGenerationPerformance();
        await this.testAnalysisPerformance();
        await this.testMemoryUsage();
        await this.testConcurrentOperations();
        
        this.generateReport();
    }

    async testInitializationPerformance() {
        console.log('\nTesting Initialization Performance...');
        
        const engines = [
            { name: 'Core Engine', path: './rawrz-standalone' },
            { name: 'HTTP Bot Generator', path: './src/engines/http-bot-generator' },
            { name: 'Stub Generator', path: './src/engines/stub-generator' },
            { name: 'Advanced Stub Generator', path: './src/engines/advanced-stub-generator' },
            { name: 'Anti-Analysis', path: './src/engines/anti-analysis' },
            { name: 'Network Tools', path: './src/engines/network-tools' }
        ];

        for (const engine of engines) {
            try {
                const start = performance.now();
                const EngineClass = require(engine.path);
                const engineInstance = new EngineClass();
                
                if (typeof engineInstance.initialize === 'function') {
                    await engineInstance.initialize({});
                }
                
                const duration = performance.now() - start;
                this.results.benchmarks.initialization.push({
                    name: engine.name,
                    duration: Math.round(duration * 100) / 100
                });
                
                console.log('  TIME: ' + engine.name + ': ' + Math.round(duration * 100) / 100 + 'ms');
                
            } catch (error) {
                console.log('  FAIL ' + engine.name + ': Failed - ' + error.message);
            }
        }
    }

    async testEncryptionPerformance() {
        console.log(' Testing Encryption Performance...'); 
        
        const testData = 'This is a test string for encryption performance testing. '.repeat(100);
        const algorithms = ['aes256', 'aes192', 'aes128', 'chacha20-poly1305'];
        
        try {
            const RawrZStandalone = require('./rawrz-standalone');
            const rawrz = new RawrZStandalone();
            await rawrz.initialize();
            
            for (const algorithm of algorithms) {
                try {
                    // Test encryption
                    const encryptStart = performance.now();
                    const encrypted = await rawrz.encrypt(algorithm, testData);
                    const encryptDuration = performance.now() - encryptStart;
                    
                    // Test decryption
                    const decryptStart = performance.now();
                    const decrypted = await rawrz.decrypt(algorithm, encrypted.encrypted, encrypted.key);
                    const decryptDuration = performance.now() - decryptStart;
                    
                    this.results.benchmarks.encryption.push({
                        algorithm,
                        encryptDuration: Math.round(encryptDuration * 100) / 100,
                        decryptDuration: Math.round(decryptDuration * 100) / 100,
                        totalDuration: Math.round((encryptDuration + decryptDuration) * 100) / 100
                    });
                    
                    console.log('   ' + algorithm + ': Encrypt ' + Math.round(encryptDuration * 100) / 100 + 'ms, Decrypt ' + Math.round(decryptDuration * 100) / 100 + 'ms');
                    
                } catch (error) {
                    console.log('  FAIL ' + algorithm + ': Failed - ' + error.message);
                }
            }
            
        } catch (error) {
            console.log('  FAIL Encryption tests failed: ' + error.message);
        }
    }

    async testGenerationPerformance() {
        console.log('\n  Testing Generation Performance...');
        
        try {
            // Test HTTP Bot Generation
            const HTTPBotGenerator = require('./src/engines/http-bot-generator');
            const httpBotGen = new HTTPBotGenerator();
            await httpBotGen.initialize({});
            
            const botStart = performance.now();
            const botResult = await httpBotGen.generateBot({
                language: 'javascript',
                features: ['keylogger', 'screenshot'],
                serverUrl: 'http://localhost:8080'
            });
            const botDuration = performance.now() - botStart;
            
            this.results.benchmarks.generation.push({
                type: 'HTTP Bot',
                duration: Math.round(botDuration * 100) / 100
            });
            
            console.log('  HTTP Bot Generation: ' + Math.round(botDuration * 100) / 100 + 'ms');
            
            // Test Stub Generation
            const StubGenerator = require('./src/engines/stub-generator');
            const stubGen = new StubGenerator();
            await stubGen.initialize({});
            
            const stubStart = performance.now();
            const stubResult = await stubGen.generateStub({
                template: 'minimal-stub',
                language: 'cpp',
                encryption: 'aes256'
            });
            const stubDuration = performance.now() - stubStart;
            
            this.results.benchmarks.generation.push({
                type: 'Stub',
                duration: Math.round(stubDuration * 100) / 100
            });
            
            console.log('  Stub Generation: ' + Math.round(stubDuration * 100) / 100 + 'ms');
            
        } catch (error) {
            console.log('  FAIL Generation tests failed: ' + error.message);
        }
    }

    async testAnalysisPerformance() {
        console.log('\n Testing Analysis Performance...');
        
        try {
            // Test Anti-Analysis
            const AntiAnalysis = require('./src/engines/anti-analysis');
            const antiAnalysis = new AntiAnalysis();
            await antiAnalysis.initialize({});
            
            const vmStart = performance.now();
            const vmResult = await antiAnalysis.checkVM();
            const vmDuration = performance.now() - vmStart;
            
            this.results.benchmarks.analysis.push({
                type: 'VM Detection',
                duration: Math.round(vmDuration * 100) / 100
            });
            
            console.log('    VM Detection: ' + Math.round(vmDuration * 100) / 100 + 'ms');
            
            // Test Network Analysis
            const NetworkTools = require('./src/engines/network-tools');
            const networkTools = new NetworkTools();
            await networkTools.initialize({});
            
            const networkStart = performance.now();
            const networkResult = await networkTools.portScan('localhost', [80, 443, 22]);
            const networkDuration = performance.now() - networkStart;
            
            this.results.benchmarks.analysis.push({
                type: 'Port Scan',
                duration: Math.round(networkDuration * 100) / 100
            });
            
            console.log('   Port Scan: ' + Math.round(networkDuration * 100) / 100 + 'ms');
            
        } catch (error) {
            console.log('  FAIL Analysis tests failed: ' + error.message);
        }
    }

    async testMemoryUsage() {
        console.log('\n Testing Memory Usage...');
        
        const memBefore = process.memoryUsage();
        
        try {
            // Initialize multiple engines
            const engines = [];
            const enginePaths = [
                './src/engines/http-bot-generator',
                './src/engines/stub-generator',
                './src/engines/anti-analysis',
                './src/engines/network-tools',
                './src/engines/health-monitor'
            ];
            
            for (const enginePath of enginePaths) {
                const EngineClass = require(enginePath);
                const engine = new EngineClass();
                await engine.initialize({});
                engines.push(engine);
            }
            
            const memAfter = process.memoryUsage();
            const memIncrease = memAfter.heapUsed - memBefore.heapUsed;
            const memIncreaseMB = Math.round((memIncrease / 1024 / 1024) * 100) / 100;
            
            this.results.tests.push({
                name: 'Memory Usage',
                result: memIncreaseMB + 'MB increase',
                passed: memIncreaseMB < 100 // Should not use more than 100MB
            });
            
            console.log('   Memory increase: ' + memIncreaseMB + 'MB');
            
        } catch (error) {
            console.log('  FAIL Memory test failed: ' + error.message);
        }
    }

    async testConcurrentOperations() {
        console.log('\n Testing Concurrent Operations...');
        
        try {
            const RawrZStandalone = require('./rawrz-standalone');
            const rawrz = new RawrZStandalone();
            await rawrz.initialize();
            
            // Test concurrent encryption operations
            const concurrentStart = performance.now();
            const promises = [];
            
            for (let i = 0; i < 10; i++) {
                promises.push(rawrz.encrypt('aes256', 'test data ' + i));
            }
            
            await Promise.all(promises);
            const concurrentDuration = performance.now() - concurrentStart;
            
            this.results.tests.push({
                name: 'Concurrent Operations',
                result: Math.round(concurrentDuration * 100) / 100 + 'ms for 10 operations',
                passed: concurrentDuration < 5000 // Should complete within 5 seconds
            });
            
            console.log('   10 concurrent operations: ' + Math.round(concurrentDuration * 100) / 100 + 'ms');
            
        } catch (error) {
            console.log('  FAIL Concurrent test failed: ' + error.message);
        }
    }

    generateReport() {
        console.log('\n' + '='.repeat(60));
        console.log(' PERFORMANCE TEST REPORT');
        console.log('='.repeat(60));
        
        // Initialization benchmarks
        if (this.results.benchmarks.initialization.length > 0) {
            console.log('\n Initialization Performance:');
            this.results.benchmarks.initialization
                .sort((a, b) => a.duration - b.duration)
                .forEach(benchmark => {
                    console.log('  ' + benchmark.name + ': ' + benchmark.duration + 'ms');
                });
        }
        
        // Encryption benchmarks
        if (this.results.benchmarks.encryption.length > 0) {
            console.log('\n Encryption Performance:');
            this.results.benchmarks.encryption
                .sort((a, b) => a.totalDuration - b.totalDuration)
                .forEach(benchmark => {
                    console.log('  ' + benchmark.algorithm + ': ' + benchmark.totalDuration + 'ms (encrypt: ' + benchmark.encryptDuration + 'ms, decrypt: ' + benchmark.decryptDuration + 'ms)');
                });
        }
        
        // Generation benchmarks
        if (this.results.benchmarks.generation.length > 0) {
            console.log('\n  Generation Performance:');
            this.results.benchmarks.generation
                .sort((a, b) => a.duration - b.duration)
                .forEach(benchmark => {
                    console.log('  ' + benchmark.type + ': ' + benchmark.duration + 'ms');
                });
        }
        
        // Analysis benchmarks
        if (this.results.benchmarks.analysis.length > 0) {
            console.log('\n Analysis Performance:');
            this.results.benchmarks.analysis
                .sort((a, b) => a.duration - b.duration)
                .forEach(benchmark => {
                    console.log('  ' + benchmark.type + ': ' + benchmark.duration + 'ms');
                });
        }
        
        // Other tests
        if (this.results.tests.length > 0) {
            console.log('\n Other Performance Tests:');
            this.results.tests.forEach(test => {
                const status = test.passed ? 'PASS' : 'FAIL';
                console.log('  ' + status + ' ' + test.name + ': ' + test.result);
            });
        }
        
        // Save detailed report
        const report = {
            benchmarks: this.results.benchmarks,
            tests: this.results.tests,
            timestamp: new Date().toISOString()
        };
        
        fs.writeFile('performance-report.json', JSON.stringify(report, null, 2))
            .then(() => console.log('\n Detailed report saved to: performance-report.json'))
            .catch(console.error);
    }
}

// Run the performance tests
if (require.main === module) {
    const testSuite = new PerformanceTestSuite();
    testSuite.run().catch(console.error);
}

module.exports = PerformanceTestSuite;
