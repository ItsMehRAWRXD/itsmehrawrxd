#!/usr/bin/env node

/**
 * RawrZ Complete CLI Examples
 * 
 * This file demonstrates complete CLI usage with all features working via API
 * and shows real-world usage scenarios.
 */

const RawrZStandalone = require('../rawrz-standalone');
const { OpenSSLManager } = require('../src/utils/openssl-manager');
const advancedCrypto = require('../src/engines/advanced-crypto');
const stubGenerator = require('../src/engines/stub-generator');

class RawrZCompleteCLI {
    constructor() {
        this.rawrz = new RawrZStandalone();
        this.opensslManager = new OpenSSLManager();
        this.advancedCrypto = advancedCrypto;
        this.stubGenerator = stubGenerator;
        this.isInitialized = false;
    }

    async initialize() {
        if (!this.isInitialized) {
            await this.opensslManager.initialize();
            this.opensslManager.registerEngine('advanced-crypto', this.advancedCrypto);
            this.opensslManager.registerEngine('stub-generator', this.stubGenerator);
            this.isInitialized = true;
            console.log('✅ RawrZ CLI initialized successfully');
        }
    }

    // Example 1: Complete OpenSSL Management Workflow
    async demonstrateOpenSSLWorkflow() {
        console.log('🔐 Complete OpenSSL Management Workflow\n');

        try {
            await this.initialize();

            // Step 1: Check current configuration
            console.log('Step 1: Checking current configuration...');
            const config = this.opensslManager.getConfigSummary();
            console.log('Current config:', JSON.stringify(config, null, 2));
            console.log();

            // Step 2: Toggle OpenSSL mode
            console.log('Step 2: Toggling OpenSSL mode...');
            await this.opensslManager.toggleOpenSSLMode(true);
            console.log('✅ OpenSSL mode enabled');
            console.log();

            // Step 3: Get available algorithms
            console.log('Step 3: Getting available algorithms...');
            const algorithms = this.opensslManager.getAvailableAlgorithms();
            console.log(`Total algorithms: ${algorithms.length}`);
            
            const opensslAlgorithms = this.opensslManager.getOpenSSLAlgorithms();
            console.log(`OpenSSL algorithms: ${opensslAlgorithms.length}`);
            
            const customAlgorithms = this.opensslManager.getCustomAlgorithms();
            console.log(`Custom algorithms: ${customAlgorithms.length}`);
            console.log();

            // Step 4: Test algorithm resolution
            console.log('Step 4: Testing algorithm resolution...');
            const testAlgorithms = ['aes-256-gcm', 'serpent-256-cbc', 'quantum-resistant'];
            
            for (const algorithm of testAlgorithms) {
                const resolved = this.opensslManager.resolveAlgorithm(algorithm);
                console.log(`${algorithm} → ${resolved}`);
            }
            console.log();

            // Step 5: Update algorithm preferences
            console.log('Step 5: Updating algorithm preferences...');
            await this.opensslManager.updateAlgorithmPreference('my-custom-alg', 'aes-256-gcm');
            console.log('✅ Algorithm preference updated');
            console.log();

            // Step 6: Validate engines
            console.log('Step 6: Validating engines...');
            const validation = this.opensslManager.validateEngines();
            console.log('Validation result:', validation);
            console.log();

            console.log('🎉 OpenSSL workflow completed successfully!');

        } catch (error) {
            console.error('❌ OpenSSL workflow failed:', error.message);
        }
    }

    // Example 2: Advanced Stub Generation with All Options
    async demonstrateAdvancedStubGeneration() {
        console.log('🏗️ Advanced Stub Generation with All Options\n');

        try {
            await this.initialize();

            const target = 'advanced-demo.exe';
            const options = {
                // Encryption options
                encryptionMethod: 'aes-256-gcm',
                
                // Stub type
                stubType: 'cpp',
                
                // Anti-analysis features
                includeAntiDebug: true,
                includeAntiVM: true,
                includeAntiSandbox: true,
                
                // Advanced options
                polymorphic: true,
                selfModifying: true,
                encryptedStrings: true,
                controlFlowFlattening: true,
                deadCodeInjection: true,
                
                // Obfuscation
                obfuscationLevel: 'extreme',
                
                // Packing
                packingMethod: 'upx',
                
                // Stealth
                stealth: {
                    processHollowing: true,
                    dllInjection: true,
                    reflectiveLoading: true
                },
                
                // Anti-analysis
                antiAnalysis: {
                    antiDebugger: true,
                    antiVM: true,
                    antiSandbox: true,
                    antiEmulation: true
                },
                
                // Target platform
                target: 'windows'
            };

            console.log('Generating advanced stub with options:');
            console.log(JSON.stringify(options, null, 2));
            console.log();

            const result = await this.stubGenerator.generateStub(target, options);
            
            if (result.success) {
                console.log('✅ Advanced stub generated successfully!');
                console.log('Result:', JSON.stringify(result, null, 2));
            } else {
                console.log('❌ Advanced stub generation failed');
            }
            console.log();

        } catch (error) {
            console.error('❌ Advanced stub generation failed:', error.message);
        }
    }

    // Example 3: Complete Encryption Workflow
    async demonstrateEncryptionWorkflow() {
        console.log('🔐 Complete Encryption Workflow\n');

        try {
            await this.initialize();

            const testData = 'This is sensitive data that needs to be encrypted securely.';
            
            // Step 1: Test OpenSSL-compatible encryption
            console.log('Step 1: Testing OpenSSL-compatible encryption...');
            await this.opensslManager.toggleOpenSSLMode(true);
            await this.opensslManager.toggleCustomAlgorithms(false);
            
            const opensslResult = await this.advancedCrypto.encrypt(testData, {
                algorithm: 'aes-256-gcm',
                dataType: 'text',
                encoding: 'utf8',
                outputFormat: 'hex',
                compression: true,
                obfuscation: true
            });
            
            console.log('✅ OpenSSL encryption successful');
            console.log('Algorithm:', opensslResult.algorithm);
            console.log('Encrypted length:', opensslResult.encrypted.length);
            console.log();

            // Step 2: Test custom algorithm encryption
            console.log('Step 2: Testing custom algorithm encryption...');
            await this.opensslManager.toggleCustomAlgorithms(true);
            
            const customResult = await this.advancedCrypto.encrypt(testData, {
                algorithm: 'quantum-resistant',
                dataType: 'text',
                encoding: 'utf8',
                outputFormat: 'hex'
            });
            
            console.log('✅ Custom encryption successful');
            console.log('Algorithm:', customResult.algorithm);
            console.log('Encrypted length:', customResult.encrypted.length);
            console.log();

            // Step 3: Test algorithm resolution
            console.log('Step 3: Testing algorithm resolution...');
            const resolvedAlgorithm = this.opensslManager.resolveAlgorithm('serpent-256-cbc');
            console.log(`serpent-256-cbc resolves to: ${resolvedAlgorithm}`);
            
            const resolvedResult = await this.advancedCrypto.encrypt(testData, {
                algorithm: resolvedAlgorithm
            });
            
            console.log('✅ Resolved algorithm encryption successful');
            console.log();

            // Step 4: Test decryption
            console.log('Step 4: Testing decryption...');
            const decrypted = await this.advancedCrypto.decrypt(opensslResult.encrypted, {
                algorithm: opensslResult.algorithm,
                key: opensslResult.key,
                iv: opensslResult.iv,
                authTag: opensslResult.authTag,
                dataType: 'text',
                encoding: 'utf8'
            });
            
            console.log('✅ Decryption successful');
            console.log('Decrypted data matches original:', decrypted === testData);
            console.log();

            console.log('🎉 Encryption workflow completed successfully!');

        } catch (error) {
            console.error('❌ Encryption workflow failed:', error.message);
        }
    }

    // Example 4: Network Operations
    async demonstrateNetworkOperations() {
        console.log('🌐 Network Operations Demonstration\n');

        try {
            // Step 1: Ping test
            console.log('Step 1: Testing ping...');
            const pingResult = await this.rawrz.ping('google.com', false);
            console.log('Ping result:', pingResult);
            console.log();

            // Step 2: DNS lookup
            console.log('Step 2: Testing DNS lookup...');
            const dnsResult = await this.rawrz.dnsLookup('google.com');
            console.log('DNS result:', dnsResult);
            console.log();

            // Step 3: Port scan implementation
            console.log('Step 3: Simulating port scan...');
            const portScanResult = await this.rawrz.processCommand(['portscan', '127.0.0.1', '80', '443']);
            console.log('Port scan result:', portScanResult);
            console.log();

            // Step 4: Network analysis
            console.log('Step 4: Network analysis...');
            const networkResult = await this.rawrz.processCommand(['network', 'analyze', '127.0.0.1']);
            console.log('Network analysis result:', networkResult);
            console.log();

            console.log('🎉 Network operations completed successfully!');

        } catch (error) {
            console.error('❌ Network operations failed:', error.message);
        }
    }

    // Example 5: File Operations
    async demonstrateFileOperations() {
        console.log('📁 File Operations Demonstration\n');

        try {
            // Step 1: File analysis
            console.log('Step 1: Testing file analysis...');
            const analysisResult = await this.rawrz.analyzeFile('package.json');
            console.log('File analysis result:', analysisResult);
            console.log();

            // Step 2: File encryption
            console.log('Step 2: Testing file encryption...');
            const encryptResult = await this.rawrz.encrypt('aes256', 'package.json', '.enc');
            console.log('File encryption result:', encryptResult);
            console.log();

            // Step 3: File operations
            console.log('Step 3: Testing file operations...');
            const fileOpsResult = await this.rawrz.fileOperations('copy', 'package.json', 'package-copy.json');
            console.log('File operations result:', fileOpsResult);
            console.log();

            // Step 4: List files
            console.log('Step 4: Listing files...');
            const filesResult = await this.rawrz.listFiles();
            console.log('Files result:', filesResult);
            console.log();

            console.log('🎉 File operations completed successfully!');

        } catch (error) {
            console.error('❌ File operations failed:', error.message);
        }
    }

    // Example 6: Complete Security Workflow
    async demonstrateSecurityWorkflow() {
        console.log('🛡️ Complete Security Workflow\n');

        try {
            await this.initialize();

            const target = 'security-demo.exe';
            const sensitiveData = 'This is highly sensitive information that needs maximum protection.';

            // Step 1: Configure maximum security
            console.log('Step 1: Configuring maximum security...');
            await this.opensslManager.toggleOpenSSLMode(true);
            await this.opensslManager.toggleCustomAlgorithms(true);
            console.log('✅ Security configuration set to maximum');
            console.log();

            // Step 2: Encrypt sensitive data
            console.log('Step 2: Encrypting sensitive data...');
            const encryptedData = await this.advancedCrypto.encrypt(sensitiveData, {
                algorithm: 'aes-256-gcm',
                compression: true,
                obfuscation: true,
                metadata: {
                    securityLevel: 'maximum',
                    timestamp: new Date().toISOString(),
                    user: 'security-demo'
                }
            });
            console.log('✅ Sensitive data encrypted');
            console.log();

            // Step 3: Generate secure stub
            console.log('Step 3: Generating secure stub...');
            const secureStubOptions = {
                encryptionMethod: 'aes-256-gcm',
                stubType: 'cpp',
                includeAntiDebug: true,
                includeAntiVM: true,
                includeAntiSandbox: true,
                polymorphic: true,
                selfModifying: true,
                encryptedStrings: true,
                controlFlowFlattening: true,
                deadCodeInjection: true,
                obfuscationLevel: 'extreme',
                packingMethod: 'upx',
                stealth: {
                    processHollowing: true,
                    dllInjection: true,
                    reflectiveLoading: true
                },
                antiAnalysis: {
                    antiDebugger: true,
                    antiVM: true,
                    antiSandbox: true,
                    antiEmulation: true,
                    antiAnalysis: true,
                    antiDisassembly: true,
                    antiDecompilation: true
                },
                target: 'windows'
            };

            const secureStub = await this.stubGenerator.generateStub(target, secureStubOptions);
            console.log('✅ Secure stub generated');
            console.log();

            // Step 4: Generate security report
            console.log('Step 4: Generating security report...');
            const securityReport = {
                timestamp: new Date().toISOString(),
                securityLevel: 'maximum',
                configuration: {
                    openssl: {
                        mode: 'enabled',
                        customAlgorithms: 'enabled',
                        availableAlgorithms: this.opensslManager.getAvailableAlgorithms().length
                    },
                    encryption: {
                        algorithm: encryptedData.algorithm,
                        keySize: encryptedData.key.length * 2,
                        compression: true,
                        obfuscation: true
                    },
                    stub: {
                        type: secureStubOptions.stubType,
                        antiAnalysis: Object.keys(secureStubOptions.antiAnalysis).length,
                        stealth: Object.keys(secureStubOptions.stealth).length,
                        obfuscation: secureStubOptions.obfuscationLevel,
                        packing: secureStubOptions.packingMethod
                    }
                },
                results: {
                    dataEncryption: 'success',
                    stubGeneration: secureStub.success ? 'success' : 'failed'
                },
                recommendations: [
                    'Use OpenSSL-compatible algorithms for maximum compatibility',
                    'Enable all anti-analysis features for production use',
                    'Use extreme obfuscation for sensitive applications',
                    'Implement stealth techniques for advanced evasion',
                    'Regularly update encryption keys and algorithms'
                ]
            };

            console.log('📋 Security Report:');
            console.log(JSON.stringify(securityReport, null, 2));
            console.log();

            console.log('🎉 Security workflow completed successfully!');

        } catch (error) {
            console.error('❌ Security workflow failed:', error.message);
        }
    }

    // Example 7: Performance Testing
    async demonstratePerformanceTesting() {
        console.log('⚡ Performance Testing Demonstration\n');

        try {
            await this.initialize();

            const testData = 'Performance test data for encryption benchmarking.';
            const iterations = 100;

            // Test 1: OpenSSL algorithms performance
            console.log('Test 1: OpenSSL algorithms performance...');
            await this.opensslManager.toggleOpenSSLMode(true);
            await this.opensslManager.toggleCustomAlgorithms(false);
            
            const opensslAlgorithms = this.opensslManager.getOpenSSLAlgorithms().slice(0, 5);
            const opensslResults = {};

            for (const algorithm of opensslAlgorithms) {
                const startTime = Date.now();
                
                for (let i = 0; i < iterations; i++) {
                    await this.advancedCrypto.encrypt(testData, { algorithm });
                }
                
                const endTime = Date.now();
                const duration = endTime - startTime;
                const avgTime = duration / iterations;
                
                opensslResults[algorithm] = {
                    totalTime: duration,
                    averageTime: avgTime,
                    iterations: iterations
                };
            }

            console.log('OpenSSL algorithms performance:');
            Object.entries(opensslResults).forEach(([algorithm, result]) => {
                console.log(`  ${algorithm}: ${result.averageTime.toFixed(2)}ms average`);
            });
            console.log();

            // Test 2: Custom algorithms performance
            console.log('Test 2: Custom algorithms performance...');
            await this.opensslManager.toggleCustomAlgorithms(true);
            
            const customAlgorithms = this.opensslManager.getCustomAlgorithms().slice(0, 3);
            const customResults = {};

            for (const algorithm of customAlgorithms) {
                const startTime = Date.now();
                
                for (let i = 0; i < iterations; i++) {
                    await this.advancedCrypto.encrypt(testData, { algorithm });
                }
                
                const endTime = Date.now();
                const duration = endTime - startTime;
                const avgTime = duration / iterations;
                
                customResults[algorithm] = {
                    totalTime: duration,
                    averageTime: avgTime,
                    iterations: iterations
                };
            }

            console.log('Custom algorithms performance:');
            Object.entries(customResults).forEach(([algorithm, result]) => {
                console.log(`  ${algorithm}: ${result.averageTime.toFixed(2)}ms average`);
            });
            console.log();

            // Test 3: Stub generation performance
            console.log('Test 3: Stub generation performance...');
            const stubOptions = {
                encryptionMethod: 'aes-256-gcm',
                stubType: 'cpp',
                includeAntiDebug: true,
                includeAntiVM: true
            };

            const stubStartTime = Date.now();
            const stubResult = await this.stubGenerator.generateStub('perf-test.exe', stubOptions);
            const stubEndTime = Date.now();
            const stubDuration = stubEndTime - stubStartTime;

            console.log(`Stub generation time: ${stubDuration}ms`);
            console.log();

            // Generate performance report
            const performanceReport = {
                timestamp: new Date().toISOString(),
                testConfiguration: {
                    iterations: iterations,
                    testDataLength: testData.length,
                    algorithms: {
                        openssl: opensslAlgorithms.length,
                        custom: customAlgorithms.length
                    }
                },
                results: {
                    openssl: opensslResults,
                    custom: customResults,
                    stubGeneration: {
                        duration: stubDuration,
                        success: stubResult.success
                    }
                },
                summary: {
                    fastestOpenSSL: Object.entries(opensslResults).reduce((a, b) => 
                        a[1].averageTime < b[1].averageTime ? a : b
                    ),
                    fastestCustom: Object.entries(customResults).reduce((a, b) => 
                        a[1].averageTime < b[1].averageTime ? a : b
                    )
                }
            };

            console.log('📊 Performance Report:');
            console.log(JSON.stringify(performanceReport, null, 2));
            console.log();

            console.log('🎉 Performance testing completed successfully!');

        } catch (error) {
            console.error('❌ Performance testing failed:', error.message);
        }
    }

    // Run all demonstrations
    async runAllDemonstrations() {
        console.log('🚀 RawrZ Complete CLI Demonstrations\n');
        console.log('=' .repeat(60));
        console.log();

        try {
            await this.demonstrateOpenSSLWorkflow();
            console.log();
            
            await this.demonstrateAdvancedStubGeneration();
            console.log();
            
            await this.demonstrateEncryptionWorkflow();
            console.log();
            
            await this.demonstrateNetworkOperations();
            console.log();
            
            await this.demonstrateFileOperations();
            console.log();
            
            await this.demonstrateSecurityWorkflow();
            console.log();
            
            await this.demonstratePerformanceTesting();
            console.log();

            console.log('🎉 All CLI demonstrations completed successfully!');

        } catch (error) {
            console.error('❌ CLI demonstrations failed:', error.message);
        }
    }
}

// Usage examples
async function runCompleteCLIExamples() {
    const cli = new RawrZCompleteCLI();
    await cli.runAllDemonstrations();
}

// Run if called directly
if (require.main === module) {
    runCompleteCLIExamples().catch(error => {
        console.error('❌ Complete CLI examples failed:', error.message);
        process.exit(1);
    });
}

module.exports = { RawrZCompleteCLI };
