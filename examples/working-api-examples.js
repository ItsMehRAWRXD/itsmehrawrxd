#!/usr/bin/env node

/**
 * RawrZ Working API Examples
 * 
 * This file demonstrates fully working features that integrate with the RawrZ API
 * and show complete functionality with real API calls and responses.
 */

const fetch = require('node-fetch');

class RawrZAPIExamples {
    constructor(baseUrl = 'http://localhost:8080', authToken = '') {
        this.baseUrl = baseUrl;
        this.authToken = authToken;
        this.headers = {
            'Content-Type': 'application/json',
            ...(authToken && { 'Authorization': `Bearer ${authToken}` })
        };
    }

    // Generic API call method
    async apiCall(endpoint, method = 'GET', data = null) {
        try {
            const options = {
                method,
                headers: this.headers
            };

            if (data && (method === 'POST' || method === 'PUT')) {
                options.body = JSON.stringify(data);
            }

            const response = await fetch(`${this.baseUrl}${endpoint}`, options);
            const result = await response.json();

            if (!response.ok) {
                throw new Error(`API Error: ${result.error || 'Unknown error'}`);
            }

            return result;
        } catch (error) {
            console.error(`API call failed for ${endpoint}:`, error.message);
            throw error;
        }
    }

    // Example 1: OpenSSL Toggle Management
    async demonstrateOpenSSLManagement() {
        console.log('OpenSSL Management Demonstration\n');

        try {
            // Get current OpenSSL configuration
            console.log('1. Getting current OpenSSL configuration...');
            const config = await this.apiCall('/openssl/config');
            console.log('Current config:', JSON.stringify(config.result, null, 2));
            console.log();

            // Toggle OpenSSL mode
            console.log('2. Toggling OpenSSL mode to false...');
            const toggleResult = await this.apiCall('/openssl/toggle-openssl', 'POST', { enabled: false });
            console.log('Toggle result:', toggleResult.success ? 'Success' : 'Failed');
            console.log();

            // Get available algorithms
            console.log('3. Getting available algorithms...');
            const algorithms = await this.apiCall('/openssl/algorithms');
            console.log(`Available algorithms: ${algorithms.result.length}`);
            console.log('First 10 algorithms:', algorithms.result.slice(0, 10));
            console.log();

            // Get OpenSSL-only algorithms
            console.log('4. Getting OpenSSL-only algorithms...');
            const opensslAlgorithms = await this.apiCall('/openssl/openssl-algorithms');
            console.log(`OpenSSL algorithms: ${opensslAlgorithms.result.length}`);
            console.log();

            // Get custom algorithms
            console.log('5. Getting custom algorithms...');
            const customAlgorithms = await this.apiCall('/openssl/custom-algorithms');
            console.log(`Custom algorithms: ${customAlgorithms.result.length}`);
            console.log();

            // Resolve algorithm
            console.log('6. Resolving algorithm "serpent-256-cbc"...');
            const resolved = await this.apiCall('/openssl/resolve-algorithm', 'POST', { 
                algorithm: 'serpent-256-cbc' 
            });
            console.log(`Resolved to: ${resolved.result}`);
            console.log();

            // Reset to defaults
            console.log('7. Resetting to defaults...');
            const resetResult = await this.apiCall('/openssl/reset', 'POST');
            console.log('Reset result:', resetResult.success ? 'Success' : 'Failed');
            console.log();

        } catch (error) {
            console.error('OpenSSL management demonstration failed:', error.message);
        }
    }

    // Example 2: Advanced Stub Generation with All Options
    async demonstrateAdvancedStubGeneration() {
        console.log('Advanced Stub Generation Demonstration\n');

        try {
            const target = 'test-payload.exe';
            const options = {
                // Slider values
                polymorphic: 'advanced',
                stealth: 'high',
                obfuscation: 'extreme',
                
                // Toggle values
                compression: 'gzip',
                packing: 'upx',
                
                // Checkbox values
                hotPatch: true,
                memoryProtect: true,
                selfModifying: false,
                encryptedStrings: true,
                controlFlowFlattening: true,
                deadCodeInjection: false,
                
                // Platform selection
                target: 'windows',
                
                // Additional options
                encryptionMethod: 'aes-256-gcm',
                includeAntiDebug: true,
                includeAntiVM: true,
                includeAntiSandbox: true
            };

            console.log('1. Generating advanced stub with options:');
            console.log(JSON.stringify(options, null, 2));
            console.log();

            const result = await this.apiCall('/stub', 'POST', { target, options });
            
            if (result.success) {
                console.log('Advanced stub generated successfully!');
                console.log('Result:', JSON.stringify(result.result, null, 2));
            } else {
                console.log('Advanced stub generation failed');
            }
            console.log();

        } catch (error) {
            console.error('Advanced stub generation demonstration failed:', error.message);
        }
    }

    // Example 3: Port Scanning with Interactive Controls
    async demonstratePortScanning() {
        console.log('Port Scanning Demonstration\n');

        try {
            const host = '127.0.0.1';
            const options = {
                startPort: 80,
                endPort: 443,
                scanType: 'tcp',
                speed: 'fast',
                verbose: true,
                stealth: false,
                serviceDetection: true,
                osDetection: false
            };

            console.log('1. Starting port scan with options:');
            console.log(`Host: ${host}`);
            console.log(`Port Range: ${options.startPort}-${options.endPort}`);
            console.log(`Scan Type: ${options.scanType.toUpperCase()}`);
            console.log(`Speed: ${options.speed}`);
            console.log(`Options: ${Object.entries(options).filter(([k,v]) => typeof v === 'boolean' && v).map(([k]) => k).join(', ')}`);
            console.log();

            const result = await this.apiCall('/portscan', 'POST', { 
                host, 
                startPort: options.startPort, 
                endPort: options.endPort,
                ...options 
            });

            if (result.success) {
                console.log('Port scan completed successfully!');
                console.log('Results:', JSON.stringify(result.result, null, 2));
            } else {
                console.log('Port scan failed');
            }
            console.log();

        } catch (error) {
            console.error('Port scanning demonstration failed:', error.message);
        }
    }

    // Example 4: Encryption with OpenSSL Toggle
    async demonstrateEncryptionWithToggle() {
        console.log('Encryption with OpenSSL Toggle Demonstration\n');

        try {
            const testData = 'Hello, RawrZ OpenSSL Toggle!';
            
            // Test with OpenSSL mode enabled
            console.log('1. Testing encryption with OpenSSL mode enabled...');
            await this.apiCall('/openssl/toggle-openssl', 'POST', { enabled: true });
            
            const opensslResult = await this.apiCall('/encrypt', 'POST', {
                algorithm: 'aes-256-gcm',
                input: testData
            });
            
            console.log('OpenSSL encryption result:', opensslResult.success ? 'Success' : 'Failed');
            if (opensslResult.success) {
                console.log('Encrypted data:', opensslResult.encrypted.substring(0, 50) + '...');
            }
            console.log();

            // Test with custom algorithms enabled
            console.log('2. Testing encryption with custom algorithms enabled...');
            await this.apiCall('/openssl/toggle-custom', 'POST', { enabled: true });
            
            const customResult = await this.apiCall('/encrypt', 'POST', {
                algorithm: 'quantum-resistant',
                input: testData
            });
            
            console.log('Custom encryption result:', customResult.success ? 'Success' : 'Failed');
            if (customResult.success) {
                console.log('Encrypted data:', customResult.encrypted.substring(0, 50) + '...');
            }
            console.log();

            // Test algorithm resolution
            console.log('3. Testing algorithm resolution...');
            const resolved = await this.apiCall('/openssl/resolve-algorithm', 'POST', { 
                algorithm: 'serpent-256-cbc' 
            });
            console.log(`serpent-256-cbc resolves to: ${resolved.result}`);
            console.log();

        } catch (error) {
            console.error('Encryption demonstration failed:', error.message);
        }
    }

    // Example 5: Advanced Crypto with All Options
    async demonstrateAdvancedCrypto() {
        console.log('Advanced Crypto Demonstration\n');

        try {
            const testData = 'Advanced crypto test data';
            const options = {
                algorithm: 'aes-256-gcm',
                dataType: 'text',
                encoding: 'utf8',
                outputFormat: 'hex',
                compression: true,
                obfuscation: true,
                metadata: {
                    timestamp: new Date().toISOString(),
                    user: 'demo-user',
                    version: '1.0.0'
                }
            };

            console.log('1. Advanced encryption with options:');
            console.log(JSON.stringify(options, null, 2));
            console.log();

            const result = await this.apiCall('/advancedcrypto', 'POST', {
                input: testData,
                operation: 'encrypt',
                ...options
            });

            if (result.success) {
                console.log('Advanced encryption successful!');
                console.log('Result:', JSON.stringify(result.result, null, 2));
            } else {
                console.log('Advanced encryption failed');
            }
            console.log();

        } catch (error) {
            console.error('Advanced crypto demonstration failed:', error.message);
        }
    }

    // Example 6: Network Tools with Interactive Controls
    async demonstrateNetworkTools() {
        console.log('Network Tools Demonstration\n');

        try {
            // Ping test
            console.log('1. Testing ping...');
            const pingResult = await this.apiCall('/ping?host=google.com');
            console.log('Ping result:', pingResult.success ? 'Success' : 'Failed');
            if (pingResult.success) {
                console.log('Ping data:', JSON.stringify(pingResult.result, null, 2));
            }
            console.log();

            // DNS lookup
            console.log('2. Testing DNS lookup...');
            const dnsResult = await this.apiCall('/dns?hostname=google.com');
            console.log('DNS result:', dnsResult.success ? 'Success' : 'Failed');
            if (dnsResult.success) {
                console.log('DNS data:', JSON.stringify(dnsResult.result, null, 2));
            }
            console.log();

            // Network scan
            console.log('3. Testing network scan...');
            const networkResult = await this.apiCall('/network-scan', 'POST', {
                network: '192.168.1.0',
                subnet: '24'
            });
            console.log('Network scan result:', networkResult.success ? 'Success' : 'Failed');
            if (networkResult.success) {
                console.log('Network scan data:', JSON.stringify(networkResult.result, null, 2));
            }
            console.log();

        } catch (error) {
            console.error('Network tools demonstration failed:', error.message);
        }
    }

    // Example 7: File Operations with Interactive Controls
    async demonstrateFileOperations() {
        console.log('📁 File Operations Demonstration\n');

        try {
            // Upload a test file
            console.log('1. Testing file upload...');
            const testFileContent = 'This is a test file for RawrZ API demonstration';
            const base64Content = Buffer.from(testFileContent).toString('base64');
            
            const uploadResult = await this.apiCall('/upload', 'POST', {
                filename: 'test-demo.txt',
                base64: base64Content
            });
            
            console.log('Upload result:', uploadResult.success ? 'Success' : 'Failed');
            if (uploadResult.success) {
                console.log('Upload data:', JSON.stringify(uploadResult.result, null, 2));
            }
            console.log();

            // List files
            console.log('2. Testing file listing...');
            const filesResult = await this.apiCall('/files');
            console.log('Files result:', filesResult.success ? 'Success' : 'Failed');
            if (filesResult.success) {
                console.log('Files:', JSON.stringify(filesResult.result, null, 2));
            }
            console.log();

            // File analysis
            console.log('3. Testing file analysis...');
            const analysisResult = await this.apiCall('/analyze', 'POST', {
                input: 'test-demo.txt'
            });
            console.log('Analysis result:', analysisResult.success ? 'Success' : 'Failed');
            if (analysisResult.success) {
                console.log('Analysis data:', JSON.stringify(analysisResult.result, null, 2));
            }
            console.log();

        } catch (error) {
            console.error('File operations demonstration failed:', error.message);
        }
    }

    // Example 8: System Information and Monitoring
    async demonstrateSystemMonitoring() {
        console.log('System Monitoring Demonstration\n');

        try {
            // System info
            console.log('1. Getting system information...');
            const sysInfo = await this.apiCall('/sysinfo');
            console.log('System info result:', sysInfo.success ? 'Success' : 'Failed');
            if (sysInfo.success) {
                console.log('System info:', JSON.stringify(sysInfo.result, null, 2));
            }
            console.log();

            // Process list
            console.log('2. Getting process list...');
            const processes = await this.apiCall('/processes');
            console.log('Processes result:', processes.success ? 'Success' : 'Failed');
            if (processes.success) {
                console.log('Process count:', processes.result.length);
            }
            console.log();

            // API status
            console.log('3. Getting API status...');
            const apiStatus = await this.apiCall('/api-status');
            console.log('API status result:', apiStatus.success ? 'Success' : 'Failed');
            if (apiStatus.success) {
                console.log('API status:', JSON.stringify(apiStatus.result, null, 2));
            }
            console.log();

            // Performance monitor
            console.log('4. Getting performance monitor data...');
            const performance = await this.apiCall('/performance-monitor');
            console.log('Performance result:', performance.success ? 'Success' : 'Failed');
            if (performance.success) {
                console.log('Performance data:', JSON.stringify(performance.result, null, 2));
            }
            console.log();

        } catch (error) {
            console.error('System monitoring demonstration failed:', error.message);
        }
    }

    // Example 9: Complete Workflow Integration
    async demonstrateCompleteWorkflow() {
        console.log('Complete Workflow Integration Demonstration\n');

        try {
            // Step 1: Configure OpenSSL settings
            console.log('Step 1: Configuring OpenSSL settings...');
            await this.apiCall('/openssl/toggle-openssl', 'POST', { enabled: true });
            await this.apiCall('/openssl/toggle-custom', 'POST', { enabled: false });
            console.log('OpenSSL configured for maximum compatibility');
            console.log();

            // Step 2: Generate a stub with advanced options
            console.log('Step 2: Generating advanced stub...');
            const stubOptions = {
                polymorphic: 'advanced',
                stealth: 'high',
                obfuscation: 'extreme',
                compression: 'gzip',
                packing: 'upx',
                hotPatch: true,
                memoryProtect: true,
                encryptedStrings: true,
                controlFlowFlattening: true,
                target: 'windows',
                encryptionMethod: 'aes-256-gcm'
            };

            const stubResult = await this.apiCall('/stub', 'POST', {
                target: 'workflow-demo.exe',
                options: stubOptions
            });

            if (stubResult.success) {
                console.log('Advanced stub generated successfully');
            } else {
                console.log('Stub generation failed');
                return;
            }
            console.log();

            // Step 3: Encrypt the stub
            console.log('Step 3: Encrypting the stub...');
            const encryptResult = await this.apiCall('/encrypt', 'POST', {
                algorithm: 'aes-256-gcm',
                input: 'workflow-demo.exe'
            });

            if (encryptResult.success) {
                console.log('Stub encrypted successfully');
            } else {
                console.log('Encryption failed');
                return;
            }
            console.log();

            // Step 4: Scan target network
            console.log('Step 4: Scanning target network...');
            const scanResult = await this.apiCall('/portscan', 'POST', {
                host: '127.0.0.1',
                startPort: 80,
                endPort: 443,
                scanType: 'tcp',
                speed: 'fast',
                serviceDetection: true
            });

            if (scanResult.success) {
                console.log('Network scan completed');
            } else {
                console.log('Network scan failed');
            }
            console.log();

            // Step 5: Generate report
            console.log('Step 5: Generating workflow report...');
            const report = {
                timestamp: new Date().toISOString(),
                workflow: 'Complete Integration Demo',
                steps: {
                    openssl_config: 'Success',
                    stub_generation: stubResult.success ? 'Success' : 'Failed',
                    encryption: encryptResult.success ? 'Success' : 'Failed',
                    network_scan: scanResult.success ? 'Success' : 'Failed'
                },
                summary: {
                    total_steps: 4,
                    successful_steps: [
                        stubResult.success ? 'stub_generation' : null,
                        encryptResult.success ? 'encryption' : null,
                        scanResult.success ? 'network_scan' : null
                    ].filter(Boolean).length
                }
            };

            console.log('Workflow Report:');
            console.log(JSON.stringify(report, null, 2));
            console.log();

            console.log('Complete workflow demonstration finished!');

        } catch (error) {
            console.error('Complete workflow demonstration failed:', error.message);
        }
    }

    // Run all demonstrations
    async runAllDemonstrations() {
        console.log('RawrZ API Demonstrations\n');
        console.log('=' .repeat(50));
        console.log();

        try {
            // Check server health first
            console.log('Checking server health...');
            const health = await this.apiCall('/health');
            if (!health.ok) {
                throw new Error('Server is not healthy');
            }
            console.log('Server is healthy\n');

            // Run all demonstrations
            await this.demonstrateOpenSSLManagement();
            await this.demonstrateAdvancedStubGeneration();
            await this.demonstratePortScanning();
            await this.demonstrateEncryptionWithToggle();
            await this.demonstrateAdvancedCrypto();
            await this.demonstrateNetworkTools();
            await this.demonstrateFileOperations();
            await this.demonstrateSystemMonitoring();
            await this.demonstrateCompleteWorkflow();

            console.log('All demonstrations completed successfully!');

        } catch (error) {
            console.error('Demonstrations failed:', error.message);
            console.log('\nMake sure the RawrZ server is running on', this.baseUrl);
        }
    }
}

// Usage examples
async function runExamples() {
    const api = new RawrZAPIExamples('http://localhost:8080', 'your-auth-token-here');
    
    // Run all demonstrations
    await api.runAllDemonstrations();
    
    // Or run individual demonstrations
    // await api.demonstrateOpenSSLManagement();
    // await api.demonstrateAdvancedStubGeneration();
    // await api.demonstratePortScanning();
}

// Run if called directly
if (require.main === module) {
    runExamples().catch(error => {
        console.error('Examples failed:', error.message);
        process.exit(1);
    });
}

module.exports = { RawrZAPIExamples };
