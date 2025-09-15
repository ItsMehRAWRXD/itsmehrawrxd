// RawrZ Security Platform - Comprehensive Testing Suite
// Tests all engines, CLI commands, API endpoints, and web panels

const fs = require('fs').promises;
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);

class RawrZTestSuite {
    constructor() {
        this.testResults = [];
        this.passedTests = 0;
        this.failedTests = 0;
        this.startTime = Date.now();
        this.serverUrl = 'http://localhost:8080';
        this.authToken = 'test-token';
    }

    // Test result logging
    logTest(testName, passed, details = '') {
        const result = {
            test: testName,
            passed: passed,
            details: details,
            timestamp: new Date().toISOString()
        };
        
        this.testResults.push(result);
        
        if (passed) {
            this.passedTests++;
            console.log('PASS: ' + testName);
        } else {
            this.failedTests++;
            console.log('FAIL: ' + testName + ' - ' + details);
        }
    }

    // API helper
    async apiCall(endpoint, method = 'GET', data = null) {
        try {
            const fetch = require('node-fetch');
            const options = {
                method,
                headers: {
                    'Content-Type': 'application/json'
                }
            };

            // Add authentication for protected endpoints
            if (endpoint.startsWith('/api/') && !endpoint.includes('/health')) {
                options.headers['Authorization'] = 'Bearer ' + this.authToken;
            }

            if (data) {
                options.body = JSON.stringify(data);
            }

            const response = await fetch(this.serverUrl + endpoint, options);
            
            // Try to parse as JSON, but handle non-JSON responses gracefully
            let result;
            try {
                result = await response.json();
            } catch (jsonError) {
                // If JSON parsing fails, return the text response
                const textResponse = await response.text();
                result = { message: textResponse };
            }
            
            return {
                status: response.status,
                data: result
            };
        } catch (error) {
            return {
                status: 500,
                data: { error: error.message }
            };
        }
    }

    // Test server health
    async testServerHealth() {
        try {
            const result = await this.apiCall('/health');
            const passed = result.status === 200 && result.data.ok === true;
            this.logTest('Server Health Check', passed, passed ? 'Server is healthy' : 'Status: ' + result.status);
            return passed;
        } catch (error) {
            this.logTest('Server Health Check', false, error.message);
            return false;
        }
    }

    // Test API status endpoint
    async testAPIStatus() {
        try {
            const result = await this.apiCall('/api/status');
            const passed = result.status === 200 && result.data.success === true;
            this.logTest('API Status Endpoint', passed, passed ? 'Status endpoint working' : 'Status: ' + result.status);
            return passed;
        } catch (error) {
            this.logTest('API Status Endpoint', false, error.message);
            return false;
        }
    }

    // Test CLI commands
    async testCLICommands() {
        const commands = [
            { cmd: 'node rawrz-standalone.js help', name: 'CLI Help Command' },
            { cmd: 'node rawrz-standalone.js engines status', name: 'CLI Engines Status' },
            { cmd: 'node rawrz-standalone.js engines load network-tools', name: 'CLI Load Engine' },
            { cmd: 'node rawrz-standalone.js ping google.com', name: 'CLI Ping Command' },
            { cmd: 'node rawrz-standalone.js dns google.com', name: 'CLI DNS Command' },
            { cmd: 'node rawrz-standalone.js rebuild', name: 'CLI Rebuild Command' }
        ];

        for (const command of commands) {
            try {
                const { stdout, stderr } = await execAsync(command.cmd);
                const passed = !stderr && stdout.length > 0;
                this.logTest(command.name, passed, passed ? 'Command executed successfully' : stderr);
            } catch (error) {
                this.logTest(command.name, false, error.message);
            }
        }
    }

    // Test engine initialization
    async testEngineInitialization() {
        const engines = [
            'anti-analysis',
            'digital-forensics',
            'malware-analysis',
            'network-tools',
            'hot-patchers',
            'reverse-engineering',
            'jotti-scanner',
            'private-virus-scanner',
            'dual-generators',
            'health-monitor',
            'stealth-engine',
            'advanced-fud-engine'
        ];

        for (const engineName of engines) {
            try {
                const enginePath = './src/engines/' + engineName;
                const EngineModule = require(enginePath);
                
                // Handle different export patterns
                let engine;
                if (typeof EngineModule === 'function') {
                    // It's a class constructor
                    engine = new EngineModule();
                } else if (EngineModule.default) {
                    // Default export
                    if (typeof EngineModule.default === 'function') {
                        engine = new EngineModule.default();
                    } else {
                        engine = EngineModule.default;
                    }
                } else if (typeof EngineModule === 'object' && EngineModule !== null) {
                    // It's already an instance - this is the most common pattern
                    engine = EngineModule;
                } else {
                    this.logTest('Engine ' + engineName + ' Initialization', false, 'Could not find engine class or instance');
                    continue;
                }
                
                if (!engine) {
                    this.logTest('Engine ' + engineName + ' Initialization', false, 'Engine is null or undefined');
                    continue;
                }
                
                if (typeof engine.initialize === 'function') {
                    await engine.initialize();
                    this.logTest('Engine ' + engineName + ' Initialization', true, 'Engine initialized successfully');
                } else {
                    this.logTest('Engine ' + engineName + ' Initialization', true, 'Engine loaded (no initialize method)');
                }
            } catch (error) {
                this.logTest('Engine ' + engineName + ' Initialization', false, error.message);
            }
        }
    }

    // Test API endpoints
    async testAPIEndpoints() {
        const endpoints = [
            { endpoint: '/api/status', method: 'GET', name: 'Status Endpoint' },
            { endpoint: '/api/rebuild', method: 'POST', name: 'Rebuild Endpoint' },
            { endpoint: '/api/security/scan', method: 'POST', data: { target: 'localhost' }, name: 'Security Scan Endpoint' },
            { endpoint: '/api/analysis/malware', method: 'POST', data: { file: 'package.json' }, name: 'Malware Analysis Endpoint' },
            { endpoint: '/api/dashboard/stats', method: 'GET', name: 'Dashboard Stats Endpoint' },
            { endpoint: '/api/bots/status', method: 'GET', name: 'Bots Status Endpoint' }
        ];

        for (const endpoint of endpoints) {
            try {
                const result = await this.apiCall(endpoint.endpoint, endpoint.method, endpoint.data);
                const passed = result.status === 200;
                this.logTest(endpoint.name, passed, passed ? 'Endpoint working' : 'Status: ' + result.status);
            } catch (error) {
                this.logTest(endpoint.name, false, error.message);
            }
        }
    }

    // Test web panels
    async testWebPanels() {
        const panels = [
            '/panel',
            '/unified',
            '/irc-bot-builder',
            '/http-bot-panel',
            '/stub-generator-panel',
            '/health-dashboard'
        ];

        for (const panel of panels) {
            try {
                const fetch = require('node-fetch');
                const response = await fetch(this.serverUrl + panel);
                const passed = response.status === 200;
                
                if (passed) {
                    const content = await response.text();
                    const hasHTML = content.includes('<html') || content.includes('<!DOCTYPE');
                    this.logTest('Web Panel ' + panel, hasHTML, hasHTML ? 'Panel loads correctly' : 'No HTML content');
                } else {
                    this.logTest('Web Panel ' + panel, false, 'Status: ' + response.status);
                }
            } catch (error) {
                this.logTest('Web Panel ' + panel, false, error.message);
            }
        }
    }

    // Test file operations
    async testFileOperations() {
        try {
            // Test file reading
            const packageJson = await fs.readFile('package.json', 'utf8');
            const passed = packageJson.length > 0;
            this.logTest('File Reading', passed, passed ? 'Package.json read successfully' : 'Failed to read package.json');

            // Test directory listing
            const files = await fs.readdir('.');
            const hasFiles = files.length > 0;
            this.logTest('Directory Listing', hasFiles, hasFiles ? 'Found ' + files.length + ' files' : 'No files found');

        } catch (error) {
            this.logTest('File Operations', false, error.message);
        }
    }

    // Test encryption/decryption
    async testEncryption() {
        try {
            const crypto = require('crypto');
            const testData = 'Test encryption data';
            const algorithm = 'aes-256-cbc';
            const key = crypto.randomBytes(32);
            const iv = crypto.randomBytes(16);

            // Encrypt
            const cipher = crypto.createCipheriv(algorithm, key, iv);
            let encrypted = cipher.update(testData, 'utf8', 'hex');
            encrypted += cipher.final('hex');

            // Decrypt
            const decipher = crypto.createDecipheriv(algorithm, key, iv);
            let decrypted = decipher.update(encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            const passed = decrypted === testData;
            this.logTest('Encryption/Decryption', passed, passed ? 'Encryption/decryption working' : 'Data mismatch');
        } catch (error) {
            this.logTest('Encryption/Decryption', false, error.message);
        }
    }

    // Test network operations
    async testNetworkOperations() {
        try {
            const net = require('net');
            const dns = require('dns').promises;

            // Test DNS lookup
            const dnsResult = await dns.lookup('google.com');
            const dnsPassed = dnsResult.address && dnsResult.family;
            this.logTest('DNS Lookup', dnsPassed, dnsPassed ? 'Resolved to ' + dnsResult.address : 'DNS lookup failed');

            // Test TCP connection
            const tcpTest = new Promise((resolve) => {
                const socket = new net.Socket();
                socket.setTimeout(5000);
                socket.on('connect', () => {
                    socket.destroy();
                    resolve(true);
                });
                socket.on('timeout', () => {
                    socket.destroy();
                    resolve(false);
                });
                socket.on('error', () => {
                    socket.destroy();
                    resolve(false);
                });
                socket.connect(80, 'google.com');
            });

            const tcpPassed = await tcpTest;
            this.logTest('TCP Connection', tcpPassed, tcpPassed ? 'TCP connection successful' : 'TCP connection failed');

        } catch (error) {
            this.logTest('Network Operations', false, error.message);
        }
    }

    // Test session management
    async testSessionManagement() {
        try {
            // Test session creation
            const createResult = await execAsync('node rawrz-standalone.js session create test-session');
            const createPassed = !createResult.stderr;
            this.logTest('Session Creation', createPassed, createPassed ? 'Session created' : createResult.stderr);

            // Test session listing
            const listResult = await execAsync('node rawrz-standalone.js session list');
            const listPassed = !listResult.stderr && listResult.stdout.includes('test-session');
            this.logTest('Session Listing', listPassed, listPassed ? 'Sessions listed' : listResult.stderr);

        } catch (error) {
            this.logTest('Session Management', false, error.message);
        }
    }

    // Test error handling
    async testErrorHandling() {
        try {
            // Test invalid command
            const invalidResult = await execAsync('node rawrz-standalone.js invalid-command');
            const errorHandled = invalidResult.stderr && (
                invalidResult.stderr.includes('Unknown command') ||
                invalidResult.stderr.includes('ERROR') || 
                invalidResult.stderr.includes('error')
            );
            this.logTest('Error Handling', errorHandled, errorHandled ? 'Errors handled properly' : 'No error handling detected. stderr: ' + invalidResult.stderr);

        } catch (error) {
            // If execAsync throws an error, that means the command failed as expected
            const errorHandled = error.message && (
                error.message.includes('Unknown command') ||
                error.message.includes('ERROR') || 
                error.message.includes('error')
            );
            this.logTest('Error Handling', errorHandled, errorHandled ? 'Error handling working (caught exception)' : 'No error handling detected. Error: ' + error.message);
        }
    }

    // Run all tests
    async runAllTests() {
        console.log('Starting RawrZ Security Platform Test Suite...\n');
        
        // Test server health first
        const serverHealthy = await this.testServerHealth();
        if (!serverHealthy) {
            console.log('ERROR: Server is not healthy. Please start the server first.');
            return;
        }

        // Run all test categories
        await this.testAPIStatus();
        await this.testCLICommands();
        await this.testEngineInitialization();
        await this.testAPIEndpoints();
        await this.testWebPanels();
        await this.testFileOperations();
        await this.testEncryption();
        await this.testNetworkOperations();
        await this.testSessionManagement();
        await this.testErrorHandling();

        // Generate report
        this.generateReport();
    }

    // Generate test report
    generateReport() {
        const endTime = Date.now();
        const duration = endTime - this.startTime;
        const totalTests = this.passedTests + this.failedTests;
        const successRate = totalTests > 0 ? (this.passedTests / totalTests * 100).toFixed(2) : 0;

        console.log('\nTest Suite Report');
        console.log('==================');
        console.log('Total Tests: ' + totalTests);
        console.log('Passed: ' + this.passedTests);
        console.log('Failed: ' + this.failedTests);
        console.log('Success Rate: ' + successRate + '%');
        console.log('Duration: ' + duration + 'ms');

        if (this.failedTests > 0) {
            console.log('\nFailed Tests:');
            this.testResults
                .filter(test => !test.passed)
                .forEach(test => {
                    console.log('  - ' + test.test + ': ' + test.details);
                });
        }

        // Save report to file
        const report = {
            summary: {
                totalTests,
                passedTests: this.passedTests,
                failedTests: this.failedTests,
                successRate: parseFloat(successRate),
                duration
            },
            results: this.testResults,
            timestamp: new Date().toISOString()
        };

        fs.writeFile('test-report.json', JSON.stringify(report, null, 2))
            .then(() => console.log('\nTest report saved to test-report.json'))          
            .catch(err => console.log('\nWARNING: Failed to save test report: ' + err.message));

        console.log('\nTest suite completed!');
    }
}

// Run tests if called directly
if (require.main === module) {
    const testSuite = new RawrZTestSuite();
    testSuite.runAllTests().catch(console.error);
}

module.exports = RawrZTestSuite;
