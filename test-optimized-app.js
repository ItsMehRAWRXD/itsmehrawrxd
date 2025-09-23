#!/usr/bin/env node

/**
 * RawrZ Security Platform - Optimized App Tester
 * Tests the optimized version before deployment
 */

const http = require('http');
const { spawn } = require('child_process');
const fs = require('fs');

console.log('🧪 Testing Optimized RawrZ Security Platform...\n');

class AppTester {
    constructor() {
        this.serverProcess = null;
        this.port = 3001; // Use different port for testing
        this.testResults = [];
    }

    log(message, type = 'info') {
        const colors = {
            info: '\x1b[36m',    // Cyan
            success: '\x1b[32m', // Green
            error: '\x1b[31m',   // Red
            warning: '\x1b[33m'  // Yellow
        };
        
        const reset = '\x1b[0m';
        const timestamp = new Date().toISOString();
        console.log(`${colors[type]}[${type.toUpperCase()}]${reset} ${timestamp} - ${message}`);
    }

    async startServer() {
        return new Promise((resolve, reject) => {
            this.log('Starting optimized server...');
            
            // Set environment variables for testing
            const env = {
                ...process.env,
                NODE_ENV: 'production',
                PORT: this.port.toString(),
                LOG_LEVEL: 'error', // Reduce logs during testing
                NODE_OPTIONS: '--max-old-space-size=256'
            };

            this.serverProcess = spawn('node', ['server.optimized.js'], {
                env,
                stdio: ['pipe', 'pipe', 'pipe']
            });

            let startupOutput = '';

            this.serverProcess.stdout.on('data', (data) => {
                startupOutput += data.toString();
            });

            this.serverProcess.stderr.on('data', (data) => {
                const error = data.toString();
                if (error.includes('EADDRINUSE')) {
                    this.log(`Port ${this.port} is in use, trying ${this.port + 1}`, 'warning');
                    this.port++;
                    this.serverProcess.kill();
                    setTimeout(() => this.startServer().then(resolve).catch(reject), 1000);
                    return;
                }
                console.error(error);
            });

            this.serverProcess.on('error', (error) => {
                this.log(`Failed to start server: ${error.message}`, 'error');
                reject(error);
            });

            // Wait for server to start
            setTimeout(() => {
                if (startupOutput.includes('started successfully') || startupOutput.includes('listening')) {
                    this.log(`Server started successfully on port ${this.port}`, 'success');
                    resolve();
                } else {
                    // Try to connect to see if server is responding
                    this.makeRequest('GET', '/health')
                        .then(() => {
                            this.log('Server is responding to requests', 'success');
                            resolve();
                        })
                        .catch(() => {
                            this.log('Server failed to start properly', 'error');
                            reject(new Error('Server startup timeout'));
                        });
                }
            }, 3000);
        });
    }

    async makeRequest(method, path, data = null) {
        return new Promise((resolve, reject) => {
            const options = {
                hostname: 'localhost',
                port: this.port,
                path: path,
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                    'User-Agent': 'RawrZ-Tester/1.0'
                }
            };

            const req = http.request(options, (res) => {
                let responseData = '';

                res.on('data', (chunk) => {
                    responseData += chunk;
                });

                res.on('end', () => {
                    try {
                        const parsedData = responseData ? JSON.parse(responseData) : {};
                        resolve({
                            statusCode: res.statusCode,
                            headers: res.headers,
                            data: parsedData,
                            rawData: responseData
                        });
                    } catch (error) {
                        resolve({
                            statusCode: res.statusCode,
                            headers: res.headers,
                            data: {},
                            rawData: responseData
                        });
                    }
                });
            });

            req.on('error', (error) => {
                reject(error);
            });

            if (data && method !== 'GET') {
                req.write(JSON.stringify(data));
            }

            req.end();
        });
    }

    async runTest(name, testFunction) {
        this.log(`Running test: ${name}`);
        const startTime = Date.now();
        
        try {
            const result = await testFunction();
            const duration = Date.now() - startTime;
            
            this.testResults.push({
                name,
                status: 'PASSED',
                duration: `${duration}ms`,
                result
            });
            
            this.log(`✅ ${name} - PASSED (${duration}ms)`, 'success');
            return result;
        } catch (error) {
            const duration = Date.now() - startTime;
            
            this.testResults.push({
                name,
                status: 'FAILED',
                duration: `${duration}ms`,
                error: error.message
            });
            
            this.log(`❌ ${name} - FAILED (${duration}ms): ${error.message}`, 'error');
            throw error;
        }
    }

    async runAllTests() {
        const tests = [
            {
                name: 'Health Check Endpoint',
                test: async () => {
                    const response = await this.makeRequest('GET', '/health');
                    if (response.statusCode !== 200) {
                        throw new Error(`Expected 200, got ${response.statusCode}`);
                    }
                    if (!response.data.status || response.data.status !== 'healthy') {
                        throw new Error('Health check returned unhealthy status');
                    }
                    return response.data;
                }
            },
            {
                name: 'Root Endpoint',
                test: async () => {
                    const response = await this.makeRequest('GET', '/');
                    if (response.statusCode !== 200) {
                        throw new Error(`Expected 200, got ${response.statusCode}`);
                    }
                    if (!response.data.message) {
                        throw new Error('Root endpoint missing message');
                    }
                    return response.data;
                }
            },
            {
                name: 'API Endpoint',
                test: async () => {
                    const response = await this.makeRequest('GET', '/api');
                    if (response.statusCode !== 200) {
                        throw new Error(`Expected 200, got ${response.statusCode}`);
                    }
                    if (!response.data.version) {
                        throw new Error('API endpoint missing version');
                    }
                    return response.data;
                }
            },
            {
                name: 'API Test Endpoint (POST)',
                test: async () => {
                    const testData = { data: 'test payload' };
                    const response = await this.makeRequest('POST', '/api/test', testData);
                    if (response.statusCode !== 200) {
                        throw new Error(`Expected 200, got ${response.statusCode}`);
                    }
                    if (response.data.received !== testData.data) {
                        throw new Error('Test data not echoed correctly');
                    }
                    return response.data;
                }
            },
            {
                name: 'Status Endpoint',
                test: async () => {
                    const response = await this.makeRequest('GET', '/api/status');
                    if (response.statusCode !== 200) {
                        throw new Error(`Expected 200, got ${response.statusCode}`);
                    }
                    if (!response.data.server || !response.data.platform) {
                        throw new Error('Status endpoint missing server or platform info');
                    }
                    return response.data;
                }
            },
            {
                name: '404 Handling',
                test: async () => {
                    const response = await this.makeRequest('GET', '/nonexistent');
                    if (response.statusCode !== 404) {
                        throw new Error(`Expected 404, got ${response.statusCode}`);
                    }
                    return response.data;
                }
            },
            {
                name: 'Performance Test (Memory)',
                test: async () => {
                    const initialMemory = process.memoryUsage().heapUsed;
                    
                    // Make multiple requests to test memory stability
                    const requests = [];
                    for (let i = 0; i < 50; i++) {
                        requests.push(this.makeRequest('GET', '/health'));
                    }
                    
                    await Promise.all(requests);
                    
                    // Force garbage collection if available
                    if (global.gc) {
                        global.gc();
                    }
                    
                    const finalMemory = process.memoryUsage().heapUsed;
                    const memoryDiff = finalMemory - initialMemory;
                    const memoryDiffMB = memoryDiff / (1024 * 1024);
                    
                    if (memoryDiffMB > 50) { // More than 50MB increase
                        throw new Error(`Memory leak detected: ${memoryDiffMB.toFixed(2)}MB increase`);
                    }
                    
                    return {
                        initialMemoryMB: (initialMemory / (1024 * 1024)).toFixed(2),
                        finalMemoryMB: (finalMemory / (1024 * 1024)).toFixed(2),
                        diffMB: memoryDiffMB.toFixed(2)
                    };
                }
            },
            {
                name: 'Rate Limiting',
                test: async () => {
                    const requests = [];
                    
                    // Make many requests quickly to test rate limiting
                    for (let i = 0; i < 10; i++) {
                        requests.push(
                            this.makeRequest('GET', '/health').catch(err => ({ error: err.message }))
                        );
                    }
                    
                    const responses = await Promise.all(requests);
                    const successCount = responses.filter(r => !r.error).length;
                    
                    if (successCount === 0) {
                        throw new Error('All requests failed - rate limiting too aggressive');
                    }
                    
                    return {
                        totalRequests: requests.length,
                        successfulRequests: successCount
                    };
                }
            }
        ];

        let passedTests = 0;
        let totalTests = tests.length;

        this.log(`\n🚀 Starting ${totalTests} tests...\n`);

        for (const { name, test } of tests) {
            try {
                await this.runTest(name, test);
                passedTests++;
            } catch (error) {
                // Test failed, continue with others
            }
            
            // Small delay between tests
            await new Promise(resolve => setTimeout(resolve, 100));
        }

        return { passedTests, totalTests };
    }

    generateReport(testResults) {
        const passed = this.testResults.filter(t => t.status === 'PASSED').length;
        const failed = this.testResults.filter(t => t.status === 'FAILED').length;
        const total = this.testResults.length;

        console.log('\n' + '='.repeat(60));
        console.log('🧪 TEST REPORT');
        console.log('='.repeat(60));
        console.log(`📊 Total Tests: ${total}`);
        console.log(`✅ Passed: ${passed}`);
        console.log(`❌ Failed: ${failed}`);
        console.log(`📈 Success Rate: ${((passed / total) * 100).toFixed(1)}%`);
        console.log('='.repeat(60));

        if (failed > 0) {
            console.log('\n❌ Failed Tests:');
            this.testResults
                .filter(t => t.status === 'FAILED')
                .forEach(test => {
                    console.log(`   • ${test.name}: ${test.error}`);
                });
        }

        console.log('\n📋 Detailed Results:');
        this.testResults.forEach(test => {
            const statusIcon = test.status === 'PASSED' ? '✅' : '❌';
            console.log(`   ${statusIcon} ${test.name} (${test.duration})`);
        });

        return testResults;
    }

    async cleanup() {
        if (this.serverProcess) {
            this.log('Stopping test server...');
            this.serverProcess.kill('SIGTERM');
            
            // Wait for graceful shutdown
            await new Promise(resolve => {
                this.serverProcess.on('exit', resolve);
                setTimeout(() => {
                    this.serverProcess.kill('SIGKILL');
                    resolve();
                }, 5000);
            });
            
            this.log('Test server stopped', 'success');
        }
    }
}

// Main test execution
async function main() {
    const tester = new AppTester();
    
    try {
        // Check if optimized files exist
        if (!fs.existsSync('server.optimized.js')) {
            console.error('❌ server.optimized.js not found. Please ensure optimized files are present.');
            process.exit(1);
        }

        await tester.startServer();
        const results = await tester.runAllTests();
        tester.generateReport(results);
        
        console.log('\n🎉 Testing completed!');
        
        if (results.passedTests === results.totalTests) {
            console.log('✅ All tests passed - ready for deployment!');
            process.exit(0);
        } else {
            console.log(`❌ ${results.totalTests - results.passedTests} test(s) failed - review before deployment`);
            process.exit(1);
        }
        
    } catch (error) {
        console.error(`❌ Test execution failed: ${error.message}`);
        process.exit(1);
    } finally {
        await tester.cleanup();
    }
}

// Handle process termination
process.on('SIGINT', async () => {
    console.log('\n🛑 Test interrupted by user');
    process.exit(1);
});

process.on('SIGTERM', async () => {
    console.log('\n🛑 Test terminated');
    process.exit(1);
});

// Run tests
main().catch(console.error);