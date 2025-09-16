// Comprehensive Endpoint Test Suite for RawrZ Web Panel
// Tests all endpoints to ensure web panel functionality

const http = require('http');

class EndpointTester {
    constructor() {
        this.baseUrl = 'http://localhost:8080';
        this.results = {
            passed: 0,
            failed: 0,
            tests: []
        };
    }

    async makeRequest(method, endpoint, body = null) {
        return new Promise((resolve, reject) => {
            const url = `${this.baseUrl}${endpoint}`;
            const options = {
                method: method,
                headers: {
                    'Content-Type': 'application/json'
                }
            };

            const req = http.request(url, options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        const jsonData = JSON.parse(data);
                        resolve({ status: res.statusCode, data: jsonData });
                    } catch (e) {
                        resolve({ status: res.statusCode, data: data });
                    }
                });
            });

            req.on('error', reject);
            req.setTimeout(10000, () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });

            if (body) {
                req.write(JSON.stringify(body));
            }
            req.end();
        });
    }

    async testEndpoint(method, endpoint, name, expectedStatus = 200, body = null) {
        try {
            console.log(`\n🔍 Testing ${name} (${method} ${endpoint})...`);
            const response = await this.makeRequest(method, endpoint, body);
            
            if (response.status === expectedStatus) {
                console.log(`✅ ${name} - Status: ${response.status}`);
                this.results.passed++;
                this.results.tests.push({ 
                    name, 
                    method, 
                    endpoint, 
                    status: 'PASS', 
                    details: `Status: ${response.status}` 
                });
            } else {
                console.log(`❌ ${name} - Expected: ${expectedStatus}, Got: ${response.status}`);
                this.results.failed++;
                this.results.tests.push({ 
                    name, 
                    method, 
                    endpoint, 
                    status: 'FAIL', 
                    details: `Expected: ${expectedStatus}, Got: ${response.status}` 
                });
            }
            
        } catch (error) {
            console.log(`❌ ${name} - Error: ${error.message}`);
            this.results.failed++;
            this.results.tests.push({ 
                name, 
                method, 
                endpoint, 
                status: 'FAIL', 
                details: error.message 
            });
        }
    }

    async runAllTests() {
        console.log('🚀 Starting Comprehensive RawrZ Endpoint Tests...\n');
        console.log('='.repeat(80));

        // Test dropdown endpoints
        console.log('\n📋 TESTING DROPDOWN ENDPOINTS');
        console.log('-'.repeat(40));
        await this.testEndpoint('GET', '/api/algorithms', 'Algorithms Dropdown');
        await this.testEndpoint('GET', '/api/engines', 'Engines Dropdown');
        await this.testEndpoint('GET', '/api/features', 'Features Dropdown');
        await this.testEndpoint('GET', '/api/status', 'Status Dropdown');
        await this.testEndpoint('GET', '/api/health', 'Health Dropdown');
        await this.testEndpoint('GET', '/api/crypto/algorithms', 'Crypto Algorithms');
        await this.testEndpoint('GET', '/api/crypto/modes', 'Crypto Modes');
        await this.testEndpoint('GET', '/api/crypto/key-sizes', 'Crypto Key Sizes');
        await this.testEndpoint('GET', '/api/bots/languages', 'Bot Languages');
        await this.testEndpoint('GET', '/api/bots/features', 'Bot Features');
        await this.testEndpoint('GET', '/api/bots/templates', 'Bot Templates');
        await this.testEndpoint('GET', '/api/analysis/tools', 'Analysis Tools');
        await this.testEndpoint('GET', '/api/analysis/engines', 'Analysis Engines');
        await this.testEndpoint('GET', '/api/compile/languages', 'Compile Languages');
        await this.testEndpoint('GET', '/api/compile/targets', 'Compile Targets');
        await this.testEndpoint('GET', '/api/network/ports', 'Network Ports');
        await this.testEndpoint('GET', '/api/network/protocols', 'Network Protocols');

        // Test core functionality endpoints
        console.log('\n🔧 TESTING CORE FUNCTIONALITY ENDPOINTS');
        console.log('-'.repeat(40));
        await this.testEndpoint('POST', '/encrypt', 'Encryption', 200, {algorithm: 'aes256', input: 'test data'});
        await this.testEndpoint('POST', '/decrypt', 'Decryption', 200, {algorithm: 'aes256', input: 'encrypted_data', key: 'test_key'});
        await this.testEndpoint('POST', '/hash', 'Hashing', 200, {input: 'test data', algorithm: 'sha256'});
        await this.testEndpoint('POST', '/keygen', 'Key Generation', 200, {algorithm: 'aes256', length: 256});
        await this.testEndpoint('GET', '/files', 'File Listing');
        await this.testEndpoint('GET', '/sysinfo', 'System Information');
        await this.testEndpoint('GET', '/processes', 'Process Listing');
        await this.testEndpoint('POST', '/portscan', 'Port Scan', 200, {host: 'localhost', startPort: 80, endPort: 90});

        // Test bot generation endpoints
        console.log('\n🤖 TESTING BOT GENERATION ENDPOINTS');
        console.log('-'.repeat(40));
        await this.testEndpoint('GET', '/http-bot/templates', 'HTTP Bot Templates');
        await this.testEndpoint('GET', '/http-bot/features', 'HTTP Bot Features');
        await this.testEndpoint('GET', '/http-bot/status', 'HTTP Bot Status');
        await this.testEndpoint('POST', '/http-bot/generate', 'HTTP Bot Generate', 200, {
            config: {server: 'localhost', port: 8080},
            features: ['fileManager'],
            extensions: ['basic']
        });
        await this.testEndpoint('GET', '/irc-bot/templates', 'IRC Bot Templates');
        await this.testEndpoint('GET', '/irc-bot/features', 'IRC Bot Features');

        // Test analysis endpoints
        console.log('\n🔍 TESTING ANALYSIS ENDPOINTS');
        console.log('-'.repeat(40));
        await this.testEndpoint('POST', '/analyze', 'File Analysis', 200, {input: 'test.exe'});
        await this.testEndpoint('POST', '/api/analysis/malware', 'Malware Analysis', 200, {file: 'test.exe'});
        await this.testEndpoint('POST', '/api/analysis/digital-forensics', 'Digital Forensics', 200);
        await this.testEndpoint('POST', '/api/analysis/network', 'Network Analysis', 200, {target: 'localhost'});

        // Test security endpoints
        console.log('\n🛡️ TESTING SECURITY ENDPOINTS');
        console.log('-'.repeat(40));
        await this.testEndpoint('POST', '/api/security/scan', 'Security Scan', 200, {target: 'localhost'});
        await this.testEndpoint('POST', '/api/security/fud-analysis', 'FUD Analysis', 200);
        await this.testEndpoint('POST', '/api/security/stealth-mode', 'Stealth Mode', 200);
        await this.testEndpoint('POST', '/api/security/anti-detection', 'Anti-Detection', 200);

        // Test crypto endpoints
        console.log('\n🔐 TESTING CRYPTO ENDPOINTS');
        console.log('-'.repeat(40));
        await this.testEndpoint('POST', '/api/crypto/test-algorithm', 'Test Algorithm', 200, {algorithm: 'aes256'});
        await this.testEndpoint('POST', '/api/crypto/generate-report', 'Generate Report', 200);
        await this.testEndpoint('POST', '/base64encode', 'Base64 Encode', 200, {input: 'test data'});
        await this.testEndpoint('POST', '/base64decode', 'Base64 Decode', 200, {input: 'dGVzdCBkYXRh'});
        await this.testEndpoint('POST', '/hexencode', 'Hex Encode', 200, {input: 'test data'});
        await this.testEndpoint('POST', '/hexdecode', 'Hex Decode', 200, {input: '746573742064617461'});

        // Test utility endpoints
        console.log('\n🛠️ TESTING UTILITY ENDPOINTS');
        console.log('-'.repeat(40));
        await this.testEndpoint('GET', '/uuid', 'UUID Generation');
        await this.testEndpoint('POST', '/password', 'Password Generation', 200, {length: 16});
        await this.testEndpoint('POST', '/random', 'Random Generation', 200, {length: 32});
        await this.testEndpoint('GET', '/time', 'Time Information');
        await this.testEndpoint('POST', '/math', 'Math Operations', 200, {expression: '2+2'});

        // Test network endpoints
        console.log('\n🌐 TESTING NETWORK ENDPOINTS');
        console.log('-'.repeat(40));
        await this.testEndpoint('GET', '/ping', 'Ping Test', 200, {host: 'localhost'});
        await this.testEndpoint('GET', '/dns', 'DNS Lookup', 200, {hostname: 'google.com'});
        await this.testEndpoint('POST', '/traceroute', 'Traceroute', 200, {host: 'google.com'});
        await this.testEndpoint('POST', '/whois', 'WHOIS Lookup', 200, {domain: 'google.com'});

        // Test panel endpoints
        console.log('\n📱 TESTING PANEL ENDPOINTS');
        console.log('-'.repeat(40));
        await this.testEndpoint('GET', '/panel', 'Main Panel', 200);
        await this.testEndpoint('GET', '/irc-bot-builder', 'IRC Bot Builder', 200);
        await this.testEndpoint('GET', '/http-bot-panel', 'HTTP Bot Panel', 200);
        await this.testEndpoint('GET', '/stub-generator-panel', 'Stub Generator Panel', 200);
        await this.testEndpoint('GET', '/health-dashboard', 'Health Dashboard', 200);
        await this.testEndpoint('GET', '/bot-manager', 'Bot Manager', 200);
        await this.testEndpoint('GET', '/unified', 'Unified Panel', 200);

        this.printResults();
    }

    printResults() {
        console.log('\n' + '='.repeat(80));
        console.log('📊 COMPREHENSIVE ENDPOINT TEST RESULTS');
        console.log('='.repeat(80));
        
        const total = this.results.passed + this.results.failed;
        const successRate = total > 0 ? ((this.results.passed / total) * 100).toFixed(1) : 0;
        
        console.log(`✅ Passed: ${this.results.passed}`);
        console.log(`❌ Failed: ${this.results.failed}`);
        console.log(`📈 Success Rate: ${successRate}%`);
        
        console.log('\n📋 Detailed Results:');
        this.results.tests.forEach(test => {
            const icon = test.status === 'PASS' ? '✅' : '❌';
            console.log(`${icon} ${test.name} (${test.method} ${test.endpoint}): ${test.status} - ${test.details}`);
        });
        
        if (this.results.failed === 0) {
            console.log('\n🎉 ALL ENDPOINT TESTS PASSED! Web panel is fully functional!');
        } else {
            console.log('\n⚠️  Some endpoint tests failed. Check the details above.');
        }
        
        console.log('\n' + '='.repeat(80));
    }
}

// Run the tests
async function main() {
    const tester = new EndpointTester();
    await tester.runAllTests();
}

if (require.main === module) {
    main().catch(console.error);
}

module.exports = EndpointTester;
