// Complete endpoint discovery and testing for RawrZ platform
const http = require('http');

class CompleteEndpointTester {
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
            const options = {
                method: method,
                headers: {
                    'Content-Type': 'application/json'
                }
            };

            const req = http.request(`${this.baseUrl}${endpoint}`, options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        const jsonData = JSON.parse(data);
                        resolve({ status: res.statusCode, success: true, data: jsonData });
                    } catch (e) {
                        resolve({ status: res.statusCode, success: false, data: data });
                    }
                });
            });
            
            req.on('error', reject);
            req.setTimeout(10000, () => {
                req.destroy();
                reject(new Error('Timeout'));
            });

            if (body) {
                req.write(JSON.stringify(body));
            }
            req.end();
        });
    }

    async testEndpoint(method, endpoint, name, body = null) {
        try {
            const response = await this.makeRequest(method, endpoint, body);
            
            if (response.status === 200) {
                this.results.passed++;
                this.results.tests.push({ 
                    name, 
                    method, 
                    endpoint, 
                    status: 'PASS', 
                    details: `Status: ${response.status}` 
                });
                return true;
            } else {
                this.results.failed++;
                this.results.tests.push({ 
                    name, 
                    method, 
                    endpoint, 
                    status: 'FAIL', 
                    details: `Status: ${response.status}` 
                });
                return false;
            }
            
        } catch (error) {
            this.results.failed++;
            this.results.tests.push({ 
                name, 
                method, 
                endpoint, 
                status: 'FAIL', 
                details: error.message 
            });
            return false;
        }
    }

    async runCompleteTest() {
        console.log('🚀 Complete RawrZ Endpoint Discovery and Testing\n');
        console.log('='.repeat(80));

        // Get the actual list of available engines and features
        console.log('📋 Discovering available engines and features...');
        
        try {
            const enginesResponse = await this.makeRequest('GET', '/api/engines');
            const featuresResponse = await this.makeRequest('GET', '/api/features');
            
            if (enginesResponse.success) {
                console.log(`✅ Found ${enginesResponse.data.engines?.length || 0} engines`);
            }
            
            if (featuresResponse.success) {
                console.log(`✅ Found ${featuresResponse.data.features?.length || 0} features`);
            }
        } catch (error) {
            console.log(`❌ Failed to discover engines/features: ${error.message}`);
        }

        console.log('\n🔧 TESTING ALL AVAILABLE ENDPOINTS');
        console.log('-'.repeat(50));

        // Test all the endpoints we know exist
        const allEndpoints = [
            // Core API endpoints
            { method: 'GET', endpoint: '/api/status', name: 'API Status' },
            { method: 'GET', endpoint: '/api/health', name: 'API Health' },
            { method: 'GET', endpoint: '/api/engines', name: 'API Engines' },
            { method: 'GET', endpoint: '/api/features', name: 'API Features' },
            { method: 'GET', endpoint: '/api/algorithms', name: 'API Algorithms' },
            
            // Crypto endpoints
            { method: 'GET', endpoint: '/api/crypto/algorithms', name: 'Crypto Algorithms' },
            { method: 'GET', endpoint: '/api/crypto/modes', name: 'Crypto Modes' },
            { method: 'GET', endpoint: '/api/crypto/key-sizes', name: 'Crypto Key Sizes' },
            { method: 'POST', endpoint: '/api/crypto/test-algorithm', name: 'Test Algorithm', body: { algorithm: 'aes-256-cbc' } },
            { method: 'POST', endpoint: '/api/crypto/generate-report', name: 'Generate Report', body: {} },
            
            // Bot endpoints
            { method: 'GET', endpoint: '/api/bots/languages', name: 'Bot Languages' },
            { method: 'GET', endpoint: '/api/bots/features', name: 'Bot Features' },
            { method: 'GET', endpoint: '/api/bots/templates', name: 'Bot Templates' },
            { method: 'GET', endpoint: '/http-bot/templates', name: 'HTTP Bot Templates' },
            { method: 'GET', endpoint: '/http-bot/features', name: 'HTTP Bot Features' },
            { method: 'GET', endpoint: '/http-bot/status', name: 'HTTP Bot Status' },
            { method: 'POST', endpoint: '/http-bot/generate', name: 'HTTP Bot Generate', body: { config: { name: 'test', server: 'localhost', port: 8080 }, features: ['basic'], extensions: [] } },
            { method: 'GET', endpoint: '/irc-bot/templates', name: 'IRC Bot Templates' },
            { method: 'GET', endpoint: '/irc-bot/features', name: 'IRC Bot Features' },
            
            // Analysis endpoints
            { method: 'GET', endpoint: '/api/analysis/tools', name: 'Analysis Tools' },
            { method: 'GET', endpoint: '/api/analysis/engines', name: 'Analysis Engines' },
            { method: 'POST', endpoint: '/api/analysis/malware', name: 'Malware Analysis', body: { file: 'server.js' } },
            { method: 'POST', endpoint: '/api/analysis/digital-forensics', name: 'Digital Forensics', body: {} },
            { method: 'POST', endpoint: '/api/analysis/network', name: 'Network Analysis', body: { target: 'localhost' } },
            
            // Security endpoints
            { method: 'POST', endpoint: '/api/security/scan', name: 'Security Scan', body: { target: 'localhost' } },
            { method: 'POST', endpoint: '/api/security/fud-analysis', name: 'FUD Analysis', body: {} },
            { method: 'POST', endpoint: '/api/security/stealth-mode', name: 'Stealth Mode', body: {} },
            { method: 'POST', endpoint: '/api/security/anti-detection', name: 'Anti-Detection', body: {} },
            { method: 'POST', endpoint: '/api/security/vulnerability-check', name: 'Vulnerability Check', body: { target: 'localhost' } },
            { method: 'POST', endpoint: '/api/security/threat-detection', name: 'Threat Detection', body: { target: 'localhost' } },
            
            // Network endpoints
            { method: 'GET', endpoint: '/api/network/ports', name: 'Network Ports' },
            { method: 'GET', endpoint: '/api/network/protocols', name: 'Network Protocols' },
            { method: 'GET', endpoint: '/ping', name: 'Ping Test' },
            { method: 'GET', endpoint: '/dns', name: 'DNS Lookup' },
            { method: 'POST', endpoint: '/traceroute', name: 'Traceroute', body: { host: 'google.com' } },
            { method: 'POST', endpoint: '/whois', name: 'WHOIS Lookup', body: { domain: 'google.com' } },
            { method: 'POST', endpoint: '/portscan', name: 'Port Scan', body: { host: 'localhost', startPort: 80, endPort: 443 } },
            
            // Core functionality
            { method: 'POST', endpoint: '/encrypt', name: 'Encryption', body: { algorithm: 'aes-256-cbc', input: 'test', key: 'testkey123456789012345678901234' } },
            { method: 'POST', endpoint: '/decrypt', name: 'Decryption', body: { algorithm: 'aes-256-cbc', input: 'encrypted_data', key: 'testkey123456789012345678901234' } },
            { method: 'POST', endpoint: '/hash', name: 'Hashing', body: { algorithm: 'sha256', input: 'test' } },
            { method: 'POST', endpoint: '/keygen', name: 'Key Generation', body: { algorithm: 'aes-256' } },
            { method: 'POST', endpoint: '/base64encode', name: 'Base64 Encode', body: { input: 'test' } },
            { method: 'POST', endpoint: '/base64decode', name: 'Base64 Decode', body: { input: 'dGVzdA==' } },
            { method: 'POST', endpoint: '/hexencode', name: 'Hex Encode', body: { input: 'test' } },
            { method: 'POST', endpoint: '/hexdecode', name: 'Hex Decode', body: { input: '74657374' } },
            
            // File operations
            { method: 'GET', endpoint: '/files', name: 'File Listing' },
            { method: 'POST', endpoint: '/upload', name: 'File Upload', body: { filename: 'test.txt', base64: 'dGVzdA==' } },
            { method: 'GET', endpoint: '/download?filename=test.txt', name: 'File Download' },
            { method: 'POST', endpoint: '/fileops', name: 'File Operations', body: { operation: 'copy', input: 'test.txt', output: 'test_copy.txt' } },
            
            // System information
            { method: 'GET', endpoint: '/sysinfo', name: 'System Information' },
            { method: 'GET', endpoint: '/processes', name: 'Process Listing' },
            { method: 'GET', endpoint: '/time', name: 'Time Information' },
            { method: 'GET', endpoint: '/uuid', name: 'UUID Generation' },
            
            // Utility endpoints
            { method: 'POST', endpoint: '/password', name: 'Password Generation', body: { length: 12 } },
            { method: 'POST', endpoint: '/random', name: 'Random Generation', body: { length: 16 } },
            { method: 'POST', endpoint: '/math', name: 'Math Operations', body: { expression: '5 + 3' } },
            { method: 'POST', endpoint: '/textops', name: 'Text Operations', body: { operation: 'uppercase', input: 'hello' } },
            
            // Panel endpoints
            { method: 'GET', endpoint: '/panel', name: 'Main Panel' },
            { method: 'GET', endpoint: '/irc-bot-builder', name: 'IRC Bot Builder' },
            { method: 'GET', endpoint: '/http-bot-panel', name: 'HTTP Bot Panel' },
            { method: 'GET', endpoint: '/stub-generator-panel', name: 'Stub Generator Panel' },
            { method: 'GET', endpoint: '/health-dashboard', name: 'Health Dashboard' },
            { method: 'GET', endpoint: '/bot-manager', name: 'Bot Manager' },
            { method: 'GET', endpoint: '/unified', name: 'Unified Panel' },
            
            // OpenSSL endpoints
            { method: 'GET', endpoint: '/openssl/config', name: 'OpenSSL Config' },
            { method: 'GET', endpoint: '/openssl/algorithms', name: 'OpenSSL Algorithms' },
            { method: 'GET', endpoint: '/openssl/openssl-algorithms', name: 'OpenSSL Native Algorithms' },
            { method: 'GET', endpoint: '/openssl/custom-algorithms', name: 'OpenSSL Custom Algorithms' },
            { method: 'POST', endpoint: '/openssl/toggle-openssl', name: 'Toggle OpenSSL', body: { enabled: true } },
            { method: 'POST', endpoint: '/openssl/toggle-custom', name: 'Toggle Custom Algorithms', body: { enabled: true } },
            
            // Additional endpoints
            { method: 'POST', endpoint: '/analyze', name: 'File Analysis', body: { input: 'server.js' } },
            { method: 'POST', endpoint: '/malware-scan', name: 'Malware Scan', body: { target: 'server.js' } },
            { method: 'POST', endpoint: '/vulnerability-check', name: 'Vulnerability Check', body: { target: 'localhost' } },
            { method: 'POST', endpoint: '/threat-detection', name: 'Threat Detection', body: { target: 'localhost' } },
            { method: 'POST', endpoint: '/encrypt-file', name: 'Encrypt File', body: { file: 'server.js', algorithm: 'aes-256-cbc' } },
            { method: 'POST', endpoint: '/decrypt-file', name: 'Decrypt File', body: { file: 'encrypted_file', algorithm: 'aes-256-cbc' } },
            { method: 'POST', endpoint: '/api/irc/message', name: 'IRC Message', body: { channel: '#test', message: 'Hello' } }
        ];

        console.log(`Testing ${allEndpoints.length} endpoints...\n`);

        for (const endpoint of allEndpoints) {
            const success = await this.testEndpoint(endpoint.method, endpoint.endpoint, endpoint.name, endpoint.body);
            const icon = success ? '✅' : '❌';
            console.log(`${icon} ${endpoint.name} (${endpoint.method} ${endpoint.endpoint})`);
        }

        this.printResults();
    }

    printResults() {
        console.log('\n' + '='.repeat(80));
        console.log('📊 COMPLETE ENDPOINT TEST RESULTS');
        console.log('='.repeat(80));
        console.log(`✅ Passed: ${this.results.passed}`);
        console.log(`❌ Failed: ${this.results.failed}`);
        console.log(`📈 Success Rate: ${((this.results.passed / (this.results.passed + this.results.failed)) * 100).toFixed(1)}%`);
        console.log(`📊 Total Endpoints Tested: ${this.results.passed + this.results.failed}`);

        if (this.results.failed > 0) {
            console.log('\n❌ Failed Endpoints:');
            this.results.tests
                .filter(test => test.status === 'FAIL')
                .forEach(test => {
                    console.log(`   ${test.method} ${test.endpoint} - ${test.details}`);
                });
        }

        if (this.results.passed === this.results.passed + this.results.failed) {
            console.log('\n🎉 ALL ENDPOINTS WORKING! RawrZ platform is 100% operational!');
        } else {
            console.log(`\n⚠️  ${this.results.failed} endpoints need attention.`);
        }

        console.log('\n' + '='.repeat(80));
    }
}

// Run the complete test
async function main() {
    const tester = new CompleteEndpointTester();
    await tester.runCompleteTest();
}

if (require.main === module) {
    main().catch(console.error);
}

module.exports = CompleteEndpointTester;
