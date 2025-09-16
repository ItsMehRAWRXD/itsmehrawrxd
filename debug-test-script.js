const http = require('http');

class DebugTester {
    constructor() {
        this.baseUrl = 'http://localhost:8080';
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
            console.log(`Body: ${body ? JSON.stringify(body) : 'null'}`);
            const response = await this.makeRequest(method, endpoint, body);
            
            console.log(`Status: ${response.status}`);
            console.log(`Response: ${JSON.stringify(response.data).substring(0, 200)}...`);
            
            if (response.status === expectedStatus) {
                console.log(`✅ ${name} - Status: ${response.status}`);
                return true;
            } else {
                console.log(`❌ ${name} - Expected: ${expectedStatus}, Got: ${response.status}`);
                return false;
            }
            
        } catch (error) {
            console.log(`❌ ${name} - Error: ${error.message}`);
            return false;
        }
    }

    async testFailingEndpoints() {
        console.log('🚀 Debug Testing Failing Endpoints...\n');

        const endpoints = [
            { method: 'POST', endpoint: '/api/analysis/digital-forensics', name: 'Digital Forensics', body: null },
            { method: 'POST', endpoint: '/api/security/fud-analysis', name: 'FUD Analysis', body: null },
            { method: 'POST', endpoint: '/api/security/stealth-mode', name: 'Stealth Mode', body: null },
            { method: 'POST', endpoint: '/api/security/anti-detection', name: 'Anti-Detection', body: null },
            { method: 'POST', endpoint: '/api/crypto/generate-report', name: 'Generate Report', body: null },
            { method: 'GET', endpoint: '/dns', name: 'DNS Lookup', body: null }
        ];

        let passed = 0;
        let failed = 0;

        for (const endpoint of endpoints) {
            const result = await this.testEndpoint(
                endpoint.method, 
                endpoint.endpoint, 
                endpoint.name, 
                200, 
                endpoint.body
            );
            
            if (result) {
                passed++;
            } else {
                failed++;
            }
            
            // Add a small delay between requests
            await new Promise(resolve => setTimeout(resolve, 100));
        }

        console.log(`\n📊 Results: ${passed} passed, ${failed} failed`);
    }
}

const tester = new DebugTester();
tester.testFailingEndpoints().catch(console.error);
