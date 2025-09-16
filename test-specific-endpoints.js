// Test script for the previously failing endpoints
const http = require('http');

class FailingEndpointTester {
    constructor() {
        this.baseUrl = 'http://localhost:8080';
        this.failingEndpoints = [
            { method: 'GET', endpoint: '/beaconism/status' },
            { method: 'POST', endpoint: '/beaconism/generate-payload', body: { target: 'test-target', payloadType: 'dll' } },
            { method: 'GET', endpoint: '/red-shells/status' },
            { method: 'POST', endpoint: '/red-shells/create', body: { shellType: 'powershell' } },
            { method: 'POST', endpoint: '/mutex/generate', body: { language: 'cpp' } },
            { method: 'POST', endpoint: '/mutex/apply', body: { code: 'test code', language: 'cpp' } },
            { method: 'POST', endpoint: '/hot-patch', body: { target: 'test-target' } },
            { method: 'POST', endpoint: '/patch-rollback', body: { patchId: 'test-patch-id' } },
            { method: 'POST', endpoint: '/download-file', body: { url: 'https://example.com/test.txt' } },
            { method: 'POST', endpoint: '/read-local-file', body: { filename: 'server.js' } }
        ];
    }

    async makeRequest(method, endpoint, body = null) {
        return new Promise((resolve, reject) => {
            const url = `${this.baseUrl}${endpoint}`;
            const options = {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer test-token'
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

    async testEndpoint(endpointInfo) {
        const { method, endpoint, body } = endpointInfo;
        const name = `${method} ${endpoint}`;
        
        try {
            const response = await this.makeRequest(method, endpoint, body);
            
            if (response.status === 200) {
                console.log(`✅ ${name} - Status: ${response.status}`);
                return true;
            } else {
                console.log(`❌ ${name} - Status: ${response.status}, Error: ${response.data.error || 'Unknown error'}`);
                return false;
            }
            
        } catch (error) {
            console.log(`❌ ${name} - Error: ${error.message}`);
            return false;
        }
    }

    async runTests() {
        console.log('🧪 Testing Previously Failing Endpoints...\n');
        
        let passed = 0;
        let failed = 0;
        
        for (const endpoint of this.failingEndpoints) {
            const success = await this.testEndpoint(endpoint);
            if (success) {
                passed++;
            } else {
                failed++;
            }
            // Small delay between requests
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        
        console.log(`\n📊 Results: ${passed} passed, ${failed} failed`);
        console.log(`📈 Success Rate: ${((passed / (passed + failed)) * 100).toFixed(1)}%`);
    }
}

// Run the tests
async function main() {
    const tester = new FailingEndpointTester();
    await tester.runTests();
}

if (require.main === module) {
    main().catch(console.error);
}
