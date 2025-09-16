// Comprehensive Test for ALL 294 RawrZ Endpoints with Proper Parameters
const http = require('http');
const fs = require('fs');

class ComprehensiveEndpointTester {
    constructor() {
        this.baseUrl = 'http://localhost:8080';
        this.results = {
            passed: 0,
            failed: 0,
            tests: []
        };
        this.endpointData = null;
        this.loadEndpointData();
    }

    loadEndpointData() {
        try {
            const data = fs.readFileSync('endpoint-analysis.json', 'utf8');
            this.endpointData = JSON.parse(data);
            console.log(`📊 Loaded ${this.endpointData.totalEndpoints} endpoints for testing`);
        } catch (error) {
            console.error('Failed to load endpoint data:', error);
            process.exit(1);
        }
    }

    async makeRequest(method, endpoint, body = null, headers = {}) {
        return new Promise((resolve, reject) => {
            const url = `${this.baseUrl}${endpoint}`;
            const options = {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                    ...headers
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
            req.setTimeout(15000, () => {
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
        const { method, endpoint, testParams } = endpointInfo;
        const name = `${method} ${endpoint}`;
        
        try {
            // Handle parameterized endpoints
            let actualEndpoint = endpoint;
            if (endpoint.includes(':')) {
                actualEndpoint = endpoint.replace(/:\w+/g, 'test-id');
            }

            const response = await this.makeRequest(
                method, 
                actualEndpoint, 
                testParams.body, 
                testParams.headers
            );
            
            // Determine expected status based on endpoint type
            let expectedStatus = 200;
            if (endpoint.startsWith('/api/') && !testParams.headers.Authorization) {
                expectedStatus = 401; // Unauthorized
            } else if (method === 'POST' && !testParams.body) {
                expectedStatus = 400; // Bad Request
            }

            if (response.status === expectedStatus || response.status === 200) {
                this.results.passed++;
                this.results.tests.push({ 
                    name, 
                    method, 
                    endpoint: actualEndpoint, 
                    status: 'PASS', 
                    details: `Status: ${response.status}`,
                    category: endpointInfo.category
                });
                return true;
            } else {
                this.results.failed++;
                this.results.tests.push({ 
                    name, 
                    method, 
                    endpoint: actualEndpoint, 
                    status: 'FAIL', 
                    details: `Expected: ${expectedStatus}, Got: ${response.status}`,
                    category: endpointInfo.category
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
                details: error.message,
                category: endpointInfo.category
            });
            return false;
        }
    }

    async runAllTests() {
        console.log('🚀 Starting Comprehensive Test of ALL 294 RawrZ Endpoints...\n');
        console.log('='.repeat(80));

        // Test by category
        const categories = {};
        this.endpointData.endpoints.forEach(ep => {
            if (!categories[ep.category]) categories[ep.category] = [];
            categories[ep.category].push(ep);
        });

        for (const [category, endpoints] of Object.entries(categories)) {
            console.log(`\n📋 TESTING ${category.toUpperCase()} (${endpoints.length} endpoints)`);
            console.log('-'.repeat(50));
            
            for (const endpoint of endpoints) {
                await this.testEndpoint(endpoint);
                // Small delay to avoid overwhelming the server
                await new Promise(resolve => setTimeout(resolve, 10));
            }
        }

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
        console.log(`📊 Total Endpoints: ${total}`);
        
        // Category breakdown
        console.log('\n📊 RESULTS BY CATEGORY');
        console.log('-'.repeat(40));
        const categoryResults = {};
        this.results.tests.forEach(test => {
            if (!categoryResults[test.category]) {
                categoryResults[test.category] = { passed: 0, failed: 0 };
            }
            if (test.status === 'PASS') {
                categoryResults[test.category].passed++;
            } else {
                categoryResults[test.category].failed++;
            }
        });

        Object.entries(categoryResults).forEach(([category, results]) => {
            const total = results.passed + results.failed;
            const rate = total > 0 ? ((results.passed / total) * 100).toFixed(1) : 0;
            console.log(`  ${category}: ${results.passed}/${total} (${rate}%)`);
        });
        
        if (this.results.failed > 0) {
            console.log('\n❌ Failed Endpoints:');
            this.results.tests.filter(t => t.status === 'FAIL').slice(0, 20).forEach(test => {
                console.log(`   ${test.method} ${test.endpoint} - ${test.details}`);
            });
            if (this.results.failed > 20) {
                console.log(`   ... and ${this.results.failed - 20} more failures`);
            }
        }
        
        if (this.results.failed === 0) {
            console.log('\n🎉 ALL ENDPOINT TESTS PASSED! RawrZ is fully functional!');
        } else {
            console.log(`\n⚠️  ${this.results.failed} endpoint tests failed. Check the details above.`);
        }
        
        console.log('\n' + '='.repeat(80));
        
        // Save detailed results
        this.saveDetailedResults();
    }

    saveDetailedResults() {
        const report = {
            timestamp: new Date().toISOString(),
            summary: {
                total: this.results.passed + this.results.failed,
                passed: this.results.passed,
                failed: this.results.failed,
                successRate: ((this.results.passed / (this.results.passed + this.results.failed)) * 100).toFixed(1)
            },
            results: this.results.tests
        };

        fs.writeFileSync('endpoint-test-results.json', JSON.stringify(report, null, 2));
        console.log('💾 Detailed test results saved to endpoint-test-results.json');
    }
}

// Run the tests
async function main() {
    const tester = new ComprehensiveEndpointTester();
    await tester.runAllTests();
}

if (require.main === module) {
    main().catch(console.error);
}

module.exports = ComprehensiveEndpointTester;
