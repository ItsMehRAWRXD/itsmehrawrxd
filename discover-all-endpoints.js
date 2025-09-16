const fs = require('fs');

function discoverEndpoints() {
    const serverContent = fs.readFileSync('server.js', 'utf8');
    const endpoints = [];
    
    // Find all app.get, app.post, app.put, app.delete, app.patch patterns
    const patterns = [
        /app\.get\s*\(\s*['"`]([^'"`]+)['"`]/g,
        /app\.post\s*\(\s*['"`]([^'"`]+)['"`]/g,
        /app\.put\s*\(\s*['"`]([^'"`]+)['"`]/g,
        /app\.delete\s*\(\s*['"`]([^'"`]+)['"`]/g,
        /app\.patch\s*\(\s*['"`]([^'"`]+)['"`]/g
    ];
    
    const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
    
    patterns.forEach((pattern, index) => {
        let match;
        while ((match = pattern.exec(serverContent)) !== null) {
            endpoints.push({
                method: methods[index],
                path: match[1],
                line: serverContent.substring(0, match.index).split('\n').length
            });
        }
    });
    
    return endpoints;
}

function categorizeEndpoints(endpoints) {
    const categories = {
        'API Endpoints': [],
        'Panel Routes': [],
        'Static Routes': [],
        'Health/Status': [],
        'Bot Generation': [],
        'Analysis': [],
        'Security': [],
        'Crypto': [],
        'Network': [],
        'Utility': [],
        'Other': []
    };
    
    endpoints.forEach(endpoint => {
        const path = endpoint.path;
        
        if (path.startsWith('/api/')) {
            if (path.includes('/bot') || path.includes('/generate')) {
                categories['Bot Generation'].push(endpoint);
            } else if (path.includes('/analysis')) {
                categories['Analysis'].push(endpoint);
            } else if (path.includes('/security')) {
                categories['Security'].push(endpoint);
            } else if (path.includes('/crypto')) {
                categories['Crypto'].push(endpoint);
            } else if (path.includes('/network')) {
                categories['Network'].push(endpoint);
            } else {
                categories['API Endpoints'].push(endpoint);
            }
        } else if (path.includes('panel') || path.includes('dashboard') || path.includes('builder')) {
            categories['Panel Routes'].push(endpoint);
        } else if (path === '/' || path === '/health' || path === '/status') {
            categories['Health/Status'].push(endpoint);
        } else if (path.includes('bot') || path.includes('generate')) {
            categories['Bot Generation'].push(endpoint);
        } else if (path.includes('analyze') || path.includes('scan')) {
            categories['Analysis'].push(endpoint);
        } else if (path.includes('encrypt') || path.includes('decrypt') || path.includes('hash') || path.includes('crypto')) {
            categories['Crypto'].push(endpoint);
        } else if (path.includes('ping') || path.includes('dns') || path.includes('traceroute') || path.includes('whois')) {
            categories['Network'].push(endpoint);
        } else if (path.includes('uuid') || path.includes('password') || path.includes('random') || path.includes('time') || path.includes('math')) {
            categories['Utility'].push(endpoint);
        } else {
            categories['Other'].push(endpoint);
        }
    });
    
    return categories;
}

function generateTestScript(endpoints) {
    const categories = categorizeEndpoints(endpoints);
    
    let testScript = `// Comprehensive Test for ALL ${endpoints.length} RawrZ Endpoints
const http = require('http');

class ComprehensiveEndpointTester {
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
            const url = \`\${this.baseUrl}\${endpoint}\`;
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
            const response = await this.makeRequest(method, endpoint, body);
            
            if (response.status === expectedStatus) {
                this.results.passed++;
                this.results.tests.push({ 
                    name, 
                    method, 
                    endpoint, 
                    status: 'PASS', 
                    details: \`Status: \${response.status}\` 
                });
                return true;
            } else {
                this.results.failed++;
                this.results.tests.push({ 
                    name, 
                    method, 
                    endpoint, 
                    status: 'FAIL', 
                    details: \`Expected: \${expectedStatus}, Got: \${response.status}\` 
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

    async runAllTests() {
        console.log('🚀 Starting Comprehensive Test of ALL ${endpoints.length} RawrZ Endpoints...\\n');
        console.log('='.repeat(80));

`;

    // Generate test code for each category
    Object.entries(categories).forEach(([categoryName, categoryEndpoints]) => {
        if (categoryEndpoints.length > 0) {
            testScript += `        // Test ${categoryName} (${categoryEndpoints.length} endpoints)
        console.log('\\n📋 TESTING ${categoryName.toUpperCase()}');
        console.log('-'.repeat(40));
`;
            
            categoryEndpoints.forEach(endpoint => {
                const testName = endpoint.path.replace(/[^a-zA-Z0-9]/g, ' ').trim();
                const body = endpoint.method === 'POST' || endpoint.method === 'PUT' || endpoint.method === 'PATCH' ? '{}' : 'null';
                
                testScript += `        await this.testEndpoint('${endpoint.method}', '${endpoint.path}', '${testName}', 200, ${body});
`;
            });
            
            testScript += '\n';
        }
    });

    testScript += `        this.printResults();
    }

    printResults() {
        console.log('\\n' + '='.repeat(80));
        console.log('📊 COMPREHENSIVE ENDPOINT TEST RESULTS');
        console.log('='.repeat(80));
        
        const total = this.results.passed + this.results.failed;
        const successRate = total > 0 ? ((this.results.passed / total) * 100).toFixed(1) : 0;
        
        console.log(\`✅ Passed: \${this.results.passed}\`);
        console.log(\`❌ Failed: \${this.results.failed}\`);
        console.log(\`📈 Success Rate: \${successRate}%\`);
        console.log(\`📊 Total Endpoints: \${total}\`);
        
        if (this.results.failed > 0) {
            console.log('\\n❌ Failed Endpoints:');
            this.results.tests.filter(t => t.status === 'FAIL').forEach(test => {
                console.log(\`   \${test.method} \${test.endpoint} - \${test.details}\`);
            });
        }
        
        if (this.results.failed === 0) {
            console.log('\\n🎉 ALL ENDPOINT TESTS PASSED! RawrZ is fully functional!');
        } else {
            console.log(\`\\n⚠️  \${this.results.failed} endpoint tests failed. Check the details above.\`);
        }
        
        console.log('\\n' + '='.repeat(80));
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
`;

    return testScript;
}

// Main execution
console.log('🔍 Discovering all endpoints in server.js...');
const endpoints = discoverEndpoints();
console.log(`📊 Found ${endpoints.length} endpoint definitions`);

const categories = categorizeEndpoints(endpoints);
console.log('\n📋 Endpoint Categories:');
Object.entries(categories).forEach(([name, endpoints]) => {
    if (endpoints.length > 0) {
        console.log(`   ${name}: ${endpoints.length} endpoints`);
    }
});

console.log('\n🔧 Generating comprehensive test script...');
const testScript = generateTestScript(endpoints);
fs.writeFileSync('test-all-291-endpoints.js', testScript);
console.log('✅ Generated test-all-291-endpoints.js');

console.log('\n📋 Sample endpoints by category:');
Object.entries(categories).forEach(([name, endpoints]) => {
    if (endpoints.length > 0) {
        console.log(`\n${name}:`);
        endpoints.slice(0, 5).forEach(ep => {
            console.log(`   ${ep.method} ${ep.path}`);
        });
        if (endpoints.length > 5) {
            console.log(`   ... and ${endpoints.length - 5} more`);
        }
    }
});
