// Comprehensive endpoint test focusing on the previously failing endpoints
const http = require('http');

async function testEndpoint(method, endpoint, body = null) {
    return new Promise((resolve, reject) => {
        const options = {
            method: method,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        const req = http.request(`http://localhost:8080${endpoint}`, options, (res) => {
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

async function runComprehensiveTest() {
    console.log('🚀 Comprehensive Endpoint Test - Previously Failing Endpoints\n');
    console.log('='.repeat(70));
    
    const tests = [
        // Analysis endpoints
        { method: 'POST', endpoint: '/api/analysis/malware', body: { file: 'server.js' }, name: 'Malware Analysis' },
        { method: 'POST', endpoint: '/api/analysis/digital-forensics', body: {}, name: 'Digital Forensics' },
        
        // Security endpoints  
        { method: 'POST', endpoint: '/api/security/fud-analysis', body: {}, name: 'FUD Analysis' },
        { method: 'POST', endpoint: '/api/security/stealth-mode', body: {}, name: 'Stealth Mode' },
        { method: 'POST', endpoint: '/api/security/anti-detection', body: {}, name: 'Anti-Detection' },
        
        // Crypto endpoints
        { method: 'POST', endpoint: '/api/crypto/generate-report', body: {}, name: 'Generate Report' },
        { method: 'POST', endpoint: '/base64encode', body: { input: 'test' }, name: 'Base64 Encode' },
        
        // Network endpoints
        { method: 'GET', endpoint: '/ping', name: 'Ping Test' },
        { method: 'GET', endpoint: '/dns', name: 'DNS Lookup' },
        { method: 'POST', endpoint: '/traceroute', body: { host: 'google.com' }, name: 'Traceroute' },
        
        // Additional endpoints to verify
        { method: 'GET', endpoint: '/api/health', name: 'Health Check' },
        { method: 'GET', endpoint: '/api/status', name: 'Status Check' },
        { method: 'GET', endpoint: '/api/algorithms', name: 'Algorithms' },
        { method: 'POST', endpoint: '/encrypt', body: { algorithm: 'aes-256-cbc', input: 'test', key: 'testkey123456789012345678901234' }, name: 'Encryption' },
        { method: 'POST', endpoint: '/hash', body: { algorithm: 'sha256', input: 'test' }, name: 'Hashing' }
    ];
    
    let passed = 0;
    let failed = 0;
    const results = [];
    
    for (const test of tests) {
        try {
            console.log(`\n🔍 Testing ${test.name} (${test.method} ${test.endpoint})...`);
            const result = await testEndpoint(test.method, test.endpoint, test.body);
            
            if (result.status === 200) {
                console.log(`✅ ${test.name} - Status: ${result.status}`);
                passed++;
                results.push({ name: test.name, status: 'PASS', details: `Status: ${result.status}` });
            } else {
                console.log(`❌ ${test.name} - Status: ${result.status}`);
                failed++;
                results.push({ name: test.name, status: 'FAIL', details: `Status: ${result.status}` });
            }
        } catch (error) {
            console.log(`❌ ${test.name} - Error: ${error.message}`);
            failed++;
            results.push({ name: test.name, status: 'FAIL', details: error.message });
        }
    }
    
    console.log('\n' + '='.repeat(70));
    console.log('📊 COMPREHENSIVE ENDPOINT TEST RESULTS');
    console.log('='.repeat(70));
    console.log(`✅ Passed: ${passed}`);
    console.log(`❌ Failed: ${failed}`);
    console.log(`📈 Success Rate: ${((passed / (passed + failed)) * 100).toFixed(1)}%`);
    
    console.log('\n📋 Detailed Results:');
    results.forEach(result => {
        const icon = result.status === 'PASS' ? '✅' : '❌';
        console.log(`${icon} ${result.name}: ${result.status} - ${result.details}`);
    });
    
    if (failed === 0) {
        console.log('\n🎉 ALL ENDPOINT TESTS PASSED! RawrZ platform is fully operational!');
    } else {
        console.log(`\n⚠️  ${failed} endpoint tests failed. Check the details above.`);
    }
    
    console.log('\n' + '='.repeat(70));
}

runComprehensiveTest().catch(console.error);
