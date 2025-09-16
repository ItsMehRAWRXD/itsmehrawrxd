const http = require('http');

async function testEndpoint(method, endpoint, body = null) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'localhost',
            port: 8080,
            path: endpoint,
            method: method,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                resolve({
                    status: res.statusCode,
                    data: data,
                    headers: res.headers
                });
            });
        });

        req.on('error', reject);
        req.setTimeout(5000, () => {
            req.destroy();
            reject(new Error('Request timeout'));
        });

        if (body) {
            req.write(JSON.stringify(body));
        }
        req.end();
    });
}

async function testFailingEndpoints() {
    console.log('Testing failing endpoints...\n');

    const endpoints = [
        { method: 'POST', path: '/api/analysis/digital-forensics', body: {} },
        { method: 'POST', path: '/api/security/fud-analysis', body: {} },
        { method: 'POST', path: '/api/security/stealth-mode', body: {} },
        { method: 'POST', path: '/api/security/anti-detection', body: {} },
        { method: 'POST', path: '/api/crypto/generate-report', body: {} },
        { method: 'GET', path: '/dns?hostname=google.com', body: null }
    ];

    for (const endpoint of endpoints) {
        try {
            console.log(`Testing ${endpoint.method} ${endpoint.path}...`);
            const result = await testEndpoint(endpoint.method, endpoint.path, endpoint.body);
            console.log(`Status: ${result.status}`);
            console.log(`Response: ${result.data.substring(0, 200)}...`);
            console.log('---');
        } catch (error) {
            console.log(`Error: ${error.message}`);
            console.log('---');
        }
    }
}

testFailingEndpoints().catch(console.error);
