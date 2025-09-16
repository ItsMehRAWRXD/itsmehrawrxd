// Simple endpoint test to identify actual failures
const http = require('http');

const endpoints = [
    { method: 'GET', path: '/health', name: 'Health Check' },
    { method: 'GET', path: '/api/health', name: 'API Health' },
    { method: 'GET', path: '/api/status', name: 'API Status' },
    { method: 'GET', path: '/api/algorithms', name: 'API Algorithms' },
    { method: 'GET', path: '/api/engines', name: 'API Engines' },
    { method: 'GET', path: '/api/features', name: 'API Features' },
    { method: 'GET', path: '/ping', name: 'Ping' },
    { method: 'GET', path: '/dns', name: 'DNS' },
    { method: 'GET', path: '/uuid', name: 'UUID' },
    { method: 'GET', path: '/time', name: 'Time' },
    { method: 'GET', path: '/sysinfo', name: 'System Info' },
    { method: 'GET', path: '/processes', name: 'Processes' },
    { method: 'GET', path: '/files', name: 'Files' },
    { method: 'GET', path: '/openssl/config', name: 'OpenSSL Config' },
    { method: 'GET', path: '/openssl/algorithms', name: 'OpenSSL Algorithms' },
    { method: 'GET', path: '/openssl-management/status', name: 'OpenSSL Management Status' },
    { method: 'GET', path: '/implementation-check/status', name: 'Implementation Check Status' },
    { method: 'GET', path: '/health-monitor/status', name: 'Health Monitor Status' },
    { method: 'GET', path: '/red-killer/status', name: 'Red Killer Status' },
    { method: 'GET', path: '/beaconism/status', name: 'Beaconism Status' },
    { method: 'GET', path: '/red-shells/status', name: 'Red Shells Status' },
    { method: 'GET', path: '/stub-generator/status', name: 'Stub Generator Status' },
    { method: 'GET', path: '/native-compiler/stats', name: 'Native Compiler Stats' },
    { method: 'GET', path: '/jotti/info', name: 'Jotti Info' },
    { method: 'GET', path: '/api-status', name: 'API Status' },
    { method: 'GET', path: '/performance-monitor', name: 'Performance Monitor' },
    { method: 'GET', path: '/memory-info', name: 'Memory Info' },
    { method: 'GET', path: '/cpu-usage', name: 'CPU Usage' },
    { method: 'GET', path: '/disk-usage', name: 'Disk Usage' },
    { method: 'GET', path: '/network-stats', name: 'Network Stats' },
    { method: 'GET', path: '/backup-list', name: 'Backup List' },
    { method: 'GET', path: '/ev-cert/status', name: 'EV Cert Status' },
    { method: 'GET', path: '/ev-cert/certificates', name: 'EV Cert Certificates' },
    { method: 'GET', path: '/ev-cert/stubs', name: 'EV Cert Stubs' },
    { method: 'GET', path: '/ev-cert/templates', name: 'EV Cert Templates' },
    { method: 'GET', path: '/ev-cert/languages', name: 'EV Cert Languages' },
    { method: 'GET', path: '/ev-cert/algorithms', name: 'EV Cert Algorithms' },
    { method: 'GET', path: '/beaconism/payloads', name: 'Beaconism Payloads' },
    { method: 'GET', path: '/beaconism/targets', name: 'Beaconism Targets' },
    { method: 'GET', path: '/red-shells', name: 'Red Shells' },
    { method: 'GET', path: '/red-shells/stats', name: 'Red Shells Stats' },
    { method: 'GET', path: '/advanced-features', name: 'Advanced Features' },
    { method: 'GET', path: '/stub-generator/templates', name: 'Stub Generator Templates' },
    { method: 'GET', path: '/stub-generator/active', name: 'Stub Generator Active' },
    { method: 'GET', path: '/stub-generator/packing-methods', name: 'Stub Generator Packing Methods' },
    { method: 'GET', path: '/stub-generator/fud-techniques', name: 'Stub Generator FUD Techniques' },
    { method: 'GET', path: '/stub-generator/auto-regeneration/status', name: 'Stub Generator Auto Regeneration Status' },
    { method: 'GET', path: '/stub-generator/unpacked', name: 'Stub Generator Unpacked' },
    { method: 'GET', path: '/stub-generator/repack-history', name: 'Stub Generator Repack History' },
    { method: 'GET', path: '/stub-generator/comprehensive-stats', name: 'Stub Generator Comprehensive Stats' },
    { method: 'GET', path: '/native-compiler/supported-languages', name: 'Native Compiler Supported Languages' },
    { method: 'GET', path: '/native-compiler/available-compilers', name: 'Native Compiler Available Compilers' },
    { method: 'GET', path: '/jotti/test-connection', name: 'Jotti Test Connection' },
    { method: 'GET', path: '/implementation-check/results', name: 'Implementation Check Results' },
    { method: 'GET', path: '/implementation-check/modules', name: 'Implementation Check Modules' },
    { method: 'GET', path: '/red-killer/loot', name: 'Red Killer Loot' },
    { method: 'GET', path: '/red-killer/kills', name: 'Red Killer Kills' },
    { method: 'GET', path: '/openssl/openssl-algorithms', name: 'OpenSSL OpenSSL Algorithms' },
    { method: 'GET', path: '/openssl/custom-algorithms', name: 'OpenSSL Custom Algorithms' },
    { method: 'GET', path: '/openssl-management/report', name: 'OpenSSL Management Report' },
    { method: 'GET', path: '/api/compile/languages', name: 'API Compile Languages' },
    { method: 'GET', path: '/api/compile/targets', name: 'API Compile Targets' },
    { method: 'GET', path: '/api/dashboard/stats', name: 'API Dashboard Stats' },
    { method: 'GET', path: '/api/irc/channels', name: 'API IRC Channels' },
    { method: 'GET', path: '/api/bots/languages', name: 'API Bots Languages' },
    { method: 'GET', path: '/api/bots/features', name: 'API Bots Features' },
    { method: 'GET', path: '/api/bots/templates', name: 'API Bots Templates' },
    { method: 'GET', path: '/api/bots/status', name: 'API Bots Status' },
    { method: 'GET', path: '/api/analysis/tools', name: 'API Analysis Tools' },
    { method: 'GET', path: '/api/analysis/engines', name: 'API Analysis Engines' },
    { method: 'GET', path: '/api/crypto/algorithms', name: 'API Crypto Algorithms' },
    { method: 'GET', path: '/api/crypto/modes', name: 'API Crypto Modes' },
    { method: 'GET', path: '/api/crypto/key-sizes', name: 'API Crypto Key Sizes' },
    { method: 'GET', path: '/api/network/ports', name: 'API Network Ports' },
    { method: 'GET', path: '/api/network/protocols', name: 'API Network Protocols' },
    { method: 'GET', path: '/panel', name: 'Panel' },
    { method: 'GET', path: '/irc-bot-builder', name: 'IRC Bot Builder' },
    { method: 'GET', path: '/http-bot-panel', name: 'HTTP Bot Panel' },
    { method: 'GET', path: '/stub-generator-panel', name: 'Stub Generator Panel' },
    { method: 'GET', path: '/health-dashboard', name: 'Health Dashboard' },
    { method: 'GET', path: '/health-monitor/dashboard', name: 'Health Monitor Dashboard' },
    { method: 'GET', path: '/bot-manager', name: 'Bot Manager' },
    { method: 'GET', path: '/', name: 'Root' }
];

async function testEndpoint(endpoint) {
    return new Promise((resolve) => {
        const options = {
            hostname: 'localhost',
            port: 8080,
            path: endpoint.path,
            method: endpoint.method,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                resolve({
                    name: endpoint.name,
                    method: endpoint.method,
                    path: endpoint.path,
                    status: res.statusCode,
                    success: res.statusCode >= 200 && res.statusCode < 400
                });
            });
        });

        req.on('error', (err) => {
            resolve({
                name: endpoint.name,
                method: endpoint.method,
                path: endpoint.path,
                status: 'ERROR',
                success: false,
                error: err.message
            });
        });

        req.setTimeout(5000, () => {
            req.destroy();
            resolve({
                name: endpoint.name,
                method: endpoint.method,
                path: endpoint.path,
                status: 'TIMEOUT',
                success: false,
                error: 'Request timeout'
            });
        });

        req.end();
    });
}

async function runTests() {
    console.log('🚀 Testing RawrZ Endpoints...\n');
    
    const results = [];
    let passed = 0;
    let failed = 0;

    for (const endpoint of endpoints) {
        const result = await testEndpoint(endpoint);
        results.push(result);
        
        if (result.success) {
            passed++;
            console.log(`✅ ${result.name} (${result.method} ${result.path}) - Status: ${result.status}`);
        } else {
            failed++;
            console.log(`❌ ${result.name} (${result.method} ${result.path}) - Status: ${result.status}${result.error ? ' - ' + result.error : ''}`);
        }
    }

    console.log(`\n📊 Results: ${passed} passed, ${failed} failed`);
    console.log(`📈 Success Rate: ${((passed / (passed + failed)) * 100).toFixed(1)}%`);
    
    if (failed > 0) {
        console.log('\n❌ Failed Endpoints:');
        results.filter(r => !r.success).forEach(r => {
            console.log(`   ${r.method} ${r.path} - ${r.status}${r.error ? ' (' + r.error + ')' : ''}`);
        });
    }
}

runTests().catch(console.error);
