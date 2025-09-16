// RawrZ Web Panel Dropdown Test Suite
// Tests all dropdown functionality on the web interface

const http = require('http');
const https = require('https');

class WebPanelDropdownTester {
    constructor() {
        this.baseUrl = 'http://localhost:8080';
        this.results = {
            passed: 0,
            failed: 0,
            tests: []
        };
    }

    async makeRequest(endpoint) {
        return new Promise((resolve, reject) => {
            const url = `${this.baseUrl}${endpoint}`;
            const client = url.startsWith('https') ? https : http;
            
            const req = client.get(url, (res) => {
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
            req.setTimeout(5000, () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });
        });
    }

    async testDropdown(endpoint, name, expectedFields = []) {
        try {
            console.log(`\n🔍 Testing ${name} dropdown...`);
            const response = await this.makeRequest(endpoint);
            
            if (response.status === 200) {
                console.log(`✅ ${name} endpoint accessible`);
                
                if (expectedFields.length > 0 && response.data) {
                    const missingFields = expectedFields.filter(field => 
                        !response.data.hasOwnProperty(field) && 
                        !JSON.stringify(response.data).includes(field)
                    );
                    
                    if (missingFields.length === 0) {
                        console.log(`✅ ${name} contains expected data fields`);
                        this.results.passed++;
                        this.results.tests.push({ name, status: 'PASS', details: 'All fields present' });
                    } else {
                        console.log(`❌ ${name} missing fields: ${missingFields.join(', ')}`);
                        this.results.failed++;
                        this.results.tests.push({ name, status: 'FAIL', details: `Missing: ${missingFields.join(', ')}` });
                    }
                } else {
                    console.log(`✅ ${name} data structure valid`);
                    this.results.passed++;
                    this.results.tests.push({ name, status: 'PASS', details: 'Data structure valid' });
                }
                
                // Log sample data for debugging
                if (response.data && typeof response.data === 'object') {
                    const sampleKeys = Object.keys(response.data).slice(0, 3);
                    console.log(`📊 Sample data keys: ${sampleKeys.join(', ')}`);
                }
                
            } else {
                console.log(`❌ ${name} endpoint failed with status: ${response.status}`);
                this.results.failed++;
                this.results.tests.push({ name, status: 'FAIL', details: `HTTP ${response.status}` });
            }
            
        } catch (error) {
            console.log(`❌ ${name} test failed: ${error.message}`);
            this.results.failed++;
            this.results.tests.push({ name, status: 'FAIL', details: error.message });
        }
    }

    async runAllTests() {
        console.log('🚀 Starting RawrZ Web Panel Dropdown Tests...\n');
        console.log('=' * 60);

        // Test main dropdown endpoints
        await this.testDropdown('/api/algorithms', 'Algorithms Dropdown', ['algorithms', 'available']);
        await this.testDropdown('/api/engines', 'Engines Dropdown', ['engines', 'available']);
        await this.testDropdown('/api/features', 'Features Dropdown', ['features', 'available']);
        await this.testDropdown('/api/status', 'Health Status Dropdown', ['status', 'engines', 'features']);
        await this.testDropdown('/api/health', 'Health Check Dropdown', ['ok', 'status']);
        
        // Test crypto-specific dropdowns
        await this.testDropdown('/api/crypto/algorithms', 'Crypto Algorithms', ['algorithms']);
        await this.testDropdown('/api/crypto/modes', 'Crypto Modes', ['modes']);
        await this.testDropdown('/api/crypto/key-sizes', 'Key Sizes', ['sizes']);
        
        // Test bot generation dropdowns
        await this.testDropdown('/api/bots/languages', 'Bot Languages', ['languages']);
        await this.testDropdown('/api/bots/features', 'Bot Features', ['features']);
        await this.testDropdown('/api/bots/templates', 'Bot Templates', ['templates']);
        
        // Test analysis dropdowns
        await this.testDropdown('/api/analysis/tools', 'Analysis Tools', ['tools']);
        await this.testDropdown('/api/analysis/engines', 'Analysis Engines', ['engines']);
        
        // Test compilation dropdowns
        await this.testDropdown('/api/compile/languages', 'Compile Languages', ['languages']);
        await this.testDropdown('/api/compile/targets', 'Compile Targets', ['targets']);
        
        // Test network dropdowns
        await this.testDropdown('/api/network/ports', 'Network Ports', ['ports']);
        await this.testDropdown('/api/network/protocols', 'Network Protocols', ['protocols']);

        // Test main interface
        await this.testDropdown('/', 'Main Interface', ['html', 'title']);

        this.printResults();
    }

    printResults() {
        console.log('\n' + '=' * 60);
        console.log('📊 DROPDOWN TEST RESULTS');
        console.log('=' * 60);
        
        console.log(`✅ Passed: ${this.results.passed}`);
        console.log(`❌ Failed: ${this.results.failed}`);
        console.log(`📈 Success Rate: ${((this.results.passed / (this.results.passed + this.results.failed)) * 100).toFixed(1)}%`);
        
        console.log('\n📋 Detailed Results:');
        this.results.tests.forEach(test => {
            const icon = test.status === 'PASS' ? '✅' : '❌';
            console.log(`${icon} ${test.name}: ${test.status} - ${test.details}`);
        });
        
        if (this.results.failed === 0) {
            console.log('\n🎉 ALL DROPDOWN TESTS PASSED! Web panel dropdowns are fully functional!');
        } else {
            console.log('\n⚠️  Some dropdown tests failed. Check the details above.');
        }
        
        console.log('\n' + '=' * 60);
    }
}

// Run the tests
async function main() {
    const tester = new WebPanelDropdownTester();
    await tester.runAllTests();
}

if (require.main === module) {
    main().catch(console.error);
}

module.exports = WebPanelDropdownTester;
