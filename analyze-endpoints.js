// RawrZ Endpoint Analysis and Categorization Script
const fs = require('fs');
const path = require('path');

class EndpointAnalyzer {
    constructor() {
        this.endpoints = [];
        this.categories = {
            'API': [],
            'Panel': [],
            'Health': [],
            'Bot Generation': [],
            'Analysis': [],
            'Security': [],
            'Crypto': [],
            'Network': [],
            'Utility': [],
            'Other': []
        };
    }

    analyzeServerFile() {
        try {
            const serverContent = fs.readFileSync('server.js', 'utf8');
            const lines = serverContent.split('\n');
            
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];
                const match = line.match(/app\.(get|post|put|delete|patch)\s*\(['"`]([^'"`]+)['"`]/);
                
                if (match) {
                    const method = match[1].toUpperCase();
                    const endpoint = match[2];
                    
                    this.endpoints.push({
                        method,
                        endpoint,
                        line: i + 1,
                        category: this.categorizeEndpoint(endpoint)
                    });
                }
            }
            
            this.categorizeEndpoints();
            this.generateReport();
            
        } catch (error) {
            console.error('Error analyzing server file:', error);
        }
    }

    categorizeEndpoint(endpoint) {
        if (endpoint.startsWith('/api/')) {
            return 'API';
        } else if (endpoint.includes('panel') || endpoint.includes('dashboard')) {
            return 'Panel';
        } else if (endpoint.includes('health') || endpoint === '/') {
            return 'Health';
        } else if (endpoint.includes('bot') || endpoint.includes('irc') || endpoint.includes('http-bot')) {
            return 'Bot Generation';
        } else if (endpoint.includes('analysis') || endpoint.includes('scan') || endpoint.includes('jotti') || endpoint.includes('forensics')) {
            return 'Analysis';
        } else if (endpoint.includes('security') || endpoint.includes('threat') || endpoint.includes('vulnerability')) {
            return 'Security';
        } else if (endpoint.includes('crypto') || endpoint.includes('encrypt') || endpoint.includes('decrypt') || endpoint.includes('hash')) {
            return 'Crypto';
        } else if (endpoint.includes('network') || endpoint.includes('dns') || endpoint.includes('ping') || endpoint.includes('traceroute')) {
            return 'Network';
        } else if (endpoint.includes('uuid') || endpoint.includes('time') || endpoint.includes('random') || endpoint.includes('password')) {
            return 'Utility';
        } else {
            return 'Other';
        }
    }

    categorizeEndpoints() {
        this.endpoints.forEach(endpoint => {
            this.categories[endpoint.category].push(endpoint);
        });
    }

    generateReport() {
        console.log('='.repeat(80));
        console.log('🔍 RAWRZ ENDPOINT ANALYSIS REPORT');
        console.log('='.repeat(80));
        console.log(`📊 Total Endpoints Found: ${this.endpoints.length}`);
        console.log('');

        // Category breakdown
        Object.entries(this.categories).forEach(([category, endpoints]) => {
            if (endpoints.length > 0) {
                console.log(`📋 ${category.toUpperCase()} (${endpoints.length} endpoints)`);
                console.log('-'.repeat(40));
                
                // Group by method
                const byMethod = {};
                endpoints.forEach(ep => {
                    if (!byMethod[ep.method]) byMethod[ep.method] = [];
                    byMethod[ep.method].push(ep.endpoint);
                });
                
                Object.entries(byMethod).forEach(([method, endpointList]) => {
                    console.log(`  ${method}: ${endpointList.length} endpoints`);
                    endpointList.slice(0, 5).forEach(ep => {
                        console.log(`    ${method} ${ep}`);
                    });
                    if (endpointList.length > 5) {
                        console.log(`    ... and ${endpointList.length - 5} more`);
                    }
                });
                console.log('');
            }
        });

        // Method breakdown
        console.log('📊 METHOD BREAKDOWN');
        console.log('-'.repeat(40));
        const methodCounts = {};
        this.endpoints.forEach(ep => {
            methodCounts[ep.method] = (methodCounts[ep.method] || 0) + 1;
        });
        
        Object.entries(methodCounts).forEach(([method, count]) => {
            console.log(`  ${method}: ${count} endpoints`);
        });
        
        console.log('');
        console.log('='.repeat(80));
        
        // Generate test data
        this.generateTestData();
    }

    generateTestData() {
        const testData = {
            totalEndpoints: this.endpoints.length,
            categories: {},
            endpoints: this.endpoints.map(ep => ({
                method: ep.method,
                endpoint: ep.endpoint,
                category: ep.category,
                testParams: this.generateTestParams(ep.endpoint, ep.method)
            }))
        };

        // Categorize for test data
        Object.keys(this.categories).forEach(category => {
            testData.categories[category] = this.categories[category].length;
        });

        fs.writeFileSync('endpoint-analysis.json', JSON.stringify(testData, null, 2));
        console.log('💾 Endpoint analysis saved to endpoint-analysis.json');
    }

    generateTestParams(endpoint, method) {
        const params = {
            headers: {
                'Content-Type': 'application/json'
            }
        };

        // Add authentication for API endpoints
        if (endpoint.startsWith('/api/')) {
            params.headers['Authorization'] = 'Bearer test-token';
        }

        // Generate body for POST/PUT/PATCH requests
        if (['POST', 'PUT', 'PATCH'].includes(method)) {
            params.body = this.generateRequestBody(endpoint);
        }

        // Handle parameterized endpoints
        if (endpoint.includes(':')) {
            const paramEndpoint = endpoint.replace(/:\w+/g, 'test-id');
            params.endpoint = paramEndpoint;
        }

        return params;
    }

    generateRequestBody(endpoint) {
        const bodyTemplates = {
            'bot': { server: 'test-server', channel: '#test', features: ['basic'] },
            'encrypt': { data: 'test data', algorithm: 'aes-256-gcm', key: 'test-key' },
            'scan': { target: 'localhost', ports: [80, 443] },
            'generate': { type: 'test', options: {} },
            'compile': { source: 'test code', language: 'cpp', target: 'windows' },
            'analysis': { file: 'test.exe', type: 'malware' },
            'crypto': { algorithm: 'aes-256', mode: 'gcm', data: 'test' },
            'network': { host: 'localhost', port: 80 },
            'utility': { input: 'test input' }
        };

        for (const [key, template] of Object.entries(bodyTemplates)) {
            if (endpoint.toLowerCase().includes(key)) {
                return template;
            }
        }

        return { data: 'test' };
    }
}

// Run the analysis
const analyzer = new EndpointAnalyzer();
analyzer.analyzeServerFile();
