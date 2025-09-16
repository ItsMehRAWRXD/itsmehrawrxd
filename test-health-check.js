#!/usr/bin/env node

/**
 * Health Check Test Script
 * Tests the health check endpoints to ensure they work properly for Digital Ocean deployment
 */

const http = require('http');

const testEndpoints = [
  { path: '/health', description: 'Public health check endpoint' },
  { path: '/api/health', description: 'API health check endpoint' }
];

const port = process.env.PORT || 8080;
const host = process.env.HOST || 'localhost';

function testEndpoint(path, description) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: host,
      port: port,
      path: path,
      method: 'GET',
      timeout: 5000
    };

    const req = http.request(options, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          const jsonData = JSON.parse(data);
          resolve({
            success: true,
            status: res.statusCode,
            data: jsonData,
            description
          });
        } catch (e) {
          resolve({
            success: false,
            status: res.statusCode,
            data: data,
            error: 'Invalid JSON response',
            description
          });
        }
      });
    });

    req.on('error', (err) => {
      reject({
        success: false,
        error: err.message,
        description
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject({
        success: false,
        error: 'Request timeout',
        description
      });
    });

    req.end();
  });
}

async function runTests() {
  console.log(`\n🔍 Testing health check endpoints on ${host}:${port}\n`);
  
  for (const endpoint of testEndpoints) {
    try {
      console.log(`Testing ${endpoint.path} (${endpoint.description})...`);
      const result = await testEndpoint(endpoint.path, endpoint.description);
      
      if (result.success) {
        console.log(`✅ ${endpoint.path} - Status: ${result.status}`);
        console.log(`   Response: ${JSON.stringify(result.data, null, 2)}`);
      } else {
        console.log(`❌ ${endpoint.path} - Status: ${result.status}`);
        console.log(`   Error: ${result.error || 'Unknown error'}`);
        console.log(`   Response: ${result.data}`);
      }
    } catch (error) {
      console.log(`❌ ${endpoint.path} - Failed to connect`);
      console.log(`   Error: ${error.error || error.message}`);
    }
    console.log('');
  }
  
  console.log('🏁 Health check tests completed!\n');
}

// Run tests if this script is executed directly
if (require.main === module) {
  runTests().catch(console.error);
}

module.exports = { testEndpoint, runTests };
