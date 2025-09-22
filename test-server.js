const http = require('http');
const assert = require('assert');

const HOST = process.env.TEST_HOST || 'localhost';
const PORT = process.env.TEST_PORT || 8080;

console.log('🧪 Testing server at', `http://${HOST}:${PORT}`);

const tests = [
  {
    name: 'Health Check',
    path: '/health',
    method: 'GET',
    expectedStatus: 200,
    validate: (data) => {
      assert(data.status === 'healthy', 'Health status should be healthy');
      assert(data.memory, 'Should include memory info');
      assert(typeof data.uptime === 'number', 'Should include uptime');
    }
  },
  {
    name: 'API Status',
    path: '/api/status',
    method: 'GET',
    expectedStatus: 200,
    validate: (data) => {
      assert(data.status === 'online', 'API should be online');
      assert(data.version, 'Should include version');
      assert(typeof data.requests === 'number', 'Should track requests');
    }
  },
  {
    name: 'Create Session',
    path: '/api/session',
    method: 'POST',
    expectedStatus: 200,
    validate: (data) => {
      assert(data.success === true, 'Should create session successfully');
      assert(data.sessionId, 'Should return session ID');
      assert(data.expiresIn === 1800, 'Should have 30 min expiry');
      return data.sessionId; // Return for next test
    }
  },
  {
    name: 'Store Data',
    path: '/api/data',
    method: 'POST',
    body: {
      sessionId: null, // Will be set from previous test
      key: 'testKey',
      value: { test: true, timestamp: Date.now() }
    },
    expectedStatus: 200,
    validate: (data) => {
      assert(data.success === true, 'Should store data successfully');
      assert(data.stored === true, 'Should confirm storage');
    }
  },
  {
    name: 'Handle 404',
    path: '/api/nonexistent',
    method: 'GET',
    expectedStatus: 404,
    validate: (data) => {
      assert(data.error === 'Not found', 'Should return not found error');
    }
  },
  {
    name: 'Memory Leak Prevention',
    path: '/api/data',
    method: 'POST',
    body: {
      sessionId: 'test',
      key: 'bigData',
      value: 'x'.repeat(20000) // Exceed 10KB limit
    },
    expectedStatus: 413,
    validate: (data) => {
      assert(data.error === 'Data too large', 'Should reject large data');
    }
  }
];

let sessionId = null;

async function runTest(test) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: HOST,
      port: PORT,
      path: test.path,
      method: test.method,
      headers: {
        'Content-Type': 'application/json'
      }
    };

    const req = http.request(options, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          
          if (res.statusCode !== test.expectedStatus) {
            reject(new Error(`Expected status ${test.expectedStatus}, got ${res.statusCode}`));
            return;
          }
          
          const result = test.validate(parsed);
          
          // Store sessionId if returned
          if (result) {
            sessionId = result;
          }
          
          resolve();
        } catch (error) {
          reject(error);
        }
      });
    });
    
    req.on('error', reject);
    
    if (test.body) {
      // Use sessionId from previous test if needed
      if (test.body.sessionId === null && sessionId) {
        test.body.sessionId = sessionId;
      }
      req.write(JSON.stringify(test.body));
    }
    
    req.end();
  });
}

async function runAllTests() {
  console.log('\n📊 Running tests...\n');
  
  let passed = 0;
  let failed = 0;
  
  for (const test of tests) {
    try {
      await runTest(test);
      console.log(`✅ ${test.name}`);
      passed++;
    } catch (error) {
      console.log(`❌ ${test.name}: ${error.message}`);
      failed++;
    }
  }
  
  console.log('\n📈 Results:');
  console.log(`   Passed: ${passed}`);
  console.log(`   Failed: ${failed}`);
  console.log(`   Total:  ${tests.length}`);
  
  if (failed === 0) {
    console.log('\n🎉 All tests passed!');
    process.exit(0);
  } else {
    console.log('\n⚠️  Some tests failed');
    process.exit(1);
  }
}

// Check if server is running
const checkReq = http.get(`http://${HOST}:${PORT}/health`, (res) => {
  if (res.statusCode === 200 || res.statusCode === 503) {
    runAllTests();
  }
});

checkReq.on('error', (err) => {
  console.error('❌ Server is not running at', `http://${HOST}:${PORT}`);
  console.error('   Error:', err.message);
  console.log('\n💡 Start the server first:');
  console.log('   npm start');
  process.exit(1);
});