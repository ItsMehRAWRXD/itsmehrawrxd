# RawrZ Security Platform - Testing Documentation

## Overview

The RawrZ Security Platform includes a comprehensive testing suite to ensure all engines, functionality, and integrations work correctly. The testing framework consists of multiple test suites designed to validate different aspects of the platform.

## Test Suites

### 1. Unit Tests (`test-unit.js`)

**Purpose**: Basic functionality tests for individual engines
**Scope**: Tests engine initialization, basic properties, and core methods
**Duration**: ~30 seconds
**Usage**: `npm run test:unit` or `node test-unit.js`

**What it tests**:
- Engine class instantiation
- Required properties (name, version)
- Initialization methods
- Basic method availability

### 2. Performance Tests (`test-performance.js`)

**Purpose**: Performance benchmarks and memory usage testing
**Scope**: Tests initialization speed, encryption performance, memory usage
**Duration**: ~2 minutes
**Usage**: `npm run test:performance` or `node test-performance.js`

**What it tests**:
- Engine initialization performance
- Encryption/decryption speed for different algorithms
- Bot and stub generation performance
- Analysis operation performance
- Memory usage patterns
- Concurrent operation handling

### 3. Comprehensive Tests (`test-comprehensive.js`)

**Purpose**: Full integration and functionality testing
**Scope**: Tests all engines, API endpoints, web panels, and integrations
**Duration**: ~5-10 minutes
**Usage**: `npm run test:comprehensive` or `node test-comprehensive.js`

**What it tests**:
- All engine functionality
- API endpoint responses
- Web panel accessibility
- CLI command processing
- Security features
- Error handling
- Integration between components

### 4. Test Runner (`test-runner.js`)

**Purpose**: Runs all test suites and generates comprehensive reports
**Scope**: Orchestrates all test suites and provides summary reporting
**Duration**: ~10-15 minutes
**Usage**: `npm run test:all` or `node test-runner.js`

**What it does**:
- Runs all test suites sequentially
- Generates summary reports
- Combines results from all test suites
- Provides overall success/failure status

## Running Tests

### Quick Start

```bash
# Run all tests
npm run test:all

# Run individual test suites
npm run test:unit
npm run test:performance
npm run test:comprehensive
```

### Manual Execution

```bash
# Unit tests
node test-unit.js

# Performance tests
node test-performance.js

# Comprehensive tests
node test-comprehensive.js

# Test runner
node test-runner.js
```

## Test Reports

### Report Files

- `test-report.json` - Comprehensive test results
- `performance-report.json` - Performance benchmarks
- `test-runner-report.json` - Overall test suite summary

### Report Structure

```json
{
  "summary": {
    "totalTime": 15000,
    "successRate": 95.5,
    "passed": 95,
    "failed": 5,
    "total": 100
  },
  "tests": [
    {
      "name": "Test Name",
      "status": "PASSED|FAILED",
      "duration": 150,
      "error": null
    }
  ],
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

## Test Categories

### Engine Tests

Each engine is tested for:
- ✅ Initialization
- ✅ Required methods
- ✅ Basic functionality
- ✅ Error handling
- ✅ Performance

### API Tests

API endpoints are tested for:
- ✅ Response format
- ✅ Status codes
- ✅ Authentication
- ✅ Error handling
- ✅ Performance

### Security Tests

Security features are tested for:
- ✅ Authentication requirements
- ✅ CORS configuration
- ✅ Security headers
- ✅ Input validation
- ✅ XSS prevention

### Integration Tests

Integration points are tested for:
- ✅ Engine communication
- ✅ Web panel to API communication
- ✅ CLI to web API integration
- ✅ Data flow between components

## Performance Benchmarks

### Expected Performance

| Operation | Target | Acceptable |
|-----------|--------|------------|
| Engine Initialization | < 1s | < 5s |
| Encryption (AES-256) | < 100ms | < 500ms |
| Bot Generation | < 2s | < 10s |
| Port Scan | < 5s | < 30s |
| Memory Usage | < 50MB | < 100MB |

### Benchmark Categories

1. **Initialization Performance**
   - Core engine startup time
   - Individual engine loading time
   - Module initialization time

2. **Encryption Performance**
   - AES-256 encryption/decryption
   - AES-192 encryption/decryption
   - AES-128 encryption/decryption
   - ChaCha20-Poly1305 encryption/decryption

3. **Generation Performance**
   - HTTP bot generation
   - Stub generation
   - Template generation

4. **Analysis Performance**
   - VM detection
   - Sandbox detection
   - Port scanning
   - Memory analysis

## Troubleshooting

### Common Issues

1. **Server Not Starting**
   - Check if port 8080 is available
   - Verify all dependencies are installed
   - Check for syntax errors in server.js

2. **Engine Initialization Failures**
   - Verify engine files exist
   - Check for missing dependencies
   - Review engine-specific error messages

3. **Performance Test Failures**
   - Check system resources
   - Verify no other processes are consuming CPU/memory
   - Review performance thresholds

4. **API Test Failures**
   - Ensure server is running
   - Check authentication configuration
   - Verify endpoint implementations

### Debug Mode

Run tests with additional debugging:

```bash
# Enable debug logging
DEBUG=* node test-comprehensive.js

# Verbose output
node test-comprehensive.js --verbose
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: RawrZ Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
        with:
          node-version: '18'
      - run: npm install
      - run: npm run test:all
```

### Pre-commit Hooks

```bash
# Install husky for git hooks
npm install --save-dev husky

# Add pre-commit hook
npx husky add .husky/pre-commit "npm run test:unit"
```

## Test Maintenance

### Adding New Tests

1. **For New Engines**:
   - Add initialization test to `test-unit.js`
   - Add functionality test to `test-comprehensive.js`
   - Add performance test to `test-performance.js`

2. **For New API Endpoints**:
   - Add endpoint test to `test-comprehensive.js`
   - Add performance test if applicable

3. **For New Features**:
   - Add unit test for core functionality
   - Add integration test for cross-component features
   - Add performance test for resource-intensive operations

### Updating Test Thresholds

Performance thresholds can be updated in the respective test files:
- `test-performance.js` - Performance benchmarks
- `test-comprehensive.js` - Timeout values
- `test-unit.js` - Basic functionality checks

## Best Practices

1. **Test Isolation**: Each test should be independent
2. **Cleanup**: Tests should clean up after themselves
3. **Error Handling**: Tests should handle expected errors gracefully
4. **Performance**: Tests should complete within reasonable time limits
5. **Documentation**: New tests should be documented

## Support

For testing issues or questions:
1. Check the test output for specific error messages
2. Review the generated report files
3. Verify all dependencies are installed
4. Check system requirements and resources

---

*Last updated: 2024-01-01*
*Test suite version: 1.0.0*
