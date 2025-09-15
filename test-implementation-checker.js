#!/usr/bin/env node

// RawrZ Implementation Checker Test Script
// This script tests the implementation checker and health monitor systems

const path = require('path');
const fs = require('fs').promises;

// Test configuration
const TEST_CONFIG = {
    verbose: process.argv.includes('--verbose') || process.argv.includes('-v'),
    runHealthMonitor: process.argv.includes('--health'),
    runImplementationCheck: process.argv.includes('--implementation'),
    runAll: !process.argv.includes('--health') && !process.argv.includes('--implementation'),
    outputFile: process.argv.find(arg => arg.startsWith('--output='))?.split('=')[1] || null
};

// Colors for console output
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m'
};

// Logging functions
function log(message, color = colors.reset) {
    console.log(`${color}${message}${colors.reset}`);
}

function logVerbose(message) {
    if (TEST_CONFIG.verbose) {
        log(`[VERBOSE] ${message}`, colors.cyan);
    }
}

function logSuccess(message) {
    log(`✅ ${message}`, colors.green);
}

function logError(message) {
    log(`❌ ${message}`, colors.red);
}

function logWarning(message) {
    log(`⚠️  ${message}`, colors.yellow);
}

function logInfo(message) {
    log(`ℹ️  ${message}`, colors.blue);
}

// Test results storage
const testResults = {
    startTime: Date.now(),
    tests: [],
    summary: {
        total: 0,
        passed: 0,
        failed: 0,
        warnings: 0
    }
};

// Add test result
function addTestResult(name, status, message, details = null) {
    const result = {
        name,
        status,
        message,
        details,
        timestamp: Date.now()
    };
    
    testResults.tests.push(result);
    testResults.summary.total++;
    
    switch (status) {
        case 'passed':
            testResults.summary.passed++;
            logSuccess(`${name}: ${message}`);
            break;
        case 'failed':
            testResults.summary.failed++;
            logError(`${name}: ${message}`);
            break;
        case 'warning':
            testResults.summary.warnings++;
            logWarning(`${name}: ${message}`);
            break;
        default:
            logInfo(`${name}: ${message}`);
    }
    
    if (details && TEST_CONFIG.verbose) {
        logVerbose(`Details: ${JSON.stringify(details, null, 2)}`);
    }
}

// Test implementation checker
async function testImplementationChecker() {
    logInfo('Testing Implementation Checker...');
    
    try {
        // Load the implementation checker
        const implementationChecker = require('./src/engines/implementation-checker');
        
        // Test initialization
        try {
            await implementationChecker.initialize();
            addTestResult('Implementation Checker Initialization', 'passed', 'Successfully initialized');
        } catch (error) {
            addTestResult('Implementation Checker Initialization', 'failed', `Failed to initialize: ${error.message}`);
            return;
        }
        
        // Test module registry loading
        try {
            const healthStatus = implementationChecker.getHealthStatus();
            if (healthStatus.totalModules > 0) {
                addTestResult('Module Registry Loading', 'passed', `Loaded ${healthStatus.totalModules} modules`);
            } else {
                addTestResult('Module Registry Loading', 'warning', 'No modules loaded in registry');
            }
        } catch (error) {
            addTestResult('Module Registry Loading', 'failed', `Failed to load module registry: ${error.message}`);
        }
        
        // Test implementation check
        try {
            logInfo('Running implementation check...');
            const checkResult = await implementationChecker.performImplementationCheck();
            
            if (checkResult && checkResult.summary) {
                addTestResult('Implementation Check Execution', 'passed', 
                    `Check completed in ${checkResult.duration}ms`);
                
                // Test health score calculation
                if (checkResult.healthScore >= 0 && checkResult.healthScore <= 100) {
                    addTestResult('Health Score Calculation', 'passed', 
                        `Health score: ${checkResult.healthScore}%`);
                } else {
                    addTestResult('Health Score Calculation', 'failed', 
                        `Invalid health score: ${checkResult.healthScore}`);
                }
                
                // Test module checking
                const moduleCount = Object.keys(checkResult.modules).length;
                if (moduleCount > 0) {
                    addTestResult('Module Checking', 'passed', 
                        `Checked ${moduleCount} modules`);
                } else {
                    addTestResult('Module Checking', 'warning', 'No modules were checked');
                }
                
                // Test recommendations generation
                if (checkResult.recommendations && checkResult.recommendations.length >= 0) {
                    addTestResult('Recommendations Generation', 'passed', 
                        `Generated ${checkResult.recommendations.length} recommendations`);
                } else {
                    addTestResult('Recommendations Generation', 'failed', 'No recommendations generated');
                }
                
                // Test individual module results
                let passedModules = 0;
                let failedModules = 0;
                let warningModules = 0;
                
                for (const [moduleName, moduleResult] of Object.entries(checkResult.modules)) {
                    if (moduleResult.status === 'passed') passedModules++;
                    else if (moduleResult.status === 'failed') failedModules++;
                    else if (moduleResult.status === 'warning') warningModules++;
                }
                
                addTestResult('Module Status Summary', 'passed', 
                    `Passed: ${passedModules}, Failed: ${failedModules}, Warnings: ${warningModules}`);
                
            } else {
                addTestResult('Implementation Check Execution', 'failed', 'Invalid check result structure');
            }
            
        } catch (error) {
            addTestResult('Implementation Check Execution', 'failed', `Check failed: ${error.message}`);
        }
        
        // Test check results retrieval
        try {
            const results = implementationChecker.getCheckResults();
            if (Array.isArray(results) && results.length > 0) {
                addTestResult('Check Results Retrieval', 'passed', `Retrieved ${results.length} check results`);
            } else {
                addTestResult('Check Results Retrieval', 'warning', 'No check results available');
            }
        } catch (error) {
            addTestResult('Check Results Retrieval', 'failed', `Failed to retrieve results: ${error.message}`);
        }
        
        // Test module status retrieval
        try {
            const moduleStatus = implementationChecker.getModuleStatus();
            if (moduleStatus && Object.keys(moduleStatus).length > 0) {
                addTestResult('Module Status Retrieval', 'passed', 
                    `Retrieved status for ${Object.keys(moduleStatus).length} modules`);
            } else {
                addTestResult('Module Status Retrieval', 'warning', 'No module status available');
            }
        } catch (error) {
            addTestResult('Module Status Retrieval', 'failed', `Failed to retrieve module status: ${error.message}`);
        }
        
        // Test force check
        try {
            const forceResult = await implementationChecker.forceCheck();
            if (forceResult && forceResult.id) {
                addTestResult('Force Check', 'passed', `Force check completed: ${forceResult.id}`);
            } else {
                addTestResult('Force Check', 'failed', 'Invalid force check result');
            }
        } catch (error) {
            addTestResult('Force Check', 'failed', `Force check failed: ${error.message}`);
        }
        
    } catch (error) {
        addTestResult('Implementation Checker Loading', 'failed', `Failed to load implementation checker: ${error.message}`);
    }
}

// Test health monitor
async function testHealthMonitor() {
    logInfo('Testing Health Monitor...');
    
    try {
        // Load the health monitor
        const healthMonitor = require('./src/engines/health-monitor');
        
        // Test initialization
        try {
            await healthMonitor.initialize();
            addTestResult('Health Monitor Initialization', 'passed', 'Successfully initialized');
        } catch (error) {
            addTestResult('Health Monitor Initialization', 'failed', `Failed to initialize: ${error.message}`);
            return;
        }
        
        // Test monitor setup
        try {
            const monitorStatus = healthMonitor.getMonitorStatus();
            if (monitorStatus && monitorStatus.length > 0) {
                addTestResult('Monitor Setup', 'passed', `Setup ${monitorStatus.length} monitors`);
            } else {
                addTestResult('Monitor Setup', 'warning', 'No monitors setup');
            }
        } catch (error) {
            addTestResult('Monitor Setup', 'failed', `Failed to setup monitors: ${error.message}`);
        }
        
        // Test health dashboard
        try {
            const dashboard = healthMonitor.getHealthDashboard();
            if (dashboard && dashboard.overallHealth) {
                addTestResult('Health Dashboard Generation', 'passed', 
                    `Dashboard generated with health score: ${dashboard.overallHealth.score}%`);
            } else {
                addTestResult('Health Dashboard Generation', 'failed', 'Invalid dashboard structure');
            }
        } catch (error) {
            addTestResult('Health Dashboard Generation', 'failed', `Failed to generate dashboard: ${error.message}`);
        }
        
        // Test individual monitors
        const monitorTests = [
            'system-health',
            'module-health',
            'performance-metrics',
            'memory-usage',
            'disk-usage',
            'api-endpoints'
        ];
        
        for (const monitorId of monitorTests) {
            try {
                const monitor = healthMonitor.getMonitorStatus(monitorId);
                if (monitor) {
                    addTestResult(`Monitor ${monitorId}`, 'passed', 
                        `Monitor exists and is ${monitor.enabled ? 'enabled' : 'disabled'}`);
                } else {
                    addTestResult(`Monitor ${monitorId}`, 'warning', 'Monitor not found');
                }
            } catch (error) {
                addTestResult(`Monitor ${monitorId}`, 'failed', `Monitor error: ${error.message}`);
            }
        }
        
        // Test monitor toggling
        try {
            const result = healthMonitor.toggleMonitor('system-health', false);
            if (result) {
                addTestResult('Monitor Toggle', 'passed', 'Successfully toggled monitor');
                // Restore original state
                healthMonitor.toggleMonitor('system-health', true);
            } else {
                addTestResult('Monitor Toggle', 'failed', 'Failed to toggle monitor');
            }
        } catch (error) {
            addTestResult('Monitor Toggle', 'failed', `Toggle failed: ${error.message}`);
        }
        
        // Test interval update
        try {
            const result = healthMonitor.updateMonitorInterval('system-health', 10000);
            if (result) {
                addTestResult('Monitor Interval Update', 'passed', 'Successfully updated monitor interval');
            } else {
                addTestResult('Monitor Interval Update', 'failed', 'Failed to update monitor interval');
            }
        } catch (error) {
            addTestResult('Monitor Interval Update', 'failed', `Interval update failed: ${error.message}`);
        }
        
    } catch (error) {
        addTestResult('Health Monitor Loading', 'failed', `Failed to load health monitor: ${error.message}`);
    }
}

// Test server endpoints
async function testServerEndpoints() {
    logInfo('Testing Server Endpoints...');
    
    const endpoints = [
        { path: '/implementation-check/status', method: 'GET' },
        { path: '/implementation-check/run', method: 'POST' },
        { path: '/implementation-check/results', method: 'GET' },
        { path: '/implementation-check/modules', method: 'GET' },
        { path: '/health-monitor/dashboard', method: 'GET' },
        { path: '/health-monitor/status', method: 'GET' }
    ];
    
    for (const endpoint of endpoints) {
        try {
            const response = await fetch(`http://localhost:8080${endpoint.path}`, {
                method: endpoint.method,
                headers: {
                    'Authorization': 'Bearer demo-token',
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                if (data.success) {
                    addTestResult(`Endpoint ${endpoint.path}`, 'passed', 
                        `${endpoint.method} request successful`);
                } else {
                    addTestResult(`Endpoint ${endpoint.path}`, 'warning', 
                        `Request successful but returned error: ${data.error || 'Unknown error'}`);
                }
            } else {
                addTestResult(`Endpoint ${endpoint.path}`, 'failed', 
                    `HTTP ${response.status}: ${response.statusText}`);
            }
        } catch (error) {
            addTestResult(`Endpoint ${endpoint.path}`, 'failed', 
                `Request failed: ${error.message}`);
        }
    }
}

// Test file system
async function testFileSystem() {
    logInfo('Testing File System...');
    
    const requiredFiles = [
        'src/engines/implementation-checker.js',
        'src/engines/health-monitor.js',
        'public/health-dashboard.html',
        'src/engines/rawrz-engine.js',
        'server.js'
    ];
    
    for (const file of requiredFiles) {
        try {
            await fs.access(file);
            addTestResult(`File ${file}`, 'passed', 'File exists');
        } catch (error) {
            addTestResult(`File ${file}`, 'failed', 'File not found');
        }
    }
}

// Generate test report
async function generateReport() {
    const endTime = Date.now();
    const duration = endTime - testResults.startTime;
    
    const report = {
        summary: {
            ...testResults.summary,
            duration: duration,
            timestamp: new Date().toISOString()
        },
        tests: testResults.tests,
        recommendations: generateRecommendations()
    };
    
    // Console summary
    log('\n' + '='.repeat(60), colors.bright);
    log('TEST SUMMARY', colors.bright);
    log('='.repeat(60), colors.bright);
    log(`Total Tests: ${report.summary.total}`, colors.blue);
    log(`Passed: ${report.summary.passed}`, colors.green);
    log(`Failed: ${report.summary.failed}`, colors.red);
    log(`Warnings: ${report.summary.warnings}`, colors.yellow);
    log(`Duration: ${duration}ms`, colors.blue);
    log(`Success Rate: ${Math.round((report.summary.passed / report.summary.total) * 100)}%`, 
        report.summary.passed === report.summary.total ? colors.green : colors.yellow);
    
    if (report.recommendations.length > 0) {
        log('\nRECOMMENDATIONS:', colors.bright);
        report.recommendations.forEach(rec => {
            log(`• ${rec}`, colors.cyan);
        });
    }
    
    // Save report to file if requested
    if (TEST_CONFIG.outputFile) {
        try {
            await fs.writeFile(TEST_CONFIG.outputFile, JSON.stringify(report, null, 2));
            log(`\nReport saved to: ${TEST_CONFIG.outputFile}`, colors.green);
        } catch (error) {
            logError(`Failed to save report: ${error.message}`);
        }
    }
    
    return report;
}

// Generate recommendations based on test results
function generateRecommendations() {
    const recommendations = [];
    const failedTests = testResults.tests.filter(t => t.status === 'failed');
    const warningTests = testResults.tests.filter(t => t.status === 'warning');
    
    if (failedTests.length > 0) {
        recommendations.push(`Fix ${failedTests.length} failed tests to improve system reliability`);
    }
    
    if (warningTests.length > 0) {
        recommendations.push(`Address ${warningTests.length} warnings to optimize system performance`);
    }
    
    const implementationTests = testResults.tests.filter(t => t.name.includes('Implementation'));
    const failedImplTests = implementationTests.filter(t => t.status === 'failed');
    
    if (failedImplTests.length > 0) {
        recommendations.push('Review and fix implementation checker issues');
    }
    
    const healthTests = testResults.tests.filter(t => t.name.includes('Health'));
    const failedHealthTests = healthTests.filter(t => t.status === 'failed');
    
    if (failedHealthTests.length > 0) {
        recommendations.push('Review and fix health monitor issues');
    }
    
    const endpointTests = testResults.tests.filter(t => t.name.includes('Endpoint'));
    const failedEndpointTests = endpointTests.filter(t => t.status === 'failed');
    
    if (failedEndpointTests.length > 0) {
        recommendations.push('Check server configuration and ensure server is running');
    }
    
    if (testResults.summary.passed === testResults.summary.total) {
        recommendations.push('All tests passed! System is working correctly.');
    }
    
    return recommendations;
}

// Main test function
async function runTests() {
    log('RawrZ Implementation Checker Test Suite', colors.bright);
    log('='.repeat(50), colors.bright);
    log(`Configuration: ${JSON.stringify(TEST_CONFIG, null, 2)}`, colors.cyan);
    log('');
    
    try {
        // Test file system first
        await testFileSystem();
        
        // Test implementation checker
        if (TEST_CONFIG.runImplementationCheck || TEST_CONFIG.runAll) {
            await testImplementationChecker();
        }
        
        // Test health monitor
        if (TEST_CONFIG.runHealthMonitor || TEST_CONFIG.runAll) {
            await testHealthMonitor();
        }
        
        // Test server endpoints (only if server might be running)
        if (TEST_CONFIG.runAll) {
            try {
                await testServerEndpoints();
            } catch (error) {
                logWarning('Server endpoint tests skipped (server may not be running)');
            }
        }
        
        // Generate and display report
        const report = await generateReport();
        
        // Exit with appropriate code
        process.exit(testResults.summary.failed > 0 ? 1 : 0);
        
    } catch (error) {
        logError(`Test suite failed: ${error.message}`);
        process.exit(1);
    }
}

// Handle command line arguments
function showHelp() {
    log('RawrZ Implementation Checker Test Suite', colors.bright);
    log('');
    log('Usage: node test-implementation-checker.js [options]', colors.blue);
    log('');
    log('Options:', colors.blue);
    log('  --verbose, -v          Enable verbose output', colors.cyan);
    log('  --health               Test only health monitor', colors.cyan);
    log('  --implementation       Test only implementation checker', colors.cyan);
    log('  --output=file.json     Save test report to file', colors.cyan);
    log('  --help, -h             Show this help message', colors.cyan);
    log('');
    log('Examples:', colors.blue);
    log('  node test-implementation-checker.js', colors.cyan);
    log('  node test-implementation-checker.js --verbose', colors.cyan);
    log('  node test-implementation-checker.js --health --output=health-report.json', colors.cyan);
}

// Check for help flag
if (process.argv.includes('--help') || process.argv.includes('-h')) {
    showHelp();
    process.exit(0);
}

// Run tests
runTests().catch(error => {
    logError(`Fatal error: ${error.message}`);
    process.exit(1);
});
