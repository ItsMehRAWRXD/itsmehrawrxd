#!/usr/bin/env node

/**
 * Test Runner for RawrZ Security Platform
 * Runs all test suites and generates comprehensive reports
 */

const { spawn } = require('child_process');
const fs = require('fs').promises;
const path = require('path');

class TestRunner {
    constructor() {
        this.testSuites = [
            { name: 'Unit Tests', file: 'test-unit.js', description: 'Basic engine functionality tests' },
            { name: 'Performance Tests', file: 'test-performance.js', description: 'Performance and benchmark tests' },
            { name: 'Comprehensive Tests', file: 'test-comprehensive.js', description: 'Full integration and functionality tests' }
        ];
        this.results = {
            suites: [],
            summary: {
                total: 0,
                passed: 0,
                failed: 0,
                skipped: 0
            }
        };
    }

    async run() {
        console.log('RawrZ Security Platform Test Runner');
        console.log('=' .repeat(80));
        console.log('Running all test suites...\n');
        
        for (const suite of this.testSuites) {
            await this.runTestSuite(suite);
        }
        
        await this.generateSummaryReport();
    }

    async runTestSuite(suite) {
        console.log('Running ' + suite.name + '...');
        console.log(suite.description);
        console.log('-'.repeat(60));
        
        return new Promise((resolve) => {
            const startTime = Date.now();
            const process = spawn('node', [suite.file], {
                stdio: ['inherit', 'pipe', 'pipe'],
                cwd: process.cwd()
            });

            let stdout = '';
            let stderr = '';

            process.stdout.on('data', (data) => {
                stdout += data.toString();
                process.stdout.write(data);
            });

            process.stderr.on('data', (data) => {
                stderr += data.toString();
                process.stderr.write(data);
            });

            process.on('close', (code) => {
                const duration = Date.now() - startTime;
                const success = code === 0;
                
                this.results.suites.push({
                    name: suite.name,
                    file: suite.file,
                    success,
                    exitCode: code,
                    duration,
                    stdout,
                    stderr
                });
                
                this.results.summary.total++;
                if (success) {
                    this.results.summary.passed++;
                    console.log('\nPASS ' + suite.name + ' completed successfully (' + duration + 'ms)');
                } else {
                    this.results.summary.failed++;
                    console.log('\nFAIL ' + suite.name + ' failed with exit code ' + code + ' (' + duration + 'ms)');
                }
                
                resolve();
            });

            process.on('error', (error) => {
                const duration = Date.now() - startTime;
                this.results.suites.push({
                    name: suite.name,
                    file: suite.file,
                    success: false,
                    exitCode: -1,
                    duration,
                    stdout,
                    stderr: error.message
                });
                
                this.results.summary.total++;
                this.results.summary.failed++;
                console.log('\nFAIL ' + suite.name + ' failed to start: ' + error.message);
                resolve();
            });
        });
    }

    async generateSummaryReport() {
        console.log('\n' + '='.repeat(80));
        console.log('TEST RUNNER SUMMARY REPORT');
        console.log('='.repeat(80));
        
        const successRate = ((this.results.summary.passed / this.results.summary.total) * 100).toFixed(2);
        
        console.log('Overall Success Rate: ' + successRate + '%');
        console.log('PASS Passed Suites: ' + this.results.summary.passed);
        console.log('FAIL Failed Suites: ' + this.results.summary.failed);
        console.log('  Skipped Suites: ' + this.results.summary.skipped);
        console.log(' Total Suites: ' + this.results.summary.total);
        
        console.log('\n Suite Results:');
        this.results.suites.forEach(suite => {
            const status = suite.success ? 'PASS' : 'FAIL';
            const duration = suite.duration + 'ms';
            console.log('  ' + status + ' ' + suite.name + ' (' + duration + ')');
            
            if (!suite.success && suite.stderr) {
                console.log('    Error: ' + suite.stderr.substring(0, 100) + '...');
            }
        });
        
        // Check for individual test reports
        await this.checkTestReports();
        
        // Save summary report
        const report = {
            summary: this.results.summary,
            suites: this.results.suites,
            timestamp: new Date().toISOString()
        };
        
        await fs.writeFile('test-runner-report.json', JSON.stringify(report, null, 2));
        console.log('\n Summary report saved to: test-runner-report.json');
        
        // Exit with appropriate code
        process.exit(this.results.summary.failed > 0 ? 1 : 0);
    }

    async checkTestReports() {
        console.log('\n Individual Test Reports:');
        
        const reportFiles = [
            'test-report.json',
            'performance-report.json'
        ];
        
        for (const file of reportFiles) {
            try {
                const data = await fs.readFile(file, 'utf8');
                const report = JSON.parse(data);
                
                if (report.summary) {
                    console.log('   ' + file + ': ' + report.summary.passed + '/' + report.summary.total + ' tests passed');
                } else if (report.benchmarks) {
                    console.log('   ' + file + ': Performance benchmarks completed');
                }
            } catch (error) {
                console.log('  FAIL ' + file + ': Not found or invalid');
            }
        }
    }
}

// Run the test runner
if (require.main === module) {
    const runner = new TestRunner();
    runner.run().catch(console.error);
}

module.exports = TestRunner;
