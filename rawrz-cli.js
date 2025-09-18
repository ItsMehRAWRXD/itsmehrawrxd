#!/usr/bin/env node

/**
 * RawrZ CLI - Direct Engine Interface
 * No external dependencies - uses engines directly
 */

const fs = require('fs');
const path = require('path');

class RawrZCLI {
    constructor() {
        this.engines = {};
        this.loadEngines();
    }

    loadEngines() {
        const enginesDir = './src/engines';
        const engineFiles = fs.readdirSync(enginesDir).filter(file => file.endsWith('.js'));
        
        console.log('🔧 Loading RawrZ Engines...');
        
        engineFiles.forEach(file => {
            try {
                const engineName = file.replace('.js', '');
                const enginePath = path.resolve(enginesDir, file);
                const EngineClass = require(enginePath);
                
                // Handle both class and instance exports
                if (typeof EngineClass === 'function') {
                    this.engines[engineName] = new EngineClass();
                } else {
                    this.engines[engineName] = EngineClass;
                }
                
                console.log(`✅ ${engineName}: Loaded`);
            } catch (error) {
                console.log(`❌ ${file}: Failed to load - ${error.message}`);
            }
        });
        
        console.log(`\n📊 Total Engines Loaded: ${Object.keys(this.engines).length}`);
    }

    async listEngines() {
        console.log('\n🚀 Available RawrZ Engines:');
        console.log('============================');
        
        for (const [name, engine] of Object.entries(this.engines)) {
            try {
                if (engine.getStatus) {
                    const status = await engine.getStatus();
                    const statusIcon = status.status === 'active' ? '🟢' : '🔴';
                    console.log(`${statusIcon} ${name}: ${status.status || 'loaded'}`);
                } else {
                    console.log(`⚪ ${name}: loaded`);
                }
            } catch (error) {
                console.log(`❌ ${name}: error - ${error.message}`);
            }
        }
    }

    async testEngine(engineName) {
        if (!this.engines[engineName]) {
            console.log(`❌ Engine '${engineName}' not found`);
            return;
        }

        console.log(`\n🧪 Testing ${engineName}...`);
        
        try {
            const engine = this.engines[engineName];
            
            // Test initialization
            if (engine.initialize) {
                await engine.initialize();
                console.log(`✅ ${engineName}: Initialized`);
            }
            
            // Test status
            if (engine.getStatus) {
                const status = await engine.getStatus();
                console.log(`✅ ${engineName}: Status -`, status);
            }
            
            // Test specific functionality
            if (engineName === 'stub-generator' && engine.generateStub) {
                const result = await engine.generateStub('test_target.exe', {
                    encryptionMethod: 'aes-256-gcm',
                    stubType: 'cpp'
                });
                console.log(`✅ ${engineName}: Stub generation test passed`);
            }
            
            if (engineName === 'camellia-assembly' && engine.generateStub) {
                const result = engine.generateStub({
                    algorithm: 'camellia-256-cbc',
                    key: Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex'),
                    iv: Buffer.from('0123456789abcdef0123456789abcdef', 'hex'),
                    format: 'assembly'
                });
                console.log(`✅ ${engineName}: Assembly stub generation test passed`);
            }
            
            if (engineName === 'dual-crypto-engine' && engine.generateDualStub) {
                const result = engine.generateDualStub({
                    algorithm: 'dual-aes-camellia',
                    keys: {
                        primary: Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex'),
                        secondary: Buffer.from('fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210', 'hex')
                    },
                    ivs: {
                        primary: Buffer.from('0123456789abcdef0123456789abcdef', 'hex'),
                        secondary: Buffer.from('fedcba9876543210fedcba9876543210', 'hex')
                    },
                    fileType: 'exe'
                });
                console.log(`✅ ${engineName}: Dual stub generation test passed`);
            }
            
            console.log(`🎉 ${engineName}: All tests passed!`);
            
        } catch (error) {
            console.log(`❌ ${engineName}: Test failed - ${error.message}`);
        }
    }

    async generateStub(target, options = {}) {
        console.log(`\n📝 Generating stub for: ${target}`);
        
        try {
            const stubGenerator = this.engines['stub-generator'];
            if (!stubGenerator) {
                throw new Error('Stub generator not available');
            }
            
            const result = await stubGenerator.generateStub(target, {
                encryptionMethod: 'aes-256-gcm',
                stubType: 'cpp',
                includeAntiDebug: true,
                includeAntiVM: true,
                ...options
            });
            
            console.log('✅ Stub generated successfully:');
            console.log(`   ID: ${result.id}`);
            console.log(`   Type: ${result.stubType}`);
            console.log(`   Encryption: ${result.encryptionMethod}`);
            console.log(`   Output: ${result.outputPath}`);
            
            return result;
        } catch (error) {
            console.log(`❌ Stub generation failed: ${error.message}`);
        }
    }

    async scanFile(filePath) {
        console.log(`\n🔍 Scanning file: ${filePath}`);
        
        try {
            const jottiScanner = this.engines['jotti-scanner'];
            if (!jottiScanner) {
                throw new Error('Jotti scanner not available');
            }
            
            const result = await jottiScanner.scanFile(filePath);
            
            if (result.success) {
                console.log('✅ Scan completed:');
                console.log(`   File: ${result.filePath}`);
                console.log(`   Size: ${result.fileSize} bytes`);
                console.log(`   Job ID: ${result.jobId}`);
                console.log(`   Summary:`, result.summary);
            } else {
                console.log(`❌ Scan failed: ${result.error}`);
            }
            
            return result;
        } catch (error) {
            console.log(`❌ Scan failed: ${error.message}`);
        }
    }

    showHelp() {
        console.log(`
🚀 RawrZ CLI - Direct Engine Interface
=====================================

Usage: node rawrz-cli.js <command> [options]

Commands:
  list                    List all available engines
  test <engine>          Test specific engine functionality
  stub <target>          Generate stub for target file
  scan <file>            Scan file with virus scanner
  help                   Show this help message

Examples:
  node rawrz-cli.js list
  node rawrz-cli.js test stub-generator
  node rawrz-cli.js stub calc.exe
  node rawrz-cli.js scan C:\\Windows\\System32\\calc.exe

Available Engines:
${Object.keys(this.engines).map(name => `  - ${name}`).join('\n')}
`);
    }

    async run() {
        const args = process.argv.slice(2);
        const command = args[0];
        const param = args[1];

        switch (command) {
            case 'list':
                await this.listEngines();
                break;
            case 'test':
                if (!param) {
                    console.log('❌ Please specify an engine name to test');
                    console.log('Usage: node rawrz-cli.js test <engine-name>');
                    return;
                }
                await this.testEngine(param);
                break;
            case 'stub':
                if (!param) {
                    console.log('❌ Please specify a target file');
                    console.log('Usage: node rawrz-cli.js stub <target-file>');
                    return;
                }
                await this.generateStub(param);
                break;
            case 'scan':
                if (!param) {
                    console.log('❌ Please specify a file to scan');
                    console.log('Usage: node rawrz-cli.js scan <file-path>');
                    return;
                }
                await this.scanFile(param);
                break;
            case 'help':
            case '--help':
            case '-h':
                this.showHelp();
                break;
            default:
                console.log('❌ Unknown command. Use "help" for usage information.');
                this.showHelp();
        }
    }
}

// Run CLI if called directly
if (require.main === module) {
    const cli = new RawrZCLI();
    cli.run().catch(console.error);
}

module.exports = RawrZCLI;
