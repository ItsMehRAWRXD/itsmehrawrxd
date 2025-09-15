#!/usr/bin/env node

/**
 * RawrZ OpenSSL Toggle Example Implementation
 * 
 * This example demonstrates how to use the OpenSSL toggle functionality
 * with the RawrZ Advanced Crypto and Stub Generator engines.
 */

const { AdvancedCrypto } = require('../src/engines/advanced-crypto');
const { StubGenerator } = require('../src/engines/stub-generator');
const { OpenSSLConfig } = require('../src/utils/openssl-config');
const { OpenSSLManager } = require('../src/utils/openssl-manager');

async function demonstrateOpenSSLToggle() {
    console.log('RawrZ OpenSSL Toggle Demonstration\n');
    
    // Initialize the OpenSSL Manager
    const manager = new OpenSSLManager();
    await manager.initialize();
    
    // Create crypto engines with different configurations
    console.log('Creating crypto engines...\n');
    
    // OpenSSL-only mode
    const opensslCrypto = new AdvancedCrypto({ 
        useOpenSSL: true, 
        allowCustomAlgorithms: false 
    });
    
    // Custom algorithms only
    const customCrypto = new AdvancedCrypto({ 
        useOpenSSL: false, 
        allowCustomAlgorithms: true 
    });
    
    // Mixed mode (all algorithms)
    const mixedCrypto = new AdvancedCrypto({ 
        useOpenSSL: true, 
        allowCustomAlgorithms: true 
    });
    
    // Register engines with manager
    manager.registerEngine('openssl-crypto', opensslCrypto);
    manager.registerEngine('custom-crypto', customCrypto);
    manager.registerEngine('mixed-crypto', mixedCrypto);
    
    // Demonstrate algorithm availability
    console.log('Algorithm Availability Analysis:\n');
    
    const opensslAlgorithms = opensslCrypto.getOpenSSLAlgorithms();
    const customAlgorithms = customCrypto.getCustomAlgorithms();
    const allAlgorithms = mixedCrypto.getSupportedAlgorithms();
    
    console.log(`OpenSSL-only algorithms: ${opensslAlgorithms.length}`);
    console.log(`Custom algorithms: ${customAlgorithms.length}`);
    console.log(`Total algorithms: ${allAlgorithms.length}\n`);
    
    // Show some examples
    console.log('OpenSSL Algorithms (first 10):');
    opensslAlgorithms.slice(0, 10).forEach(alg => {
        console.log(`  ✓ ${alg}`);
    });
    console.log();
    
    console.log('Custom Algorithms (first 10):');
    customAlgorithms.slice(0, 10).forEach(alg => {
        console.log(`  Warning: ${alg}`);
    });
    console.log();
    
    // Demonstrate algorithm resolution
    console.log('Algorithm Resolution Examples:\n');
    
    const testAlgorithms = [
        'aes-256-gcm',      // OpenSSL native
        'serpent-256-cbc',  // Custom algorithm
        'quantum-resistant', // Custom algorithm
        'chacha20'          // OpenSSL native
    ];
    
    for (const algorithm of testAlgorithms) {
        console.log(`Testing algorithm: ${algorithm}`);
        
        // Test with OpenSSL-only mode
        const opensslResolved = opensslCrypto.resolveAlgorithm(algorithm);
        console.log(`  OpenSSL mode: ${algorithm} → ${opensslResolved}`);
        
        // Test with custom mode
        const customResolved = customCrypto.resolveAlgorithm(algorithm);
        console.log(`  Custom mode: ${algorithm} → ${customResolved}`);
        
        // Test with mixed mode
        const mixedResolved = mixedCrypto.resolveAlgorithm(algorithm);
        console.log(`  Mixed mode: ${algorithm} → ${mixedResolved}`);
        console.log();
    }
    
    // Demonstrate encryption with different modes
    console.log('Encryption Examples:\n');
    
    const testData = 'Hello, RawrZ OpenSSL Toggle!';
    console.log(`Original data: "${testData}"\n`);
    
    // Test with OpenSSL-only mode
    try {
        console.log('Testing OpenSSL-only encryption...');
        const opensslResult = await opensslCrypto.encrypt(testData, {
            algorithm: 'aes-256-gcm'
        });
        console.log(`  ✓ OpenSSL AES-256-GCM: ${opensslResult.encrypted.substring(0, 50)}...`);
        
        // Try to use custom algorithm (should fallback)
        const opensslCustomResult = await opensslCrypto.encrypt(testData, {
            algorithm: 'serpent-256-cbc'
        });
        console.log(`  ✓ Serpent fallback: ${opensslCustomResult.encrypted.substring(0, 50)}...`);
    } catch (error) {
        console.log(`  ✗ Error: ${error.message}`);
    }
    console.log();
    
    // Test with custom mode
    try {
        console.log('Testing custom algorithms encryption...');
        const customResult = await customCrypto.encrypt(testData, {
            algorithm: 'quantum-resistant'
        });
        console.log(`  ✓ Quantum-resistant: ${customResult.encrypted.substring(0, 50)}...`);
        
        const customResult2 = await customCrypto.encrypt(testData, {
            algorithm: 'serpent-256-cbc'
        });
        console.log(`  ✓ Serpent-256-CBC: ${customResult2.encrypted.substring(0, 50)}...`);
    } catch (error) {
        console.log(`  ✗ Error: ${error.message}`);
    }
    console.log();
    
    // Demonstrate runtime toggle
    console.log('Runtime Toggle Demonstration:\n');
    
    console.log('Current configuration:');
    const configSummary = manager.getConfigSummary();
    console.log(`  Mode: ${configSummary.mode}`);
    console.log(`  Custom Algorithms: ${configSummary.customAlgorithms}`);
    console.log(`  Available Algorithms: ${configSummary.availableAlgorithms}`);
    console.log();
    
    // Toggle OpenSSL mode
    console.log('Toggling OpenSSL mode to false...');
    await manager.toggleOpenSSLMode(false);
    
    const newConfig = manager.getConfigSummary();
    console.log(`  New Mode: ${newConfig.mode}`);
    console.log(`  Available Algorithms: ${newConfig.availableAlgorithms}`);
    console.log();
    
    // Toggle back
    console.log('Toggling OpenSSL mode back to true...');
    await manager.toggleOpenSSLMode(true);
    
    const finalConfig = manager.getConfigSummary();
    console.log(`  Final Mode: ${finalConfig.mode}`);
    console.log(`  Available Algorithms: ${finalConfig.availableAlgorithms}`);
    console.log();
    
    // Demonstrate stub generator integration
    console.log('Stub Generator Integration:\n');
    
    const stubGen = new StubGenerator({ 
        useOpenSSL: true, 
        allowCustomAlgorithms: false 
    });
    
    manager.registerEngine('stub-generator', stubGen);
    
    const stubAlgorithms = stubGen.getSupportedEncryptionMethods();
    console.log(`Stub generator algorithms: ${stubAlgorithms.length}`);
    console.log('First 10 stub algorithms:');
    stubAlgorithms.slice(0, 10).forEach(alg => {
        console.log(`  ✓ ${alg}`);
    });
    console.log();
    
    // Demonstrate algorithm preference updates
    console.log('Algorithm Preference Updates:\n');
    
    console.log('Adding custom algorithm preference...');
    await manager.updateAlgorithmPreference('my-custom-alg', 'aes-256-gcm');
    
    const alternative = manager.resolveAlgorithm('my-custom-alg');
    console.log(`my-custom-alg resolves to: ${alternative}`);
    console.log();
    
    // Show engine status
    console.log('Engine Status:\n');
    const engineStatus = manager.getEngineStatus();
    Object.entries(engineStatus).forEach(([name, status]) => {
        console.log(`${name}:`);
        console.log(`  Registered: ${status.registered}`);
        console.log(`  Has OpenSSL methods: ${status.hasOpenSSLMethods}`);
        console.log(`  Has algorithm methods: ${status.hasAlgorithmMethods}`);
        console.log(`  Has resolve method: ${status.hasResolveMethod}`);
        console.log();
    });
    
    // Validate engines
    console.log('Engine Validation:\n');
    const validation = manager.validateEngines();
    console.log(`Valid: ${validation.valid}`);
    if (validation.errors.length > 0) {
        console.log('Errors:');
        validation.errors.forEach(error => console.log(`  ✗ ${error}`));
    }
    if (validation.warnings.length > 0) {
        console.log('Warnings:');
        validation.warnings.forEach(warning => console.log(`  Warning: ${warning}`));
    }
    console.log();
    
    console.log('OpenSSL Toggle demonstration completed successfully!');
    console.log('\nKey Features Demonstrated:');
    console.log('  ✓ OpenSSL-only mode');
    console.log('  ✓ Custom algorithms mode');
    console.log('  ✓ Mixed mode');
    console.log('  ✓ Algorithm resolution and fallback');
    console.log('  ✓ Runtime configuration changes');
    console.log('  ✓ Engine registration and management');
    console.log('  ✓ Algorithm preference updates');
    console.log('  ✓ Engine validation');
}

// Run the demonstration
if (require.main === module) {
    demonstrateOpenSSLToggle().catch(error => {
        console.error('Demonstration failed:', error);
        process.exit(1);
    });
}

module.exports = { demonstrateOpenSSLToggle };
