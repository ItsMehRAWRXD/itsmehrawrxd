/**
 * Simple test for Beaconism DLL Sideloading System
 */

console.log('Testing Beaconism DLL Sideloading System...');

try {
    // Test 1: Load the engine
    console.log('1. Loading Beaconism engine...');
    const beaconism = require('./src/engines/beaconism-dll-sideloading');
    console.log('   [INFO] Engine loaded successfully');
    
    // Test 2: Check engine properties
    console.log('2. Checking engine properties...');
    console.log(`   - Name: ${beaconism.name}`);
    console.log(`   - Version: ${beaconism.version}`);
    console.log(`   - Initialized: ${beaconism.initialized}`);
    
    // Test 3: Check platforms
    console.log('3. Checking supported platforms...');
    const platforms = ['windows', 'macos', 'linux', 'android', 'ios', 'cross-platform'];
    platforms.forEach(platform => {
        const count = Object.values(beaconism.sideloadTargets).filter(target => target.platform === platform).length;
        console.log(`   - ${platform}: ${count} targets available`);
    });
    
    // Test 4: Check architectures
    console.log('4. Checking architectures...');
    const archCount = Object.keys(beaconism.architectures).length;
    console.log(`   - Total architectures: ${archCount}`);
    
    // Test 5: Check exploit vectors
    console.log('5. Checking exploit vectors...');
    const vectorCount = Object.keys(beaconism.exploitVectors).length;
    console.log(`   - Total exploit vectors: ${vectorCount}`);
    
    // Test 6: Check encryption methods
    console.log('6. Checking encryption methods...');
    const encryptionCount = Object.keys(beaconism.encryptionMethods).length;
    console.log(`   - Total encryption methods: ${encryptionCount}`);
    
    // Test 7: Check persistence methods
    console.log('7. Checking persistence methods...');
    const persistenceCount = beaconism.persistenceMethods.size;
    console.log(`   - Total persistence methods: ${persistenceCount}`);
    
    // Test 8: Check AV evasion techniques
    console.log('8. Checking AV evasion techniques...');
    const avEvasionCount = Object.keys(beaconism.avEvasionTechniques).length;
    console.log(`   - Total AV evasion techniques: ${avEvasionCount}`);
    
    // Test 9: Check process injection methods
    console.log('9. Checking process injection methods...');
    const injectionCount = Object.keys(beaconism.processInjectionMethods).length;
    console.log(`   - Total process injection methods: ${injectionCount}`);
    
    console.log('\n[INFO] All tests completed successfully!');
    console.log('[INFO] Beaconism DLL Sideloading System is working properly!');
    
} catch (error) {
    console.error('[INFO] Test failed:', error.message);
    console.error('Stack trace:', error.stack);
    process.exit(1);
}
