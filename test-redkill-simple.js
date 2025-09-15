const redKiller = require('./src/engines/red-killer');

console.log('Testing Red Killer engine...');

try {
    console.log('1. Engine loaded:', !!redKiller);
    console.log('2. Engine name:', redKiller.name);
    console.log('3. Engine version:', redKiller.version);
    console.log('4. Engine initialized:', redKiller.initialized);
    console.log('5. AV patterns available:', !!redKiller.avPatterns);
    
    if (redKiller.avPatterns) {
        console.log('6. Number of AV patterns:', Object.keys(redKiller.avPatterns).length);
        console.log('7. First few patterns:', Object.keys(redKiller.avPatterns).slice(0, 3));
    }
    
    console.log('Test completed successfully!');
} catch (error) {
    console.error('Test failed:', error.message);
}
