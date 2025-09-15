# RawrZ Working Examples

This directory contains comprehensive examples demonstrating all the working features of the RawrZ platform with real API integration and complete functionality.

## 🚀 Quick Start

### Prerequisites
- Node.js 16+ installed
- RawrZ server running on `http://localhost:8080`
- All dependencies installed (`npm install`)

### Running Examples

```bash
# Run all API examples
node examples/working-api-examples.js

# Run complete CLI examples
node examples/complete-cli-examples.js

# Run OpenSSL toggle examples
node examples/openssl-toggle-example.js

# Run OpenSSL CLI examples
node examples/openssl-cli-example.js
```

## 📋 Available Examples

### 1. Working API Examples (`working-api-examples.js`)

Demonstrates complete API integration with all features:

```javascript
const { RawrZAPIExamples } = require('./examples/working-api-examples');

const api = new RawrZAPIExamples('http://localhost:8080', 'your-auth-token');

// Run all demonstrations
await api.runAllDemonstrations();

// Or run individual demonstrations
await api.demonstrateOpenSSLManagement();
await api.demonstrateAdvancedStubGeneration();
await api.demonstratePortScanning();
await api.demonstrateEncryptionWithToggle();
await api.demonstrateAdvancedCrypto();
await api.demonstrateNetworkTools();
await api.demonstrateFileOperations();
await api.demonstrateSystemMonitoring();
await api.demonstrateCompleteWorkflow();
```

**Features Demonstrated:**
- ✅ OpenSSL toggle management
- ✅ Advanced stub generation with all options
- ✅ Port scanning with interactive controls
- ✅ Encryption with OpenSSL toggle
- ✅ Advanced crypto operations
- ✅ Network tools and diagnostics
- ✅ File operations and analysis
- ✅ System monitoring and status
- ✅ Complete workflow integration

### 2. Web Panel Usage Examples (`web-panel-usage-examples.js`)

Shows how to use all interactive controls in the web panel:

```javascript
// In browser console or included in panel.html
await demonstrateOpenSSLControls();
await demonstrateAdvancedStubControls();
await demonstratePortScanControls();
await demonstrateCompleteWorkflow();
demonstrateRealTimeUpdates();
await demonstrateAPIIntegration();
```

**Interactive Controls Demonstrated:**
- 🎛️ **Sliders**: Polymorphic engine, stealth level, obfuscation level, port ranges, scan speed
- 🔄 **Toggles**: OpenSSL mode, custom algorithms, compression, packing
- ☑️ **Checkboxes**: Advanced features, scan options, security features
- 📻 **Radio Buttons**: Platform selection, scan type selection
- 📊 **Real-time Updates**: Live value display, visual feedback, status indicators

### 3. Complete CLI Examples (`complete-cli-examples.js`)

Comprehensive CLI usage with all features:

```javascript
const { RawrZCompleteCLI } = require('./examples/complete-cli-examples');

const cli = new RawrZCompleteCLI();
await cli.runAllDemonstrations();
```

**CLI Features Demonstrated:**
- 🔐 Complete OpenSSL management workflow
- 🏗️ Advanced stub generation with all options
- 🔐 Complete encryption workflow
- 🌐 Network operations and diagnostics
- 📁 File operations and analysis
- 🛡️ Complete security workflow
- ⚡ Performance testing and benchmarking

### 4. OpenSSL Toggle Examples (`openssl-toggle-example.js`)

Demonstrates OpenSSL toggle functionality:

```javascript
const { demonstrateOpenSSLToggle } = require('./examples/openssl-toggle-example');

await demonstrateOpenSSLToggle();
```

**OpenSSL Features:**
- 🔄 OpenSSL mode toggle
- 🔧 Custom algorithms toggle
- 📋 Algorithm filtering and selection
- 🔍 Algorithm resolution and fallback
- ⚙️ Runtime configuration changes
- 🏗️ Engine registration and management
- ✅ Engine validation

### 5. OpenSSL CLI Examples (`openssl-cli-example.js`)

Command-line interface for OpenSSL management:

```bash
# Show current status
node examples/openssl-cli-example.js status

# Toggle OpenSSL mode
node examples/openssl-cli-example.js toggle-openssl true

# Toggle custom algorithms
node examples/openssl-cli-example.js toggle-custom false

# List algorithms
node examples/openssl-cli-example.js list-algorithms openssl

# Test encryption
node examples/openssl-cli-example.js test-encryption aes-256-gcm "Hello World"

# Resolve algorithm
node examples/openssl-cli-example.js resolve-algorithm serpent-256-cbc

# Reset to defaults
node examples/openssl-cli-example.js reset
```

## 🎛️ Interactive Controls Usage

### Sliders

```javascript
// Polymorphic Engine Slider (0-3)
const polymorphicSlider = document.getElementById('stubPolymorphicSlider');
polymorphicSlider.value = 2; // Advanced
polymorphicSlider.dispatchEvent(new Event('input'));

// Stealth Level Slider (0-3)
const stealthSlider = document.getElementById('stubStealthSlider');
stealthSlider.value = 3; // Maximum
stealthSlider.dispatchEvent(new Event('input'));

// Obfuscation Level Slider (0-4)
const obfuscationSlider = document.getElementById('stubObfuscationSlider');
obfuscationSlider.value = 4; // Extreme
obfuscationSlider.dispatchEvent(new Event('input'));

// Port Range Sliders (1-65535)
const startPortSlider = document.getElementById('scanStartPortSlider');
startPortSlider.value = 80;
startPortSlider.dispatchEvent(new Event('input'));

const endPortSlider = document.getElementById('scanEndPortSlider');
endPortSlider.value = 443;
endPortSlider.dispatchEvent(new Event('input'));

// Scan Speed Slider (1-5)
const speedSlider = document.getElementById('scanSpeedSlider');
speedSlider.value = 3; // Fast
speedSlider.dispatchEvent(new Event('input'));
```

### Toggles

```javascript
// OpenSSL Mode Toggle
const opensslToggle = document.getElementById('opensslToggle');
opensslToggle.checked = true;
opensslToggle.dispatchEvent(new Event('change'));

// Custom Algorithms Toggle
const customToggle = document.getElementById('customAlgorithmsToggle');
customToggle.checked = false;
customToggle.dispatchEvent(new Event('change'));

// Compression Toggle
const compressionToggle = document.getElementById('stubCompressionToggle');
compressionToggle.checked = true;
compressionToggle.dispatchEvent(new Event('change'));

// Packing Toggle
const packingToggle = document.getElementById('stubPackingToggle');
packingToggle.checked = true;
packingToggle.dispatchEvent(new Event('change'));
```

### Checkboxes

```javascript
// Advanced Features Checkboxes
const features = [
    'stubHotPatch',
    'stubMemoryProtect',
    'stubSelfModifying',
    'stubEncryptedStrings',
    'stubControlFlowFlattening',
    'stubDeadCodeInjection'
];

features.forEach(featureId => {
    const checkbox = document.getElementById(featureId);
    if (checkbox) {
        checkbox.checked = true;
        checkbox.dispatchEvent(new Event('change'));
    }
});

// Scan Options Checkboxes
const scanOptions = [
    'scanVerbose',
    'scanStealth',
    'scanServiceDetection',
    'scanOSDetection'
];

scanOptions.forEach(optionId => {
    const checkbox = document.getElementById(optionId);
    if (checkbox) {
        checkbox.checked = true;
        checkbox.dispatchEvent(new Event('change'));
    }
});
```

### Radio Buttons

```javascript
// Platform Selection
const platformRadio = document.querySelector('input[name="targetPlatform"][value="windows"]');
platformRadio.checked = true;
platformRadio.dispatchEvent(new Event('change'));

// Scan Type Selection
const scanTypeRadio = document.querySelector('input[name="scanType"][value="tcp"]');
scanTypeRadio.checked = true;
scanTypeRadio.dispatchEvent(new Event('change'));
```

## 🔧 API Integration Examples

### OpenSSL Management API

```javascript
// Get current configuration
const config = await api('/openssl/config');

// Toggle OpenSSL mode
await api('/openssl/toggle-openssl', 'POST', { enabled: true });

// Toggle custom algorithms
await api('/openssl/toggle-custom', 'POST', { enabled: false });

// Get available algorithms
const algorithms = await api('/openssl/algorithms');

// Get OpenSSL-only algorithms
const opensslAlgorithms = await api('/openssl/openssl-algorithms');

// Get custom algorithms
const customAlgorithms = await api('/openssl/custom-algorithms');

// Resolve algorithm
const resolved = await api('/openssl/resolve-algorithm', 'POST', { 
    algorithm: 'serpent-256-cbc' 
});

// Update algorithm preference
await api('/openssl/update-preference', 'POST', {
    customAlgorithm: 'my-custom-alg',
    opensslAlternative: 'aes-256-gcm'
});

// Reset to defaults
await api('/openssl/reset', 'POST');
```

### Advanced Stub Generation API

```javascript
const options = {
    // Slider values
    polymorphic: 'advanced',
    stealth: 'high',
    obfuscation: 'extreme',
    
    // Toggle values
    compression: 'gzip',
    packing: 'upx',
    
    // Checkbox values
    hotPatch: true,
    memoryProtect: true,
    selfModifying: false,
    encryptedStrings: true,
    controlFlowFlattening: true,
    deadCodeInjection: false,
    
    // Platform selection
    target: 'windows',
    
    // Additional options
    encryptionMethod: 'aes-256-gcm',
    includeAntiDebug: true,
    includeAntiVM: true,
    includeAntiSandbox: true
};

const result = await api('/stub', 'POST', { target: 'demo.exe', options });
```

### Port Scanning API

```javascript
const options = {
    startPort: 80,
    endPort: 443,
    scanType: 'tcp',
    speed: 'fast',
    verbose: true,
    stealth: false,
    serviceDetection: true,
    osDetection: false
};

const result = await api('/portscan', 'POST', { 
    host: '127.0.0.1', 
    startPort: options.startPort, 
    endPort: options.endPort,
    ...options 
});
```

## 📊 Real-time Control Updates

### Slider Value Updates

```javascript
// Monitor slider changes
const sliders = document.querySelectorAll('.slider');
sliders.forEach(slider => {
    slider.addEventListener('input', (e) => {
        const value = e.target.value;
        const id = e.target.id;
        
        // Update corresponding value display
        const valueElement = document.getElementById(id.replace('Slider', 'Value'));
        if (valueElement) {
            // Update based on slider type
            if (id.includes('Polymorphic')) {
                const labels = ['None', 'Basic', 'Advanced', 'Extreme'];
                valueElement.textContent = labels[parseInt(value)];
            } else if (id.includes('Stealth')) {
                const labels = ['Low', 'Medium', 'High', 'Maximum'];
                valueElement.textContent = labels[parseInt(value)];
            } else if (id.includes('Obfuscation')) {
                const labels = ['None', 'Basic', 'Intermediate', 'Advanced', 'Extreme'];
                valueElement.textContent = labels[parseInt(value)];
            } else if (id.includes('Speed')) {
                const labels = ['Slow', 'Normal', 'Fast', 'Aggressive', 'Insane'];
                valueElement.textContent = labels[parseInt(value) - 1];
            } else {
                valueElement.textContent = value;
            }
        }
    });
});
```

### Toggle Status Updates

```javascript
// Monitor toggle changes
const toggles = document.querySelectorAll('.toggle-switch input');
toggles.forEach(toggle => {
    toggle.addEventListener('change', (e) => {
        const enabled = e.target.checked;
        const id = e.target.id;
        
        // Update status text
        const statusElement = document.getElementById(id.replace('Toggle', 'Status'));
        if (statusElement) {
            const feature = id.replace('stub', '').replace('Toggle', '');
            statusElement.textContent = `${feature}: ${enabled ? 'Enabled' : 'Disabled'}`;
        }
        
        // Enable/disable related controls
        if (id === 'stubCompressionToggle') {
            const select = document.getElementById('stubCompression');
            if (select) {
                select.disabled = !enabled;
                select.style.opacity = enabled ? '1' : '0.5';
            }
        }
    });
});
```

## 🎯 Complete Workflow Examples

### Security Workflow

```javascript
async function securityWorkflow() {
    // Step 1: Configure maximum security
    await toggleOpenSSLMode(true);
    await toggleCustomAlgorithms(true);
    
    // Step 2: Set up advanced stub options
    const stubOptions = {
        polymorphic: 'extreme',
        stealth: 'maximum',
        obfuscation: 'extreme',
        compression: 'gzip',
        packing: 'upx',
        hotPatch: true,
        memoryProtect: true,
        encryptedStrings: true,
        controlFlowFlattening: true,
        target: 'windows'
    };
    
    // Step 3: Generate secure stub
    const stubResult = await runAdvancedStub({
        target: 'secure-app.exe',
        options: stubOptions
    });
    
    // Step 4: Encrypt sensitive data
    const encryptedData = await encrypt('aes-256-gcm', 'sensitive-data.txt');
    
    // Step 5: Generate security report
    const report = {
        timestamp: new Date().toISOString(),
        securityLevel: 'maximum',
        stubGeneration: stubResult.success ? 'success' : 'failed',
        dataEncryption: 'success',
        recommendations: [
            'Use OpenSSL-compatible algorithms for maximum compatibility',
            'Enable all anti-analysis features for production use',
            'Use extreme obfuscation for sensitive applications'
        ]
    };
    
    return report;
}
```

### Performance Testing Workflow

```javascript
async function performanceWorkflow() {
    const testData = 'Performance test data';
    const iterations = 100;
    
    // Test OpenSSL algorithms
    const opensslAlgorithms = ['aes-256-gcm', 'aes-256-cbc', 'chacha20'];
    const opensslResults = {};
    
    for (const algorithm of opensslAlgorithms) {
        const startTime = Date.now();
        
        for (let i = 0; i < iterations; i++) {
            await encrypt(algorithm, testData);
        }
        
        const endTime = Date.now();
        const avgTime = (endTime - startTime) / iterations;
        opensslResults[algorithm] = avgTime;
    }
    
    // Test custom algorithms
    const customAlgorithms = ['quantum-resistant', 'serpent-256-cbc'];
    const customResults = {};
    
    for (const algorithm of customAlgorithms) {
        const startTime = Date.now();
        
        for (let i = 0; i < iterations; i++) {
            await encrypt(algorithm, testData);
        }
        
        const endTime = Date.now();
        const avgTime = (endTime - startTime) / iterations;
        customResults[algorithm] = avgTime;
    }
    
    return {
        openssl: opensslResults,
        custom: customResults,
        fastest: {
            openssl: Object.entries(opensslResults).reduce((a, b) => a[1] < b[1] ? a : b),
            custom: Object.entries(customResults).reduce((a, b) => a[1] < b[1] ? a : b)
        }
    };
}
```

## 🔍 Troubleshooting

### Common Issues

1. **Server not running**: Make sure the RawrZ server is running on `http://localhost:8080`
2. **Authentication errors**: Check if you need to provide an auth token
3. **API errors**: Verify the server is healthy with `/health` endpoint
4. **Control not responding**: Check if the element IDs match the HTML

### Debug Mode

```javascript
// Enable debug logging
localStorage.setItem('debug', 'true');

// Check server health
fetch('/health')
    .then(response => response.json())
    .then(data => console.log('Server health:', data));

// Check OpenSSL configuration
fetch('/openssl/config')
    .then(response => response.json())
    .then(data => console.log('OpenSSL config:', data));
```

## 📚 Additional Resources

- **API Documentation**: See `server.js` for all available endpoints
- **OpenSSL Configuration**: See `src/utils/openssl-config.js`
- **OpenSSL Management**: See `src/utils/openssl-manager.js`
- **Advanced Crypto**: See `src/engines/advanced-crypto.js`
- **Stub Generator**: See `src/engines/stub-generator.js`

## 🎉 Conclusion

These examples demonstrate the complete functionality of the RawrZ platform with:
- ✅ Fully working API integration
- ✅ Interactive web panel controls
- ✅ Complete CLI functionality
- ✅ OpenSSL toggle management
- ✅ Advanced stub generation
- ✅ Real-time control updates
- ✅ Comprehensive error handling
- ✅ Performance testing
- ✅ Security workflows

All examples are production-ready and can be used as templates for your own implementations.
