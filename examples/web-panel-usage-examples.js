/**
 * RawrZ Web Panel Usage Examples
 * 
 * This file demonstrates how to use all the interactive controls in the web panel
 * with real API calls and complete functionality.
 */

// Example 1: OpenSSL Toggle Management
async function demonstrateOpenSSLControls() {
    console.log('OpenSSL Controls Demonstration');
    
    // Initialize OpenSSL manager
    await initializeOpenSSLManager();
    
    // Toggle OpenSSL mode
    await toggleOpenSSLMode(true);
    console.log('OpenSSL mode enabled');
    
    // Toggle custom algorithms
    await toggleCustomAlgorithms(false);
    console.log('Custom algorithms disabled');
    
    // Get available algorithms
    const algorithms = await loadAvailableAlgorithms();
    console.log(`Available algorithms: ${algorithms.length}`);
    
    // Filter algorithms
    filterAlgorithms('openssl');
    console.log('Filtered to OpenSSL algorithms only');
    
    // Update algorithm info
    addAlgorithmInfo();
    console.log('Algorithm info updated');
}

// Example 2: Advanced Stub Generation with All Controls
async function demonstrateAdvancedStubControls() {
    console.log('Advanced Stub Controls Demonstration');
    
    // Set polymorphic engine to advanced
    const polymorphicSlider = document.getElementById('stubPolymorphicSlider');
    if (polymorphicSlider) {
        polymorphicSlider.value = 2; // Advanced
        polymorphicSlider.dispatchEvent(new Event('input'));
    }
    
    // Set stealth level to high
    const stealthSlider = document.getElementById('stubStealthSlider');
    if (stealthSlider) {
        stealthSlider.value = 2; // High
        stealthSlider.dispatchEvent(new Event('input'));
    }
    
    // Set obfuscation to extreme
    const obfuscationSlider = document.getElementById('stubObfuscationSlider');
    if (obfuscationSlider) {
        obfuscationSlider.value = 4; // Extreme
        obfuscationSlider.dispatchEvent(new Event('input'));
    }
    
    // Enable compression
    const compressionToggle = document.getElementById('stubCompressionToggle');
    if (compressionToggle) {
        compressionToggle.checked = true;
        compressionToggle.dispatchEvent(new Event('change'));
    }
    
    // Set compression method
    const compressionSelect = document.getElementById('stubCompression');
    if (compressionSelect) {
        compressionSelect.value = 'gzip';
    }
    
    // Enable packing
    const packingToggle = document.getElementById('stubPackingToggle');
    if (packingToggle) {
        packingToggle.checked = true;
        packingToggle.dispatchEvent(new Event('change'));
    }
    
    // Set packing method
    const packingSelect = document.getElementById('stubPackingMethod');
    if (packingSelect) {
        packingSelect.value = 'upx';
    }
    
    // Enable advanced features
    const features = [
        'stubHotPatch',
        'stubMemoryProtect',
        'stubEncryptedStrings',
        'stubControlFlowFlattening'
    ];
    
    features.forEach(featureId => {
        const checkbox = document.getElementById(featureId);
        if (checkbox) {
            checkbox.checked = true;
            checkbox.dispatchEvent(new Event('change'));
        }
    });
    
    // Set target platform
    const platformRadio = document.querySelector('input[name="targetPlatform"][value="windows"]');
    if (platformRadio) {
        platformRadio.checked = true;
        platformRadio.dispatchEvent(new Event('change'));
    }
    
    // Get all options
    const options = getAdvancedStubOptions();
    console.log('Advanced stub options:', options);
    
    // Generate stub
    const target = 'demo-stub.exe';
    const result = await runAdvancedStub({ target, options });
    console.log('Stub generation result:', result);
}

// Example 3: Port Scanning with Interactive Controls
async function demonstratePortScanControls() {
    console.log('Port Scan Controls Demonstration');
    
    // Set port range
    const startPortSlider = document.getElementById('scanStartPortSlider');
    if (startPortSlider) {
        startPortSlider.value = 80;
        startPortSlider.dispatchEvent(new Event('input'));
    }
    
    const endPortSlider = document.getElementById('scanEndPortSlider');
    if (endPortSlider) {
        endPortSlider.value = 443;
        endPortSlider.dispatchEvent(new Event('input'));
    }
    
    // Set scan type
    const scanTypeRadio = document.querySelector('input[name="scanType"][value="tcp"]');
    if (scanTypeRadio) {
        scanTypeRadio.checked = true;
        scanTypeRadio.dispatchEvent(new Event('change'));
    }
    
    // Enable scan options
    const scanOptions = [
        'scanVerbose',
        'scanServiceDetection'
    ];
    
    scanOptions.forEach(optionId => {
        const checkbox = document.getElementById(optionId);
        if (checkbox) {
            checkbox.checked = true;
            checkbox.dispatchEvent(new Event('change'));
        }
    });
    
    // Set scan speed
    const speedSlider = document.getElementById('scanSpeedSlider');
    if (speedSlider) {
        speedSlider.value = 3; // Fast
        speedSlider.dispatchEvent(new Event('input'));
    }
    
    // Get scan options
    const options = getPortScanOptions();
    console.log('Port scan options:', options);
    
    // Run port scan
    const host = '127.0.0.1';
    const result = await runPortScan({ host, options });
    console.log('Port scan result:', result);
}

// Example 4: Complete Workflow with All Controls
async function demonstrateCompleteWorkflow() {
    console.log('Complete Workflow Demonstration');
    
    try {
        // Step 1: Configure OpenSSL
        console.log('Step 1: Configuring OpenSSL...');
        await toggleOpenSSLMode(true);
        await toggleCustomAlgorithms(false);
        filterAlgorithms('openssl');
        console.log('OpenSSL configured');
        
        // Step 2: Set up advanced stub options
        console.log('Step 2: Setting up advanced stub options...');
        
        // Configure all sliders
        const sliders = [
            { id: 'stubPolymorphicSlider', value: 2 }, // Advanced
            { id: 'stubStealthSlider', value: 3 }, // Maximum
            { id: 'stubObfuscationSlider', value: 4 } // Extreme
        ];
        
        sliders.forEach(({ id, value }) => {
            const slider = document.getElementById(id);
            if (slider) {
                slider.value = value;
                slider.dispatchEvent(new Event('input'));
            }
        });
        
        // Enable toggles
        const toggles = [
            'stubCompressionToggle',
            'stubPackingToggle'
        ];
        
        toggles.forEach(toggleId => {
            const toggle = document.getElementById(toggleId);
            if (toggle) {
                toggle.checked = true;
                toggle.dispatchEvent(new Event('change'));
            }
        });
        
        // Enable checkboxes
        const checkboxes = [
            'stubHotPatch',
            'stubMemoryProtect',
            'stubEncryptedStrings',
            'stubControlFlowFlattening'
        ];
        
        checkboxes.forEach(checkboxId => {
            const checkbox = document.getElementById(checkboxId);
            if (checkbox) {
                checkbox.checked = true;
                checkbox.dispatchEvent(new Event('change'));
            }
        });
        
        console.log('Advanced stub options configured');
        
        // Step 3: Set up port scanning
        console.log('Step 3: Setting up port scanning...');
        
        const portSliders = [
            { id: 'scanStartPortSlider', value: 1 },
            { id: 'scanEndPortSlider', value: 1000 },
            { id: 'scanSpeedSlider', value: 3 } // Fast
        ];
        
        portSliders.forEach(({ id, value }) => {
            const slider = document.getElementById(id);
            if (slider) {
                slider.value = value;
                slider.dispatchEvent(new Event('input'));
            }
        });
        
        // Set scan type
        const tcpRadio = document.querySelector('input[name="scanType"][value="tcp"]');
        if (tcpRadio) {
            tcpRadio.checked = true;
            tcpRadio.dispatchEvent(new Event('change'));
        }
        
        // Enable scan options
        const scanCheckboxes = ['scanVerbose', 'scanServiceDetection'];
        scanCheckboxes.forEach(checkboxId => {
            const checkbox = document.getElementById(checkboxId);
            if (checkbox) {
                checkbox.checked = true;
                checkbox.dispatchEvent(new Event('change'));
            }
        });
        
        console.log('Port scanning configured');
        
        // Step 4: Execute workflow
        console.log('Step 4: Executing workflow...');
        
        // Generate stub
        const stubOptions = getAdvancedStubOptions();
        const stubResult = await runAdvancedStub({
            target: 'workflow-demo.exe',
            options: stubOptions
        });
        
        if (stubResult.success) {
            console.log('Stub generated successfully');
        }
        
        // Run port scan
        const scanOptions = getPortScanOptions();
        const scanResult = await runPortScan({
            host: '127.0.0.1',
            options: scanOptions
        });
        
        if (scanResult.success) {
            console.log('Port scan completed successfully');
        }
        
        // Step 5: Generate report
        console.log('Step 5: Generating workflow report...');
        
        const report = {
            timestamp: new Date().toISOString(),
            workflow: 'Complete Interactive Controls Demo',
            configuration: {
                openssl: {
                    mode: 'enabled',
                    customAlgorithms: 'disabled',
                    algorithmFilter: 'openssl'
                },
                stub: stubOptions,
                scanning: scanOptions
            },
            results: {
                stubGeneration: stubResult.success ? 'Success' : 'Failed',
                portScan: scanResult.success ? 'Success' : 'Failed'
            }
        };
        
        console.log('Workflow Report:');
        console.log(JSON.stringify(report, null, 2));
        
        console.log('Complete workflow demonstration finished!');
        
    } catch (error) {
        console.error('Workflow demonstration failed:', error);
    }
}

// Example 5: Real-time Control Updates
function demonstrateRealTimeUpdates() {
    console.log('Real-time Control Updates Demonstration');
    
    // Monitor slider changes
    const sliders = document.querySelectorAll('.slider');
    sliders.forEach(slider => {
        slider.addEventListener('input', (e) => {
            const value = e.target.value;
            const id = e.target.id;
            console.log(`Slider ${id} changed to: ${value}`);
            
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
    
    // Monitor toggle changes
    const toggles = document.querySelectorAll('.toggle-switch input');
    toggles.forEach(toggle => {
        toggle.addEventListener('change', (e) => {
            const enabled = e.target.checked;
            const id = e.target.id;
            console.log(`Toggle ${id} changed to: ${enabled ? 'enabled' : 'disabled'}`);
            
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
            } else if (id === 'stubPackingToggle') {
                const select = document.getElementById('stubPackingMethod');
                if (select) {
                    select.disabled = !enabled;
                    select.style.opacity = enabled ? '1' : '0.5';
                }
            }
        });
    });
    
    // Monitor checkbox changes
    const checkboxes = document.querySelectorAll('.checkbox-item input');
    checkboxes.forEach(checkbox => {
        checkbox.addEventListener('change', (e) => {
            const checked = e.target.checked;
            const id = e.target.id;
            console.log(`Checkbox ${id} changed to: ${checked ? 'checked' : 'unchecked'}`);
            
            // Update visual feedback
            const item = e.target.closest('.checkbox-item');
            if (item) {
                if (checked) {
                    item.style.background = 'rgba(104, 211, 145, 0.1)';
                } else {
                    item.style.background = '';
                }
            }
        });
    });
    
    // Monitor radio button changes
    const radioGroups = document.querySelectorAll('input[type="radio"]');
    radioGroups.forEach(radio => {
        radio.addEventListener('change', (e) => {
            const value = e.target.value;
            const name = e.target.name;
            console.log(`Radio group ${name} changed to: ${value}`);
            
            // Update visual feedback
            const group = e.target.closest('.platform-selector, .scan-type-selector');
            if (group) {
                // Remove active class from all options
                group.querySelectorAll('.platform-option, .scan-option').forEach(option => {
                    option.classList.remove('active');
                });
                
                // Add active class to selected option
                const selectedOption = e.target.closest('.platform-option, .scan-option');
                if (selectedOption) {
                    selectedOption.classList.add('active');
                }
            }
        });
    });
    
    console.log('Real-time monitoring enabled for all controls');
}

// Example 6: API Integration with Controls
async function demonstrateAPIIntegration() {
    console.log('API Integration Demonstration');
    
    // Function to get current control values
    function getCurrentControlValues() {
        return {
            openssl: {
                useOpenSSL: document.getElementById('opensslToggle')?.checked || false,
                allowCustomAlgorithms: document.getElementById('customAlgorithmsToggle')?.checked || false,
                algorithmFilter: document.getElementById('algorithmFilter')?.value || 'all'
            },
            stub: getAdvancedStubOptions(),
            scanning: getPortScanOptions()
        };
    }
    
    // Function to update controls from API response
    function updateControlsFromAPI(apiData) {
        // Update OpenSSL controls
        if (apiData.openssl) {
            const opensslToggle = document.getElementById('opensslToggle');
            if (opensslToggle) {
                opensslToggle.checked = apiData.openssl.useOpenSSL;
                opensslToggle.dispatchEvent(new Event('change'));
            }
            
            const customToggle = document.getElementById('customAlgorithmsToggle');
            if (customToggle) {
                customToggle.checked = apiData.openssl.allowCustomAlgorithms;
                customToggle.dispatchEvent(new Event('change'));
            }
        }
        
        // Update stub controls
        if (apiData.stub) {
            // Update sliders
            if (apiData.stub.polymorphic) {
                const slider = document.getElementById('stubPolymorphicSlider');
                if (slider) {
                    const values = ['none', 'basic', 'advanced', 'extreme'];
                    const index = values.indexOf(apiData.stub.polymorphic);
                    if (index !== -1) {
                        slider.value = index;
                        slider.dispatchEvent(new Event('input'));
                    }
                }
            }
            
            // Update toggles
            if (apiData.stub.compression !== 'none') {
                const toggle = document.getElementById('stubCompressionToggle');
                if (toggle) {
                    toggle.checked = true;
                    toggle.dispatchEvent(new Event('change'));
                }
            }
            
            // Update checkboxes
            Object.entries(apiData.stub).forEach(([key, value]) => {
                if (typeof value === 'boolean') {
                    const checkbox = document.getElementById(`stub${key.charAt(0).toUpperCase() + key.slice(1)}`);
                    if (checkbox) {
                        checkbox.checked = value;
                        checkbox.dispatchEvent(new Event('change'));
                    }
                }
            });
        }
    }
    
    // Simulate API call to get configuration
    async function loadConfigurationFromAPI() {
        try {
            const response = await fetch('/openssl/config');
            const data = await response.json();
            
            if (data.success) {
                updateControlsFromAPI(data.result);
                console.log('Controls updated from API');
            }
        } catch (error) {
            console.error('Failed to load configuration from API:', error);
        }
    }
    
    // Simulate API call to save configuration
    async function saveConfigurationToAPI() {
        try {
            const currentValues = getCurrentControlValues();
            
            const response = await fetch('/openssl/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(currentValues)
            });
            
            const data = await response.json();
            
            if (data.success) {
                console.log('Configuration saved to API');
            }
        } catch (error) {
            console.error('Failed to save configuration to API:', error);
        }
    }
    
    // Load initial configuration
    await loadConfigurationFromAPI();
    
    // Save configuration when controls change
    const allControls = document.querySelectorAll('input, select');
    allControls.forEach(control => {
        control.addEventListener('change', () => {
            saveConfigurationToAPI();
        });
    });
    
    console.log('API integration enabled');
}

// Run all demonstrations
async function runAllWebPanelDemonstrations() {
    console.log('RawrZ Web Panel Demonstrations\n');
    console.log('=' .repeat(50));
    console.log();
    
    try {
        await demonstrateOpenSSLControls();
        console.log();
        
        await demonstrateAdvancedStubControls();
        console.log();
        
        await demonstratePortScanControls();
        console.log();
        
        await demonstrateCompleteWorkflow();
        console.log();
        
        demonstrateRealTimeUpdates();
        console.log();
        
        await demonstrateAPIIntegration();
        console.log();
        
        console.log('All web panel demonstrations completed successfully!');
        
    } catch (error) {
        console.error('Web panel demonstrations failed:', error);
    }
}

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        demonstrateOpenSSLControls,
        demonstrateAdvancedStubControls,
        demonstratePortScanControls,
        demonstrateCompleteWorkflow,
        demonstrateRealTimeUpdates,
        demonstrateAPIIntegration,
        runAllWebPanelDemonstrations
    };
}

// Run if in browser environment
if (typeof window !== 'undefined') {
    // Make functions available globally
    window.runAllWebPanelDemonstrations = runAllWebPanelDemonstrations;
    window.demonstrateOpenSSLControls = demonstrateOpenSSLControls;
    window.demonstrateAdvancedStubControls = demonstrateAdvancedStubControls;
    window.demonstratePortScanControls = demonstratePortScanControls;
    window.demonstrateCompleteWorkflow = demonstrateCompleteWorkflow;
    window.demonstrateRealTimeUpdates = demonstrateRealTimeUpdates;
    window.demonstrateAPIIntegration = demonstrateAPIIntegration;
}
