/**
 * Private Virus Scanner - Multi-Engine Private Scanning
 * Integrates multiple top-tier antivirus engines for private scanning
 * No file distribution - all scanning happens locally
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');
const { promisify } = require('util');
const { logger } = require('../utils/logger');

const execAsync = promisify(exec);

class PrivateVirusScanner {
    constructor() {
        this.name = 'PrivateVirusScanner';
        this.version = '1.0.0';
        this.scanQueue = new Map();
        this.scanResults = new Map();
        this.engines = new Map();
        this.scanHistory = [];
        this.maxConcurrentScans = 5;
        this.activeScans = 0;
        
        // Initialize scanning engines
        this.initializeEngines();
    }

    async initialize(config = {}) {
        this.config = config;
        this.scanDirectory = config.scanDirectory || './scans';
        this.tempDirectory = config.tempDirectory || './temp';
        this.resultsDirectory = config.resultsDirectory || './scan-results';
        
        // Create directories
        await this.createDirectories();
        
        // Initialize engine configurations
        await this.configureEngines();
        
        logger.info('Private Virus Scanner initialized with multiple engines');
    }

    async createDirectories() {
        const dirs = [this.scanDirectory, this.tempDirectory, this.resultsDirectory];
        for (const dir of dirs) {
            try {
                await fs.mkdir(dir, { recursive: true });
            } catch (error) {
                logger.error(`Failed to create directory ${dir}:`, error);
            }
        }
    }

    initializeEngines() {
        // ClamAV Engine
        this.engines.set('clamav', {
            name: 'ClamAV',
            type: 'signature',
            command: 'clamscan',
            args: ['--no-summary', '--infected', '--remove=no'],
            enabled: true,
            weight: 0.8,
            description: 'Open source antivirus engine'
        });

        // Windows Defender Engine
        this.engines.set('defender', {
            name: 'Windows Defender',
            type: 'signature',
            command: 'powershell',
            args: ['-Command', 'Get-MpThreatDetection'],
            enabled: true,
            weight: 0.9,
            description: 'Microsoft Windows Defender'
        });

        // Custom Signature Engine
        this.engines.set('custom', {
            name: 'Custom Signatures',
            type: 'signature',
            command: 'node',
            args: ['custom-scanner.js'],
            enabled: true,
            weight: 0.7,
            description: 'Custom signature-based detection'
        });

        // Heuristic Engine
        this.engines.set('heuristic', {
            name: 'Heuristic Analysis',
            type: 'heuristic',
            command: 'node',
            args: ['heuristic-scanner.js'],
            enabled: true,
            weight: 0.6,
            description: 'Behavioral and heuristic analysis'
        });

        // YARA Rules Engine
        this.engines.set('yara', {
            name: 'YARA Rules',
            type: 'signature',
            command: 'yara',
            args: ['-r', '-w', 'malware.yar'],
            enabled: true,
            weight: 0.85,
            description: 'YARA pattern matching engine'
        });

        // Machine Learning Engine
        this.engines.set('ml', {
            name: 'Machine Learning',
            type: 'ml',
            command: 'python',
            args: ['ml-scanner.py'],
            enabled: true,
            weight: 0.75,
            description: 'AI-powered malware detection'
        });

        // Network Analysis Engine
        this.engines.set('network', {
            name: 'Network Analysis',
            type: 'network',
            command: 'node',
            args: ['network-scanner.js'],
            enabled: true,
            weight: 0.7,
            description: 'Network traffic and communication analysis'
        });

        // Memory Analysis Engine
        this.engines.set('memory', {
            name: 'Memory Analysis',
            type: 'memory',
            command: 'volatility',
            args: ['-f', 'memory.dmp', 'malware'],
            enabled: true,
            weight: 0.8,
            description: 'Memory dump analysis for malware detection'
        });

        // Additional Engine
        this.engines.set('additional', {
            name: 'Additional Analysis',
            type: 'comprehensive',
            command: 'yara',
            args: ['-r', '-w'],
            enabled: true,
            weight: 0.8,
            description: 'YARA pattern matching engine'
        });

        // Machine Learning Engine
        this.engines.set('ml', {
            name: 'ML Detection',
            type: 'machine_learning',
            command: 'node',
            args: ['ml-scanner.js'],
            enabled: true,
            weight: 0.7,
            description: 'Machine learning-based detection'
        });

        // Static Analysis Engine
        this.engines.set('static', {
            name: 'Static Analysis',
            type: 'static',
            command: 'node',
            args: ['static-scanner.js'],
            enabled: true,
            weight: 0.6,
            description: 'Static code analysis'
        });

        // Network Analysis Engine
        this.engines.set('network', {
            name: 'Network Analysis',
            type: 'network',
            command: 'node',
            args: ['network-scanner.js'],
            enabled: true,
            weight: 0.5,
            description: 'Network behavior analysis'
        });
    }

    async configureEngines() {
        // Check engine availability and configure
        for (const [engineId, engine] of this.engines) {
            try {
                engine.available = await this.checkEngineAvailability(engine);
                if (engine.available) {
                    logger.info(`Engine ${engine.name} is available`);
                } else {
                    logger.warn(`Engine ${engine.name} is not available`);
                }
            } catch (error) {
                logger.error(`Error checking engine ${engine.name}:`, error);
                engine.available = false;
            }
        }
    }

    async checkEngineAvailability(engine) {
        try {
            if (engine.command === 'node') {
                // For Node.js-based engines, check if the script exists
                const scriptPath = path.join(__dirname, engine.args[0]);
                await fs.access(scriptPath);
                return true;
            } else {
                // For external commands, check if they're in PATH
                await execAsync(`where ${engine.command}`);
                return true;
            }
        } catch (error) {
            return false;
        }
    }

    /**
     * Scan a file with all available engines
     * @param {string} filePath - Path to the file to scan
     * @param {Object} options - Scan options
     * @returns {Object} Scan results
     */
    async scanFile(filePath, options = {}) {
        const scanId = this.generateScanId();
        const startTime = Date.now();

        try {
            logger.info(`Starting private scan for: ${filePath} (ID: ${scanId})`);

            // Validate file
            const fileInfo = await this.validateFile(filePath);
            if (!fileInfo.valid) {
                throw new Error(`Invalid file: ${fileInfo.error}`);
            }

            // Add to scan queue
            this.scanQueue.set(scanId, {
                id: scanId,
                filePath,
                fileInfo,
                startTime,
                status: 'queued',
                engines: new Map(),
                options
            });

            // Wait for available slot
            await this.waitForScanSlot();

            // Update status
            this.scanQueue.get(scanId).status = 'scanning';
            this.activeScans++;

            // Run scans with all available engines
            const engineResults = await this.runEngineScans(scanId, filePath, options);

            // Calculate overall result
            const overallResult = this.calculateOverallResult(engineResults);

            // Create final result
            const scanResult = {
                scanId,
                filePath,
                fileInfo,
                startTime,
                endTime: Date.now(),
                duration: Date.now() - startTime,
                status: 'completed',
                engines: engineResults,
                overall: overallResult,
                options,
                timestamp: new Date().toISOString()
            };

            // Store result
            this.scanResults.set(scanId, scanResult);
            this.scanHistory.push(scanResult);

            // Clean up
            this.scanQueue.delete(scanId);
            this.activeScans--;

            logger.info(`Scan completed for ${filePath} (ID: ${scanId}) - Result: ${overallResult.status}`);

            return {
                success: true,
                result: scanResult
            };

        } catch (error) {
            logger.error(`Scan failed for ${filePath} (ID: ${scanId}):`, error);
            
            // Clean up on error
            this.scanQueue.delete(scanId);
            this.activeScans--;

            return {
                success: false,
                error: error.message,
                scanId,
                filePath,
                timestamp: new Date().toISOString()
            };
        }
    }

    async validateFile(filePath) {
        try {
            const stats = await fs.stat(filePath);
            const fileSize = stats.size;
            
            // Check file size limits
            const maxSize = 100 * 1024 * 1024; // 100MB
            if (fileSize > maxSize) {
                return { valid: false, error: `File too large: ${fileSize} bytes (max: ${maxSize})` };
            }

            // Check file type
            const ext = path.extname(filePath).toLowerCase();
            const allowedExts = ['.exe', '.dll', '.sys', '.scr', '.com', '.bat', '.cmd', '.ps1', '.js', '.vbs', '.jar', '.zip', '.rar', '.7z'];
            if (!allowedExts.includes(ext)) {
                return { valid: false, error: `Unsupported file type: ${ext}` };
            }

            return {
                valid: true,
                size: fileSize,
                extension: ext,
                modified: stats.mtime,
                created: stats.birthtime
            };

        } catch (error) {
            return { valid: false, error: error.message };
        }
    }

    async waitForScanSlot() {
        while (this.activeScans >= this.maxConcurrentScans) {
            await new Promise(resolve => setTimeout(resolve, 100));
        }
    }

    async runEngineScans(scanId, filePath, options) {
        const engineResults = new Map();
        const scanPromises = [];

        // Run scans in parallel for available engines
        for (const [engineId, engine] of this.engines) {
            if (engine.available && engine.enabled) {
                const promise = this.runEngineScan(engineId, engine, filePath, options)
                    .then(result => {
                        engineResults.set(engineId, result);
                        return result;
                    })
                    .catch(error => {
                        logger.error(`Engine ${engine.name} failed:`, error);
                        engineResults.set(engineId, {
                            engineId,
                            name: engine.name,
                            status: 'error',
                            error: error.message,
                            duration: 0
                        });
                    });
                
                scanPromises.push(promise);
            }
        }

        // Wait for all scans to complete
        await Promise.all(scanPromises);

        return engineResults;
    }

    async runEngineScan(engineId, engine, filePath, options) {
        const startTime = Date.now();
        
        try {
            let result;
            
            switch (engine.type) {
                case 'signature':
                    result = await this.runSignatureScan(engine, filePath);
                    break;
                case 'heuristic':
                    result = await this.runHeuristicScan(engine, filePath);
                    break;
                case 'machine_learning':
                    result = await this.runMLScan(engine, filePath);
                    break;
                case 'static':
                    result = await this.runStaticScan(engine, filePath);
                    break;
                case 'network':
                    result = await this.runNetworkScan(engine, filePath);
                    break;
                default:
                    result = await this.runGenericScan(engine, filePath);
            }

            return {
                engineId,
                name: engine.name,
                type: engine.type,
                status: 'completed',
                result,
                duration: Date.now() - startTime,
                weight: engine.weight
            };

        } catch (error) {
            return {
                engineId,
                name: engine.name,
                type: engine.type,
                status: 'error',
                error: error.message,
                duration: Date.now() - startTime,
                weight: engine.weight
            };
        }
    }

    async runSignatureScan(engine, filePath) {
        if (engine.command === 'clamav') {
            return await this.runClamAVScan(filePath);
        } else if (engine.command === 'powershell' && engine.name === 'Windows Defender') {
            return await this.runDefenderScan(filePath);
        } else if (engine.command === 'yara') {
            return await this.runYARAScan(filePath);
        } else {
            return await this.runCustomSignatureScan(filePath);
        }
    }

    async runClamAVScan(filePath) {
        try {
            const { stdout, stderr } = await execAsync(`clamscan --no-summary --infected --remove=no "${filePath}"`);
            
            const isInfected = stdout.includes('FOUND') || stderr.includes('FOUND');
            const threats = this.parseClamAVOutput(stdout + stderr);
            
            return {
                detected: isInfected,
                threats,
                rawOutput: stdout + stderr,
                engine: 'ClamAV'
            };
        } catch (error) {
            // ClamAV returns non-zero exit code when threats are found
            if (error.code === 1) {
                const threats = this.parseClamAVOutput(error.stdout + error.stderr);
                return {
                    detected: true,
                    threats,
                    rawOutput: error.stdout + error.stderr,
                    engine: 'ClamAV'
                };
            }
            throw error;
        }
    }

    async runDefenderScan(filePath) {
        try {
            // Use PowerShell to run Windows Defender scan
            const command = `powershell -Command "Start-MpScan -ScanType CustomScan -ScanPath '${filePath}' -AsJob | Wait-Job | Receive-Job"`;
            const { stdout } = await execAsync(command);
            
            // Parse Defender output
            const isInfected = stdout.includes('Threat') || stdout.includes('Infected');
            
            return {
                detected: isInfected,
                threats: isInfected ? ['Windows Defender Threat'] : [],
                rawOutput: stdout,
                engine: 'Windows Defender'
            };
        } catch (error) {
            // Defender might return non-zero for threats
            return {
                detected: true,
                threats: ['Windows Defender Threat'],
                rawOutput: error.stdout || error.message,
                engine: 'Windows Defender'
            };
        }
    }

    async runYARAScan(filePath) {
        try {
            const { stdout } = await execAsync(`yara -r -w "${filePath}"`);
            
            const isInfected = stdout.trim().length > 0;
            const threats = stdout.trim().split('\n').filter(line => line.trim());
            
            return {
                detected: isInfected,
                threats,
                rawOutput: stdout,
                engine: 'YARA'
            };
        } catch (error) {
            // YARA returns non-zero when matches are found
            if (error.code === 1) {
                const threats = error.stdout.trim().split('\n').filter(line => line.trim());
                return {
                    detected: true,
                    threats,
                    rawOutput: error.stdout,
                    engine: 'YARA'
                };
            }
            throw error;
        }
    }

    async runCustomSignatureScan(filePath) {
        // Simulate custom signature scanning
        const fileContent = await fs.readFile(filePath);
        const fileHash = crypto.createHash('sha256').update(fileContent).digest('hex');
        
        // Check against known malware hashes (simplified)
        const knownMalwareHashes = [
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', // Empty file
            // Add more known malware hashes here
        ];
        
        const isKnownMalware = knownMalwareHashes.includes(fileHash);
        
        return {
            detected: isKnownMalware,
            threats: isKnownMalware ? ['Known Malware Hash'] : [],
            fileHash,
            engine: 'Custom Signatures'
        };
    }

    async runHeuristicScan(engine, filePath) {
        // Simulate heuristic analysis
        const fileContent = await fs.readFile(filePath);
        const suspiciousPatterns = [
            'CreateProcess', 'WriteProcessMemory', 'VirtualAlloc',
            'LoadLibrary', 'GetProcAddress', 'CreateRemoteThread'
        ];
        
        const contentStr = fileContent.toString('utf8', 0, Math.min(1024, fileContent.length));
        const foundPatterns = suspiciousPatterns.filter(pattern => 
            contentStr.includes(pattern)
        );
        
        const suspiciousScore = foundPatterns.length / suspiciousPatterns.length;
        const isSuspicious = suspiciousScore > 0.3;
        
        return {
            detected: isSuspicious,
            suspiciousScore,
            patterns: foundPatterns,
            engine: 'Heuristic Analysis'
        };
    }

    async runMLScan(engine, filePath) {
        // Simulate machine learning analysis
        const fileContent = await fs.readFile(filePath);
        const features = this.extractMLFeatures(fileContent);
        
        // Simulate ML prediction (in real implementation, use actual ML model)
        const mlScore = Math.random(); // Replace with actual ML prediction
        const isMalicious = mlScore > 0.7;
        
        return {
            detected: isMalicious,
            mlScore,
            features,
            engine: 'ML Detection'
        };
    }

    async runStaticScan(engine, filePath) {
        // Simulate static analysis
        const fileContent = await fs.readFile(filePath);
        const analysis = this.performStaticAnalysis(fileContent);
        
        return {
            detected: analysis.suspicious,
            analysis,
            engine: 'Static Analysis'
        };
    }

    async runNetworkScan(engine, filePath) {
        // Simulate network analysis
        const fileContent = await fs.readFile(filePath);
        const networkFeatures = this.extractNetworkFeatures(fileContent);
        
        return {
            detected: networkFeatures.suspicious,
            networkFeatures,
            engine: 'Network Analysis'
        };
    }

    async runGenericScan(engine, filePath) {
        // Generic scan implementation
        return {
            detected: false,
            message: 'Generic scan completed',
            engine: engine.name
        };
    }

    parseClamAVOutput(output) {
        const threats = [];
        const lines = output.split('\n');
        
        for (const line of lines) {
            if (line.includes('FOUND')) {
                const match = line.match(/(.+): (.+) FOUND/);
                if (match) {
                    threats.push(match[2]);
                }
            }
        }
        
        return threats;
    }

    extractMLFeatures(fileContent) {
        // Extract features for ML analysis
        return {
            entropy: this.calculateEntropy(fileContent),
            size: fileContent.length,
            strings: this.extractStrings(fileContent),
            imports: this.extractImports(fileContent)
        };
    }

    performStaticAnalysis(fileContent) {
        // Perform static analysis
        const strings = this.extractStrings(fileContent);
        const suspiciousStrings = strings.filter(str => 
            str.includes('malware') || str.includes('virus') || str.includes('trojan')
        );
        
        return {
            suspicious: suspiciousStrings.length > 0,
            suspiciousStrings,
            totalStrings: strings.length
        };
    }

    extractNetworkFeatures(fileContent) {
        // Extract network-related features
        const contentStr = fileContent.toString('utf8', 0, Math.min(2048, fileContent.length));
        const networkPatterns = [
            'http://', 'https://', 'ftp://', 'tcp://', 'udp://',
            'socket', 'connect', 'bind', 'listen'
        ];
        
        const foundPatterns = networkPatterns.filter(pattern => 
            contentStr.includes(pattern)
        );
        
        return {
            suspicious: foundPatterns.length > 2,
            networkPatterns: foundPatterns
        };
    }

    calculateEntropy(data) {
        const freq = new Array(256).fill(0);
        for (let i = 0; i < data.length; i++) {
            freq[data[i]]++;
        }
        
        let entropy = 0;
        for (let i = 0; i < 256; i++) {
            if (freq[i] > 0) {
                const p = freq[i] / data.length;
                entropy -= p * Math.log2(p);
            }
        }
        
        return entropy;
    }

    extractStrings(data, minLength = 4) {
        const strings = [];
        let current = '';
        
        for (let i = 0; i < data.length; i++) {
            const char = data[i];
            if (char >= 32 && char <= 126) {
                current += String.fromCharCode(char);
            } else {
                if (current.length >= minLength) {
                    strings.push(current);
                }
                current = '';
            }
        }
        
        if (current.length >= minLength) {
            strings.push(current);
        }
        
        return strings;
    }

    extractImports(data) {
        // Simplified import extraction
        const contentStr = data.toString('utf8', 0, Math.min(1024, data.length));
        const importPatterns = [
            'kernel32.dll', 'user32.dll', 'ntdll.dll', 'advapi32.dll',
            'ws2_32.dll', 'wininet.dll', 'urlmon.dll'
        ];
        
        return importPatterns.filter(pattern => contentStr.includes(pattern));
    }

    calculateOverallResult(engineResults) {
        let totalWeight = 0;
        let weightedScore = 0;
        let detectedCount = 0;
        let totalEngines = 0;
        
        for (const [engineId, result] of engineResults) {
            if (result.status === 'completed') {
                totalEngines++;
                totalWeight += result.weight;
                
                if (result.result && result.result.detected) {
                    detectedCount++;
                    weightedScore += result.weight;
                }
            }
        }
        
        if (totalEngines === 0) {
            return {
                status: 'error',
                message: 'No engines completed successfully',
                detectionRate: 0,
                confidence: 0
            };
        }
        
        const detectionRate = (detectedCount / totalEngines) * 100;
        const confidence = totalWeight > 0 ? (weightedScore / totalWeight) * 100 : 0;
        
        let status;
        if (detectionRate >= 50) {
            status = 'malicious';
        } else if (detectionRate >= 20) {
            status = 'suspicious';
        } else if (detectionRate > 0) {
            status = 'low_risk';
        } else {
            status = 'clean';
        }
        
        return {
            status,
            detectionRate: Math.round(detectionRate * 10) / 10,
            confidence: Math.round(confidence * 10) / 10,
            detectedEngines: detectedCount,
            totalEngines,
            message: this.getStatusMessage(status, detectionRate)
        };
    }

    getStatusMessage(status, detectionRate) {
        switch (status) {
            case 'malicious':
                return `High threat detected (${detectionRate}% engines detected threats)`;
            case 'suspicious':
                return `Suspicious file (${detectionRate}% engines detected threats)`;
            case 'low_risk':
                return `Low risk file (${detectionRate}% engines detected threats)`;
            case 'clean':
                return 'File appears clean (no threats detected)';
            default:
                return 'Unknown status';
        }
    }

    generateScanId() {
        return crypto.randomBytes(16).toString('hex');
    }

    // Get scan result by ID
    getScanResult(scanId) {
        return this.scanResults.get(scanId);
    }

    // Get scan history
    getScanHistory(limit = 100) {
        return this.scanHistory.slice(-limit);
    }

    // Get engine status
    getEngineStatus() {
        const status = {};
        for (const [engineId, engine] of this.engines) {
            status[engineId] = {
                name: engine.name,
                type: engine.type,
                enabled: engine.enabled,
                available: engine.available,
                weight: engine.weight,
                description: engine.description
            };
        }
        return status;
    }

    // Get scanner statistics
    getScannerStats() {
        const totalScans = this.scanHistory.length;
        const completedScans = this.scanHistory.filter(scan => scan.status === 'completed').length;
        const maliciousScans = this.scanHistory.filter(scan => 
            scan.overall && scan.overall.status === 'malicious'
        ).length;
        
        return {
            totalScans,
            completedScans,
            maliciousScans,
            cleanScans: completedScans - maliciousScans,
            activeScans: this.activeScans,
            queuedScans: this.scanQueue.size,
            availableEngines: Array.from(this.engines.values()).filter(e => e.available).length,
            totalEngines: this.engines.size
        };
    }

    // Advanced scan queue management
    async addToQueue(filePath, options = {}) {
        const scanId = crypto.randomUUID();
        const queueItem = {
            id: scanId,
            filePath: filePath,
            options: options,
            status: 'queued',
            priority: options.priority || 'normal',
            createdAt: new Date(),
            engines: options.engines || Array.from(this.engines.keys()),
            callback: options.callback || null
        };
        
        this.scanQueue.set(scanId, queueItem);
        logger.info(`Added scan to queue: ${scanId} for ${filePath}`);
        
        // Process queue if not at max capacity
        if (this.activeScans < this.maxConcurrentScans) {
            await this.processQueue();
        }
        
        return scanId;
    }

    async processQueue() {
        if (this.activeScans >= this.maxConcurrentScans || this.scanQueue.size === 0) {
            return;
        }
        
        // Get highest priority item
        const queueItems = Array.from(this.scanQueue.values());
        queueItems.sort((a, b) => {
            const priorityOrder = { 'high': 3, 'normal': 2, 'low': 1 };
            return priorityOrder[b.priority] - priorityOrder[a.priority];
        });
        
        const nextItem = queueItems[0];
        if (nextItem) {
            this.scanQueue.delete(nextItem.id);
            this.activeScans++;
            
            // Start scan in background
            this.performScan(nextItem.id, nextItem.filePath, nextItem.options)
                .then(result => {
                    this.activeScans--;
                    if (nextItem.callback) {
                        nextItem.callback(result);
                    }
                    // Process next item in queue
                    this.processQueue();
                })
                .catch(error => {
                    this.activeScans--;
                    logger.error(`Scan failed for ${nextItem.id}:`, error);
                    if (nextItem.callback) {
                        nextItem.callback({ error: error.message });
                    }
                    // Process next item in queue
                    this.processQueue();
                });
        }
    }

    // Get queue status
    getQueueStatus() {
        const queueItems = Array.from(this.scanQueue.values());
        const status = {
            total: queueItems.length,
            active: this.activeScans,
            maxConcurrent: this.maxConcurrentScans,
            high: queueItems.filter(item => item.priority === 'high').length,
            normal: queueItems.filter(item => item.priority === 'normal').length,
            low: queueItems.filter(item => item.priority === 'low').length,
            items: queueItems.map(item => ({
                id: item.id,
                filePath: item.filePath,
                priority: item.priority,
                createdAt: item.createdAt,
                engines: item.engines
            }))
        };
        
        return status;
    }

    // Cancel queued scan
    async cancelQueuedScan(scanId) {
        if (this.scanQueue.has(scanId)) {
            this.scanQueue.delete(scanId);
            logger.info(`Cancelled queued scan: ${scanId}`);
            return { success: true, message: 'Scan cancelled' };
        }
        return { success: false, message: 'Scan not found in queue' };
    }

    // Clear entire queue
    async clearQueue() {
        const clearedCount = this.scanQueue.size;
        this.scanQueue.clear();
        logger.info(`Cleared scan queue: ${clearedCount} items removed`);
        return { success: true, clearedCount };
    }

    // Update queue settings
    updateQueueSettings(settings) {
        if (settings.maxConcurrentScans) {
            this.maxConcurrentScans = Math.max(1, Math.min(10, settings.maxConcurrentScans));
        }
        
        logger.info('Updated queue settings:', settings);
        return { success: true, settings: {
            maxConcurrentScans: this.maxConcurrentScans
        }};
    }
}

module.exports = PrivateVirusScanner;
