// RawrZ IDE Server - Multi-Language Development Environment
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs').promises;
const { spawn, exec } = require('child_process');
const { promisify } = require('util');

const app = express();
const PORT = process.env.IDE_PORT || 4000;
const execAsync = promisify(exec);

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
// Serve the IDE interface
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'ide.html'));
});

// Static files (but not for root)
app.use('/static', express.static('public'));

// Compilation Engine Class
class IDECompiler {
    constructor() {
        this.tempDir = '/tmp/ide-workspace';
        this.initTempDir();
    }

    async initTempDir() {
        try {
            await fs.mkdir(this.tempDir, { recursive: true });
        } catch (error) {
            console.error('Failed to create temp directory:', error);
        }
    }

    async compileC(source, filename = 'program') {
        const sourceFile = path.join(this.tempDir, `${filename}.c`);
        const outputFile = path.join(this.tempDir, filename);
        
        try {
            // Write source to file
            await fs.writeFile(sourceFile, source);
            
            // Compile with gcc
            const { stdout, stderr } = await execAsync(
                `gcc -std=c11 -Wall -Wextra -o "${outputFile}" "${sourceFile}" 2>&1`,
                { timeout: 30000 }
            );
            
            // Check if compilation succeeded
            const stats = await fs.stat(outputFile).catch(() => null);
            
            return {
                success: stats !== null,
                output: stdout || stderr,
                executable: stats ? outputFile : null,
                language: 'C',
                compiler: 'gcc'
            };
        } catch (error) {
            return {
                success: false,
                output: error.message,
                error: error.stderr || error.message,
                language: 'C',
                compiler: 'gcc'
            };
        }
    }

    async compileCpp(source, filename = 'program') {
        const sourceFile = path.join(this.tempDir, `${filename}.cpp`);
        const outputFile = path.join(this.tempDir, filename);
        
        try {
            // Write source to file
            await fs.writeFile(sourceFile, source);
            
            // Compile with g++
            const { stdout, stderr } = await execAsync(
                `g++ -std=c++17 -Wall -Wextra -o "${outputFile}" "${sourceFile}" 2>&1`,
                { timeout: 30000 }
            );
            
            // Check if compilation succeeded
            const stats = await fs.stat(outputFile).catch(() => null);
            
            return {
                success: stats !== null,
                output: stdout || stderr,
                executable: stats ? outputFile : null,
                language: 'C++',
                compiler: 'g++'
            };
        } catch (error) {
            return {
                success: false,
                output: error.message,
                error: error.stderr || error.message,
                language: 'C++',
                compiler: 'g++'
            };
        }
    }

    async compileAssembly(source, filename = 'program') {
        const sourceFile = path.join(this.tempDir, `${filename}.s`);
        const outputFile = path.join(this.tempDir, filename);
        
        try {
            // Write source to file
            await fs.writeFile(sourceFile, source);
            
            // Try to compile with gcc (as inline assembly wrapper if needed)
            let compileCommand;
            
            // Check if source looks like pure assembly or needs wrapper
            if (source.includes('_start') || source.includes('main:') || source.includes('.text')) {
                // Pure assembly - compile directly
                compileCommand = `gcc -nostdlib -static -o "${outputFile}" "${sourceFile}" 2>&1`;
            } else {
                // Create a C wrapper for inline assembly
                const wrapperSource = `
#include <stdio.h>
int main() {
    asm("${source.replace(/"/g, '\\"').replace(/\n/g, '\\n')}");
    return 0;
}`;
                const wrapperFile = path.join(this.tempDir, `${filename}_wrapper.c`);
                await fs.writeFile(wrapperFile, wrapperSource);
                compileCommand = `gcc -o "${outputFile}" "${wrapperFile}" 2>&1`;
            }
            
            const { stdout, stderr } = await execAsync(compileCommand, { timeout: 30000 });
            
            // Check if compilation succeeded
            const stats = await fs.stat(outputFile).catch(() => null);
            
            return {
                success: stats !== null,
                output: stdout || stderr,
                executable: stats ? outputFile : null,
                language: 'Assembly',
                compiler: 'gcc (gas)'
            };
        } catch (error) {
            return {
                success: false,
                output: error.message,
                error: error.stderr || error.message,
                language: 'Assembly',
                compiler: 'gcc (gas)'
            };
        }
    }

    async runExecutable(executablePath, timeoutMs = 5000) {
        try {
            // Make executable
            await execAsync(`chmod +x "${executablePath}"`);
            
            // Run with timeout
            const { stdout, stderr } = await execAsync(
                `timeout ${timeoutMs/1000}s "${executablePath}" 2>&1`,
                { timeout: timeoutMs + 1000 }
            );
            
            return {
                success: true,
                output: stdout || stderr,
                exitCode: 0
            };
        } catch (error) {
            return {
                success: false,
                output: error.stdout || error.stderr || error.message,
                exitCode: error.code || 1
            };
        }
    }

    async cleanup(filename) {
        try {
            const files = await fs.readdir(this.tempDir);
            for (const file of files) {
                if (file.includes(filename)) {
                    await fs.unlink(path.join(this.tempDir, file)).catch(() => {});
                }
            }
        } catch (error) {
            console.warn('Cleanup warning:', error.message);
        }
    }
}

const compiler = new IDECompiler();

// API Endpoints

// Compile endpoint
app.post('/api/compile', async (req, res) => {
    try {
        const { source, language, filename = 'program' } = req.body;
        
        if (!source || !language) {
            return res.status(400).json({
                success: false,
                error: 'Source code and language are required'
            });
        }

        let result;
        const timestamp = Date.now();
        const uniqueFilename = `${filename}_${timestamp}`;

        switch (language.toLowerCase()) {
            case 'c':
                result = await compiler.compileC(source, uniqueFilename);
                break;
            case 'cpp':
            case 'c++':
                result = await compiler.compileCpp(source, uniqueFilename);
                break;
            case 'assembly':
            case 'asm':
                result = await compiler.compileAssembly(source, uniqueFilename);
                break;
            default:
                return res.status(400).json({
                    success: false,
                    error: `Unsupported language: ${language}`
                });
        }

        // Clean up regardless of result
        await compiler.cleanup(uniqueFilename);

        res.json({
            success: result.success,
            output: result.output || '',
            error: result.error || null,
            language: result.language,
            compiler: result.compiler,
            executableCreated: !!result.executable,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Compilation error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error during compilation',
            details: error.message
        });
    }
});

// Compile and run endpoint
app.post('/api/compile-and-run', async (req, res) => {
    try {
        const { source, language, filename = 'program', timeout = 5000 } = req.body;
        
        if (!source || !language) {
            return res.status(400).json({
                success: false,
                error: 'Source code and language are required'
            });
        }

        const timestamp = Date.now();
        const uniqueFilename = `${filename}_${timestamp}`;

        // Compile first
        let compileResult;
        switch (language.toLowerCase()) {
            case 'c':
                compileResult = await compiler.compileC(source, uniqueFilename);
                break;
            case 'cpp':
            case 'c++':
                compileResult = await compiler.compileCpp(source, uniqueFilename);
                break;
            case 'assembly':
            case 'asm':
                compileResult = await compiler.compileAssembly(source, uniqueFilename);
                break;
            default:
                return res.status(400).json({
                    success: false,
                    error: `Unsupported language: ${language}`
                });
        }

        let runResult = null;
        
        if (compileResult.success && compileResult.executable) {
            // Run the executable
            runResult = await compiler.runExecutable(compileResult.executable, timeout);
        }

        // Clean up
        await compiler.cleanup(uniqueFilename);

        res.json({
            success: compileResult.success,
            compilation: {
                success: compileResult.success,
                output: compileResult.output || '',
                error: compileResult.error || null,
                compiler: compileResult.compiler
            },
            execution: runResult ? {
                success: runResult.success,
                output: runResult.output || '',
                exitCode: runResult.exitCode
            } : null,
            language: compileResult.language,
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Compile and run error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error during compile and run',
            details: error.message
        });
    }
});

// Get supported languages
app.get('/api/languages', (req, res) => {
    res.json({
        success: true,
        languages: [
            { name: 'C', id: 'c', extensions: ['.c'], compiler: 'gcc' },
            { name: 'C++', id: 'cpp', extensions: ['.cpp', '.cxx', '.cc'], compiler: 'g++' },
            { name: 'Assembly', id: 'assembly', extensions: ['.s', '.asm'], compiler: 'gcc (gas)' }
        ]
    });
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        service: 'RawrZ IDE Server',
        version: '1.0.0',
        timestamp: new Date().toISOString(),
        compilers: {
            gcc: 'available',
            'g++': 'available',
            gas: 'available (via gcc)'
        }
    });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`RawrZ IDE Server running on port ${PORT}`);
    console.log(`Access the IDE at: http://localhost:${PORT}`);
    console.log('Available endpoints:');
    console.log('  GET  / - IDE Interface');
    console.log('  POST /api/compile - Compile source code');
    console.log('  POST /api/compile-and-run - Compile and run source code');
    console.log('  GET  /api/languages - Get supported languages');
    console.log('  GET  /api/health - Health check');
});

module.exports = app;