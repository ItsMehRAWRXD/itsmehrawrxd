const dotNetWorkaround = require('./src/engines/dotnet-workaround');
const fs = require('fs').promises;
const path = require('path');

async function testWorkaround() {
    console.log('Testing DotNet Workaround System...\n');
    
    const testSourceCode = `using System;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Hello from RawrZ DotNet Workaround Test!");
        Console.WriteLine("This is a test of the workaround system.");
        Console.WriteLine("Current time: " + DateTime.Now);
    }
}`;

    try {
        // Initialize the workaround engine
        await dotNetWorkaround.initialize();
        console.log('✓ Workaround engine initialized successfully\n');

        // Test 1: Source Generation with Instructions
        console.log('Test 1: Source Generation with Instructions');
        const result1 = await dotNetWorkaround.generateSourceWithInstructions(testSourceCode, {
            outputPath: 'test-source-generation.exe',
            outputFormat: 'exe',
            framework: 'net6.0',
            optimization: 'release'
        });
        console.log(`✓ Generated: ${result1.outputPath}`);
        console.log(`✓ Instructions: ${result1.instructionsFile}\n`);

        // Test 2: Batch Compilation
        console.log('Test 2: Batch Compilation');
        const result2 = await dotNetWorkaround.generateBatchCompilation(testSourceCode, {
            outputPath: 'test-batch-compile.exe',
            outputFormat: 'exe',
            framework: 'net6.0',
            optimization: 'release'
        });
        console.log(`✓ Generated: ${result2.outputPath}`);
        console.log(`✓ Batch file: ${result2.batchFile}\n`);

        // Test 3: PowerShell Compilation
        console.log('Test 3: PowerShell Compilation');
        const result3 = await dotNetWorkaround.generatePowerShellCompilation(testSourceCode, {
            outputPath: 'test-powershell-compile.exe',
            outputFormat: 'exe',
            framework: 'net6.0',
            optimization: 'release'
        });
        console.log(`✓ Generated: ${result3.outputPath}`);
        console.log(`✓ PowerShell script: ${result3.psFile}\n`);

        // Test 4: Docker Compilation
        console.log('Test 4: Docker Compilation');
        const result4 = await dotNetWorkaround.generateDockerCompilation(testSourceCode, {
            outputPath: 'test-docker-compile.exe',
            outputFormat: 'exe',
            framework: 'net6.0',
            optimization: 'release'
        });
        console.log(`✓ Generated: ${result4.outputPath}`);
        console.log(`✓ Dockerfile: ${result4.dockerFile}`);
        console.log(`✓ Docker Compose: ${result4.dockerCompose}\n`);

        // Test 5: Online Compilation Instructions
        console.log('Test 5: Online Compilation Instructions');
        const result5 = await dotNetWorkaround.generateOnlineCompilationInstructions(testSourceCode, {
            outputPath: 'test-online-compile.exe',
            outputFormat: 'exe',
            framework: 'net6.0',
            optimization: 'release'
        });
        console.log(`✓ Generated: ${result5.outputPath}`);
        console.log(`✓ Online instructions: ${result5.instructionsFile}\n`);

        // Test 6: Portable Compilation Package
        console.log('Test 6: Portable Compilation Package');
        const result6 = await dotNetWorkaround.generatePortableCompilation(testSourceCode, {
            outputPath: 'test-portable-compile.exe',
            outputFormat: 'exe',
            framework: 'net6.0',
            optimization: 'release'
        });
        console.log(`✓ Generated: ${result6.outputPath}`);
        console.log(`✓ Portable directory: ${result6.portableDir}`);
        console.log(`✓ README: ${result6.readmeFile}`);
        console.log(`✓ Setup script: ${result6.setupFile}\n`);

        // Test 7: Get Available Methods
        console.log('Test 7: Available Methods');
        const methods = dotNetWorkaround.getAvailableMethods();
        console.log(`✓ Direct methods: ${methods.direct.length}`);
        console.log(`✓ Fallback methods: ${methods.fallback.length}`);
        console.log(`✓ Total methods: ${methods.total}\n`);

        // Test 8: Get Stats
        console.log('Test 8: Engine Statistics');
        const stats = dotNetWorkaround.getStats();
        console.log(`✓ Engine: ${stats.name}`);
        console.log(`✓ Version: ${stats.version}`);
        console.log(`✓ Initialized: ${stats.initialized}`);
        console.log(`✓ Available methods: ${stats.availableMethods}`);
        console.log(`✓ Fallback methods: ${stats.fallbackMethods}\n`);

        console.log('🎉 All workaround tests completed successfully!');
        console.log('\nGenerated files:');
        
        // List all generated files
        const files = [
            'test-source-generation.exe',
            'test-source-generation_instructions.txt',
            'test-batch-compile.exe',
            'test-batch-compile_compile.bat',
            'test-powershell-compile.exe',
            'test-powershell-compile_compile.ps1',
            'test-docker-compile.exe',
            'test-docker-compile_Dockerfile',
            'test-docker-compile_docker-compose.yml',
            'test-online-compile.exe',
            'test-online-compile_online_instructions.txt',
            'test-portable-compile.exe',
            'test-portable-compile_portable'
        ];

        for (const file of files) {
            try {
                const stats = await fs.stat(file);
                console.log(`✓ ${file} (${stats.size} bytes)`);
            } catch (error) {
                console.log(`✗ ${file} (not found)`);
            }
        }

    } catch (error) {
        console.error('❌ Test failed:', error.message);
        console.error(error.stack);
    }
}

// Run the test
testWorkaround().catch(console.error);
