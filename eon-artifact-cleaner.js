#!/usr/bin/env node

// ========================================
// EON ARTIFACT CLEANER - BLACKHOLE FIX
// ========================================
// This tool fixes the "blackhole" EON files by copying them and removing
// generation artifacts so they can plug in properly
// EON = Efficient Object Notation (no missing 'e', no blackholing)

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

class EONArtifactCleaner {
    constructor() {
        this.version = "EON Artifact Cleaner v1.0.0";
        this.cleanedFiles = [];
        this.artifactsRemoved = [];
        this.blackholeFiles = [];
        
        console.log("🧹 EON Artifact Cleaner - Fixing Blackhole Files!");
        console.log("✅ No missing 'e' - No blackholing!");
    }

    // Main cleanup entry point
    async cleanEONFiles(inputPath, outputPath, options = {}) {
        try {
            console.log("🎯 Starting EON artifact cleanup...");
            
            const {
                removeHeaders = true,
                removeMetadata = true,
                removeComments = false,
                validateOutput = true,
                backupOriginal = true,
                dryRun = false
            } = options;

            // Ensure output directory exists
            await this.ensureDirectory(outputPath);

            // Process files
            const files = await this.findEONFiles(inputPath);
            console.log(`📁 Found ${files.length} EON files to process`);

            for (const file of files) {
                await this.cleanEONFile(file, outputPath, {
                    removeHeaders,
                    removeMetadata,
                    removeComments,
                    validateOutput,
                    backupOriginal,
                    dryRun
                });
            }

            // Generate cleanup report
            await this.generateCleanupReport(outputPath);

            console.log("✅ EON artifact cleanup completed successfully!");
            console.log(`📊 Processed: ${this.cleanedFiles.length} files`);
            console.log(`🗑️ Artifacts removed: ${this.artifactsRemoved.length}`);
            console.log(`🕳️ Blackholes fixed: ${this.blackholeFiles.length}`);

        } catch (error) {
            console.error("❌ EON cleanup error:", error.message);
            throw error;
        }
    }

    // Find all EON files in directory
    async findEONFiles(directory) {
        const files = [];
        
        try {
            const entries = await fs.readdir(directory, { withFileTypes: true });
            
            for (const entry of entries) {
                const fullPath = path.join(directory, entry.name);
                
                if (entry.isDirectory()) {
                    // Recursively search subdirectories
                    const subFiles = await this.findEONFiles(fullPath);
                    files.push(...subFiles);
                } else if (entry.isFile() && this.isEONFile(entry.name)) {
                    files.push(fullPath);
                }
            }
        } catch (error) {
            console.warn(`⚠️ Could not read directory ${directory}: ${error.message}`);
        }
        
        return files;
    }

    // Check if file is an EON file
    isEONFile(filename) {
        const ext = path.extname(filename).toLowerCase();
        return ext === '.eon' || ext === '.eont' || filename.includes('eon');
    }

    // Clean individual EON file
    async cleanEONFile(filePath, outputDir, options) {
        try {
            console.log(`🧹 Cleaning: ${path.basename(filePath)}`);
            
            // Read original file
            const originalContent = await fs.readFile(filePath, 'utf8');
            
            // Detect if file is a blackhole (has generation artifacts)
            const isBlackhole = this.detectBlackhole(originalContent);
            
            if (isBlackhole) {
                console.log(`🕳️ Blackhole detected: ${path.basename(filePath)}`);
                this.blackholeFiles.push(filePath);
            }

            // Clean the content
            let cleanedContent = originalContent;
            
            if (options.removeHeaders) {
                cleanedContent = this.removeGenerationHeaders(cleanedContent);
            }
            
            if (options.removeMetadata) {
                cleanedContent = this.removeGenerationMetadata(cleanedContent);
            }
            
            if (options.removeComments) {
                cleanedContent = this.removeGenerationComments(cleanedContent);
            }

            // Validate cleaned content
            if (options.validateOutput) {
                const isValid = await this.validateEONContent(cleanedContent);
                if (!isValid) {
                    console.warn(`⚠️ Validation failed for: ${path.basename(filePath)}`);
                }
            }

            // Create output path
            const relativePath = path.relative(process.cwd(), filePath);
            const outputPath = path.join(outputDir, relativePath);
            
            // Ensure output directory exists
            await this.ensureDirectory(path.dirname(outputPath));

            if (!options.dryRun) {
                // Backup original if requested
                if (options.backupOriginal) {
                    const backupPath = outputPath + '.backup';
                    await fs.writeFile(backupPath, originalContent);
                }

                // Write cleaned file
                await fs.writeFile(outputPath, cleanedContent);
                
                this.cleanedFiles.push({
                    original: filePath,
                    cleaned: outputPath,
                    size: cleanedContent.length,
                    artifactsRemoved: this.countArtifactsRemoved(originalContent, cleanedContent)
                });
            }

            console.log(`✅ Cleaned: ${path.basename(filePath)}`);

        } catch (error) {
            console.error(`❌ Failed to clean ${filePath}: ${error.message}`);
        }
    }

    // Detect if file is a blackhole (has generation artifacts)
    detectBlackhole(content) {
        const blackholeIndicators = [
            'Generated by API bypass system',
            'Generated by EON IDE system',
            'Generated by API bypass system',
            'Generated:',
            'Total lines:',
            '// EON IDE -',
            '// Generated by',
            '// Description:',
            '// Generated:',
            '// Total lines:',
            'femto_charge(',
            '@emit_full_engine()',
            '@generate_quantum_pipeline()',
            'meta-gen.eon',
            'self-optimising logic',
            'femtosecond-billing'
        ];

        return blackholeIndicators.some(indicator => 
            content.includes(indicator)
        );
    }

    // Remove generation headers
    removeGenerationHeaders(content) {
        const lines = content.split('\n');
        const cleanedLines = [];
        let skipHeader = false;
        
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            
            // Skip generation headers
            if (line.includes('// EON IDE -') || 
                line.includes('// Generated by') ||
                line.includes('// Description:') ||
                line.includes('// Generated:') ||
                line.includes('// Total lines:')) {
                skipHeader = true;
                this.artifactsRemoved.push(`Header: ${line.trim()}`);
                continue;
            }
            
            // Stop skipping after first non-header line
            if (skipHeader && line.trim() !== '' && !line.startsWith('//')) {
                skipHeader = false;
            }
            
            if (!skipHeader) {
                cleanedLines.push(line);
            }
        }
        
        return cleanedLines.join('\n');
    }

    // Remove generation metadata
    removeGenerationMetadata(content) {
        let cleaned = content;
        
        // Remove generation artifacts
        const artifacts = [
            /\/\/ Generated by API bypass system[\s\S]*?\n/g,
            /\/\/ Generated by EON IDE system[\s\S]*?\n/g,
            /\/\/ Description: [^\n]*\n/g,
            /\/\/ Generated: [^\n]*\n/g,
            /\/\/ Total lines: [^\n]*\n/g,
            /femto_charge\([^)]*\);/g,
            /@emit_full_engine\(\)/g,
            /@generate_quantum_pipeline\(\)/g,
            /@generate_ebpf_probes\(\)/g,
            /@generate_helm_chart\(\)/g,
            /@generate_ci_workflow\(\)/g,
            /@generate_stripe_meter\(\)/g,
            /@generate_dashboard_react\(\)/g,
            /@generate_cosign_attestation\(\)/g,
            /@generate_femtosecond_counter\(\)/g,
            /self-optimising logic/g,
            /femtosecond-billing micro-instructions/g
        ];
        
        artifacts.forEach(pattern => {
            const matches = cleaned.match(pattern);
            if (matches) {
                matches.forEach(match => {
                    this.artifactsRemoved.push(`Metadata: ${match.trim()}`);
                });
                cleaned = cleaned.replace(pattern, '');
            }
        });
        
        return cleaned;
    }

    // Remove generation comments
    removeGenerationComments(content) {
        const lines = content.split('\n');
        const cleanedLines = [];
        
        for (const line of lines) {
            // Keep non-generation comments
            if (line.trim().startsWith('//') && 
                !line.includes('Generated') &&
                !line.includes('Description:') &&
                !line.includes('Total lines:')) {
                cleanedLines.push(line);
            } else if (!line.trim().startsWith('//')) {
                cleanedLines.push(line);
            } else {
                this.artifactsRemoved.push(`Comment: ${line.trim()}`);
            }
        }
        
        return cleanedLines.join('\n');
    }

    // Validate EON content
    async validateEONContent(content) {
        try {
            // Basic EON validation - check if it's valid JSON-like structure
            const trimmed = content.trim();
            
            // Check for basic EON structure
            if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
                // Try to parse as JSON to validate structure
                JSON.parse(trimmed);
                return true;
            }
            
            if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
                JSON.parse(trimmed);
                return true;
            }
            
            // Check for EON-specific syntax
            if (trimmed.includes('def ') || trimmed.includes('model ') || trimmed.includes('func ')) {
                return true; // EON language syntax
            }
            
            return false;
            
        } catch (error) {
            return false;
        }
    }

    // Count artifacts removed
    countArtifactsRemoved(original, cleaned) {
        const originalLines = original.split('\n').length;
        const cleanedLines = cleaned.split('\n').length;
        return originalLines - cleanedLines;
    }

    // Ensure directory exists
    async ensureDirectory(dirPath) {
        try {
            await fs.mkdir(dirPath, { recursive: true });
        } catch (error) {
            // Directory might already exist
        }
    }

    // Generate cleanup report
    async generateCleanupReport(outputDir) {
        const report = {
            timestamp: new Date().toISOString(),
            version: this.version,
            summary: {
                filesProcessed: this.cleanedFiles.length,
                artifactsRemoved: this.artifactsRemoved.length,
                blackholesFixed: this.blackholeFiles.length
            },
            cleanedFiles: this.cleanedFiles,
            artifactsRemoved: this.artifactsRemoved,
            blackholeFiles: this.blackholeFiles
        };

        const reportPath = path.join(outputDir, 'eon-cleanup-report.json');
        await fs.writeFile(reportPath, JSON.stringify(report, null, 2));
        
        console.log(`📊 Cleanup report saved to: ${reportPath}`);
    }
}

// CLI Interface
class EONCleanerCLI {
    constructor() {
        this.cleaner = new EONArtifactCleaner();
    }

    async run(args) {
        try {
            const command = this.parseArgs(args);
            await this.executeCommand(command);
        } catch (error) {
            console.error("❌ CLI Error:", error.message);
            process.exit(1);
        }
    }

    parseArgs(args) {
        const command = {
            action: 'help',
            input: null,
            output: null,
            options: {}
        };

        for (let i = 0; i < args.length; i++) {
            const arg = args[i];
            
            switch (arg) {
                case 'clean':
                case 'c':
                    command.action = 'clean';
                    command.input = args[++i];
                    command.output = args[++i] || './cleaned-eon-files';
                    break;
                case '--remove-headers':
                    command.options.removeHeaders = true;
                    break;
                case '--remove-metadata':
                    command.options.removeMetadata = true;
                    break;
                case '--remove-comments':
                    command.options.removeComments = true;
                    break;
                case '--no-validate':
                    command.options.validateOutput = false;
                    break;
                case '--no-backup':
                    command.options.backupOriginal = false;
                    break;
                case '--dry-run':
                    command.options.dryRun = true;
                    break;
                case 'help':
                case 'h':
                case '--help':
                    command.action = 'help';
                    break;
                case 'version':
                case '--version':
                    command.action = 'version';
                    break;
            }
        }

        return command;
    }

    async executeCommand(command) {
        switch (command.action) {
            case 'clean':
                await this.cleanCommand(command);
                break;
            case 'version':
                this.versionCommand();
                break;
            case 'help':
            default:
                this.helpCommand();
                break;
        }
    }

    async cleanCommand(command) {
        if (!command.input) {
            throw new Error("Input path required for clean command");
        }

        console.log(`🧹 Cleaning EON files from: ${command.input}`);
        console.log(`📁 Output directory: ${command.output}`);
        
        await this.cleaner.cleanEONFiles(command.input, command.output, command.options);
    }

    versionCommand() {
        console.log(this.cleaner.version);
        console.log("EON = Efficient Object Notation");
        console.log("✅ No missing 'e' - No blackholing!");
    }

    helpCommand() {
        console.log(`
🧹 EON Artifact Cleaner - Fixing Blackhole Files

USAGE:
    eon-cleaner <command> [options] [arguments]

COMMANDS:
    clean, c <input> [output]     Clean EON files and remove artifacts
    help, h                       Show this help message
    version                       Show version information

OPTIONS:
    --remove-headers              Remove generation headers (default: true)
    --remove-metadata             Remove generation metadata (default: true)
    --remove-comments             Remove generation comments (default: false)
    --no-validate                 Skip output validation (default: false)
    --no-backup                   Don't backup original files (default: false)
    --dry-run                     Show what would be done without making changes

EXAMPLES:
    eon-cleaner clean ./generated-eon-files ./cleaned-files
    eon-cleaner clean ./eon-ide-complete ./clean-eon --remove-comments
    eon-cleaner clean ./blackhole-files ./fixed-files --dry-run

FEATURES:
    ✅ Fixes blackhole EON files
    ✅ Removes generation artifacts
    ✅ Validates cleaned output
    ✅ Creates backup copies
    ✅ Generates cleanup reports
    ✅ No missing 'e' - No blackholing!

VERSION: ${this.cleaner.version}
        `);
    }
}

// Main execution
async function main() {
    const cli = new EONCleanerCLI();
    const args = process.argv.slice(2);
    await cli.run(args);
}

// Run if called directly
if (require.main === module) {
    main().catch(console.error);
}

module.exports = { EONArtifactCleaner, EONCleanerCLI };
