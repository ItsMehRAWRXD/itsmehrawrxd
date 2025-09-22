const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);

class BackupSystem {
    constructor(options = {}) {
        this.backupDir = options.backupDir || path.join(__dirname, '../../backups');
        this.encryptionKey = options.encryptionKey || 'RawrZBackup2024SecretKey!@#$%^&*()';
        this.compressionLevel = options.compressionLevel || 6;
        this.retentionDays = options.retentionDays || 30;
        this.maxBackups = options.maxBackups || 50;
        
        this.ensureBackupDirectory();
    }

    ensureBackupDirectory() {
        if (!fs.existsSync(this.backupDir)) {
            fs.mkdirSync(this.backupDir, { recursive: true });
        }
    }

    async createFullBackup(options = {}) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const backupName = `full-backup-${timestamp}`;
        const backupPath = path.join(this.backupDir, backupName);

        try {
            console.log(`[BACKUP] Starting full backup: ${backupName}`);

            // Create backup directory
            fs.mkdirSync(backupPath, { recursive: true });

            // Backup application data
            await this.backupApplicationData(backupPath);

            // Backup bot data
            await this.backupBotData(backupPath);

            // Backup configuration
            await this.backupConfiguration(backupPath);

            // Backup logs
            await this.backupLogs(backupPath);

            // Backup extracted data
            await this.backupExtractedData(backupPath);

            // Create backup manifest
            await this.createBackupManifest(backupPath, 'full');

            // Compress backup
            const compressedPath = await this.compressBackup(backupPath);

            // Encrypt backup
            const encryptedPath = await this.encryptBackup(compressedPath);

            // Clean up uncompressed backup
            await this.cleanupDirectory(backupPath);

            // Update backup index
            await this.updateBackupIndex(backupName, 'full', encryptedPath);

            console.log(`[BACKUP] Full backup completed: ${encryptedPath}`);
            return {
                success: true,
                backupName: backupName,
                backupPath: encryptedPath,
                size: this.getFileSize(encryptedPath),
                timestamp: new Date().toISOString()
            };

        } catch (error) {
            console.error(`[BACKUP] Full backup failed: ${error.message}`);
            await this.cleanupDirectory(backupPath);
            return {
                success: false,
                error: error.message
            };
        }
    }

    async createIncrementalBackup(options = {}) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const backupName = `incremental-backup-${timestamp}`;
        const backupPath = path.join(this.backupDir, backupName);

        try {
            console.log(`[BACKUP] Starting incremental backup: ${backupName}`);

            // Get last backup timestamp
            const lastBackup = await this.getLastBackup();
            const lastBackupTime = lastBackup ? new Date(lastBackup.timestamp) : new Date(0);

            // Create backup directory
            fs.mkdirSync(backupPath, { recursive: true });

            // Backup only changed files since last backup
            await this.backupChangedFiles(backupPath, lastBackupTime);

            // Create backup manifest
            await this.createBackupManifest(backupPath, 'incremental', lastBackupTime);

            // Compress backup
            const compressedPath = await this.compressBackup(backupPath);

            // Encrypt backup
            const encryptedPath = await this.encryptBackup(compressedPath);

            // Clean up uncompressed backup
            await this.cleanupDirectory(backupPath);

            // Update backup index
            await this.updateBackupIndex(backupName, 'incremental', encryptedPath);

            console.log(`[BACKUP] Incremental backup completed: ${encryptedPath}`);
            return {
                success: true,
                backupName: backupName,
                backupPath: encryptedPath,
                size: this.getFileSize(encryptedPath),
                timestamp: new Date().toISOString()
            };

        } catch (error) {
            console.error(`[BACKUP] Incremental backup failed: ${error.message}`);
            await this.cleanupDirectory(backupPath);
            return {
                success: false,
                error: error.message
            };
        }
    }

    async backupApplicationData(backupPath) {
        const appDataDir = path.join(backupPath, 'application');
        fs.mkdirSync(appDataDir, { recursive: true });

        // Backup server files
        const serverFiles = [
            'server.js',
            'package.json',
            'package-lock.json'
        ];

        for (const file of serverFiles) {
            const sourcePath = path.join(__dirname, '../../', file);
            if (fs.existsSync(sourcePath)) {
                const destPath = path.join(appDataDir, file);
                fs.copyFileSync(sourcePath, destPath);
            }
        }

        // Backup source code
        const srcDir = path.join(__dirname, '../../src');
        if (fs.existsSync(srcDir)) {
            const destSrcDir = path.join(appDataDir, 'src');
            await this.copyDirectory(srcDir, destSrcDir);
        }
    }

    async backupBotData(backupPath) {
        const botDataDir = path.join(backupPath, 'bot-data');
        fs.mkdirSync(botDataDir, { recursive: true });

        // Backup bot registry
        const botRegistryPath = path.join(__dirname, '../../data/bot-registry.json');
        if (fs.existsSync(botRegistryPath)) {
            const destPath = path.join(botDataDir, 'bot-registry.json');
            fs.copyFileSync(botRegistryPath, destPath);
        }

        // Backup command queue
        const commandQueuePath = path.join(__dirname, '../../data/command-queue.json');
        if (fs.existsSync(commandQueuePath)) {
            const destPath = path.join(botDataDir, 'command-queue.json');
            fs.copyFileSync(commandQueuePath, destPath);
        }
    }

    async backupConfiguration(backupPath) {
        const configDir = path.join(backupPath, 'configuration');
        fs.mkdirSync(configDir, { recursive: true });

        // Backup configuration files
        const configFiles = [
            '.env',
            'config.json',
            'security-config.js'
        ];

        for (const file of configFiles) {
            const sourcePath = path.join(__dirname, '../../', file);
            if (fs.existsSync(sourcePath)) {
                const destPath = path.join(configDir, file);
                fs.copyFileSync(sourcePath, destPath);
            }
        }
    }

    async backupLogs(backupPath) {
        const logsDir = path.join(backupPath, 'logs');
        fs.mkdirSync(logsDir, { recursive: true });

        const sourceLogsDir = path.join(__dirname, '../../logs');
        if (fs.existsSync(sourceLogsDir)) {
            await this.copyDirectory(sourceLogsDir, logsDir);
        }
    }

    async backupExtractedData(backupPath) {
        const extractedDataDir = path.join(backupPath, 'extracted-data');
        fs.mkdirSync(extractedDataDir, { recursive: true });

        const sourceExtractedDir = path.join(__dirname, '../../extracted_data');
        if (fs.existsSync(sourceExtractedDir)) {
            await this.copyDirectory(sourceExtractedDir, extractedDataDir);
        }
    }

    async backupChangedFiles(backupPath, sinceTime) {
        const changedFilesDir = path.join(backupPath, 'changed-files');
        fs.mkdirSync(changedFilesDir, { recursive: true });

        // Get list of files modified since last backup
        const modifiedFiles = await this.getModifiedFiles(sinceTime);

        for (const file of modifiedFiles) {
            const relativePath = path.relative(path.join(__dirname, '../../'), file);
            const destPath = path.join(changedFilesDir, relativePath);
            const destDir = path.dirname(destPath);

            if (!fs.existsSync(destDir)) {
                fs.mkdirSync(destDir, { recursive: true });
            }

            fs.copyFileSync(file, destPath);
        }
    }

    async getModifiedFiles(sinceTime) {
        const modifiedFiles = [];
        const rootDir = path.join(__dirname, '../../');

        const scanDirectory = async (dir) => {
            const items = fs.readdirSync(dir);

            for (const item of items) {
                const itemPath = path.join(dir, item);
                const stat = fs.statSync(itemPath);

                if (stat.isDirectory()) {
                    // Skip certain directories
                    if (!['node_modules', '.git', 'backups'].includes(item)) {
                        await scanDirectory(itemPath);
                    }
                } else if (stat.isFile()) {
                    if (stat.mtime > sinceTime) {
                        modifiedFiles.push(itemPath);
                    }
                }
            }
        };

        await scanDirectory(rootDir);
        return modifiedFiles;
    }

    async createBackupManifest(backupPath, type, lastBackupTime = null) {
        const manifest = {
            type: type,
            timestamp: new Date().toISOString(),
            lastBackupTime: lastBackupTime ? lastBackupTime.toISOString() : null,
            files: await this.getBackupFileList(backupPath),
            checksums: await this.calculateChecksums(backupPath),
            version: '1.0.0',
            platform: process.platform,
            nodeVersion: process.version
        };

        const manifestPath = path.join(backupPath, 'backup-manifest.json');
        fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
    }

    async getBackupFileList(backupPath) {
        const files = [];
        
        const scanDirectory = (dir, relativePath = '') => {
            const items = fs.readdirSync(dir);

            for (const item of items) {
                const itemPath = path.join(dir, item);
                const relativeItemPath = path.join(relativePath, item);
                const stat = fs.statSync(itemPath);

                if (stat.isDirectory()) {
                    scanDirectory(itemPath, relativeItemPath);
                } else {
                    files.push({
                        path: relativeItemPath,
                        size: stat.size,
                        modified: stat.mtime.toISOString()
                    });
                }
            }
        };

        scanDirectory(backupPath);
        return files;
    }

    async calculateChecksums(backupPath) {
        const checksums = {};
        
        const calculateDirectoryChecksums = (dir, relativePath = '') => {
            const items = fs.readdirSync(dir);

            for (const item of items) {
                const itemPath = path.join(dir, item);
                const relativeItemPath = path.join(relativePath, item);
                const stat = fs.statSync(itemPath);

                if (stat.isDirectory()) {
                    calculateDirectoryChecksums(itemPath, relativeItemPath);
                } else {
                    const data = fs.readFileSync(itemPath);
                    const checksum = crypto.createHash('sha256').update(data).digest('hex');
                    checksums[relativeItemPath] = checksum;
                }
            }
        };

        calculateDirectoryChecksums(backupPath);
        return checksums;
    }

    async compressBackup(backupPath) {
        const compressedPath = backupPath + '.tar.gz';
        
        try {
            await execAsync(`tar -czf "${compressedPath}" -C "${path.dirname(backupPath)}" "${path.basename(backupPath)}"`);
            return compressedPath;
        } catch (error) {
            throw new Error(`Compression failed: ${error.message}`);
        }
    }

    async encryptBackup(compressedPath) {
        const encryptedPath = compressedPath + '.enc';
        
        try {
            const data = fs.readFileSync(compressedPath);
            const cipher = crypto.createCipher('aes-256-cbc', this.encryptionKey);
            let encrypted = cipher.update(data, null, 'hex');
            encrypted += cipher.final('hex');
            
            fs.writeFileSync(encryptedPath, encrypted);
            
            // Remove uncompressed file
            fs.unlinkSync(compressedPath);
            
            return encryptedPath;
        } catch (error) {
            throw new Error(`Encryption failed: ${error.message}`);
        }
    }

    async restoreBackup(backupName, restorePath = null) {
        try {
            console.log(`[BACKUP] Starting restore: ${backupName}`);

            const backupInfo = await this.getBackupInfo(backupName);
            if (!backupInfo) {
                throw new Error(`Backup not found: ${backupName}`);
            }

            const backupPath = backupInfo.path;
            const tempPath = path.join(this.backupDir, 'temp-restore');

            // Decrypt backup
            const decryptedPath = await this.decryptBackup(backupPath, tempPath);

            // Decompress backup
            const decompressedPath = await this.decompressBackup(decryptedPath);

            // Restore files
            const restoreTarget = restorePath || path.join(__dirname, '../../');
            await this.restoreFiles(decompressedPath, restoreTarget);

            // Clean up temporary files
            await this.cleanupDirectory(tempPath);

            console.log(`[BACKUP] Restore completed: ${backupName}`);
            return {
                success: true,
                backupName: backupName,
                restorePath: restoreTarget,
                timestamp: new Date().toISOString()
            };

        } catch (error) {
            console.error(`[BACKUP] Restore failed: ${error.message}`);
            return {
                success: false,
                error: error.message
            };
        }
    }

    async decryptBackup(encryptedPath, outputPath) {
        try {
            const encryptedData = fs.readFileSync(encryptedPath, 'utf8');
            const decipher = crypto.createDecipher('aes-256-cbc', this.encryptionKey);
            let decrypted = decipher.update(encryptedData, 'hex', null);
            decrypted += decipher.final();
            
            fs.writeFileSync(outputPath, decrypted);
            return outputPath;
        } catch (error) {
            throw new Error(`Decryption failed: ${error.message}`);
        }
    }

    async decompressBackup(compressedPath) {
        const outputDir = path.dirname(compressedPath);
        
        try {
            await execAsync(`tar -xzf "${compressedPath}" -C "${outputDir}"`);
            return outputDir;
        } catch (error) {
            throw new Error(`Decompression failed: ${error.message}`);
        }
    }

    async restoreFiles(sourcePath, targetPath) {
        if (!fs.existsSync(targetPath)) {
            fs.mkdirSync(targetPath, { recursive: true });
        }

        await this.copyDirectory(sourcePath, targetPath);
    }

    async copyDirectory(source, destination) {
        if (!fs.existsSync(destination)) {
            fs.mkdirSync(destination, { recursive: true });
        }

        const items = fs.readdirSync(source);

        for (const item of items) {
            const sourcePath = path.join(source, item);
            const destPath = path.join(destination, item);
            const stat = fs.statSync(sourcePath);

            if (stat.isDirectory()) {
                await this.copyDirectory(sourcePath, destPath);
            } else {
                fs.copyFileSync(sourcePath, destPath);
            }
        }
    }

    async cleanupDirectory(dirPath) {
        if (fs.existsSync(dirPath)) {
            await execAsync(`rm -rf "${dirPath}"`);
        }
    }

    async updateBackupIndex(backupName, type, backupPath) {
        const indexPath = path.join(this.backupDir, 'backup-index.json');
        let index = {};

        if (fs.existsSync(indexPath)) {
            const indexData = fs.readFileSync(indexPath, 'utf8');
            index = JSON.parse(indexData);
        }

        index[backupName] = {
            type: type,
            path: backupPath,
            timestamp: new Date().toISOString(),
            size: this.getFileSize(backupPath)
        };

        fs.writeFileSync(indexPath, JSON.stringify(index, null, 2));
    }

    async getBackupInfo(backupName) {
        const indexPath = path.join(this.backupDir, 'backup-index.json');
        
        if (fs.existsSync(indexPath)) {
            const indexData = fs.readFileSync(indexPath, 'utf8');
            const index = JSON.parse(indexData);
            return index[backupName];
        }
        
        return null;
    }

    async getLastBackup() {
        const indexPath = path.join(this.backupDir, 'backup-index.json');
        
        if (fs.existsSync(indexPath)) {
            const indexData = fs.readFileSync(indexPath, 'utf8');
            const index = JSON.parse(indexData);
            
            let lastBackup = null;
            let lastTime = new Date(0);
            
            for (const [name, info] of Object.entries(index)) {
                const backupTime = new Date(info.timestamp);
                if (backupTime > lastTime) {
                    lastTime = backupTime;
                    lastBackup = { name, ...info };
                }
            }
            
            return lastBackup;
        }
        
        return null;
    }

    async listBackups() {
        const indexPath = path.join(this.backupDir, 'backup-index.json');
        
        if (fs.existsSync(indexPath)) {
            const indexData = fs.readFileSync(indexPath, 'utf8');
            const index = JSON.parse(indexData);
            
            return Object.entries(index).map(([name, info]) => ({
                name,
                ...info
            })).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        }
        
        return [];
    }

    async cleanupOldBackups() {
        const backups = await this.listBackups();
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - this.retentionDays);

        let deletedCount = 0;
        let freedSpace = 0;

        for (const backup of backups) {
            const backupDate = new Date(backup.timestamp);
            
            if (backupDate < cutoffDate || deletedCount >= this.maxBackups) {
                try {
                    if (fs.existsSync(backup.path)) {
                        const size = this.getFileSize(backup.path);
                        fs.unlinkSync(backup.path);
                        freedSpace += size;
                    }
                    
                    // Remove from index
                    const indexPath = path.join(this.backupDir, 'backup-index.json');
                    if (fs.existsSync(indexPath)) {
                        const indexData = fs.readFileSync(indexPath, 'utf8');
                        const index = JSON.parse(indexData);
                        delete index[backup.name];
                        fs.writeFileSync(indexPath, JSON.stringify(index, null, 2));
                    }
                    
                    deletedCount++;
                } catch (error) {
                    console.error(`[BACKUP] Failed to delete backup ${backup.name}: ${error.message}`);
                }
            }
        }

        console.log(`[BACKUP] Cleanup completed: ${deletedCount} backups deleted, ${this.formatBytes(freedSpace)} freed`);
        return {
            deletedCount,
            freedSpace
        };
    }

    getFileSize(filePath) {
        if (fs.existsSync(filePath)) {
            const stat = fs.statSync(filePath);
            return stat.size;
        }
        return 0;
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
}

module.exports = BackupSystem;
