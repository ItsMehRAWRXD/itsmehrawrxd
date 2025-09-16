const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');

class PayloadManager {
    constructor() {
        this.payloadsDir = path.join(__dirname, '..', '..', 'data', 'payloads');
        this.uploadsDir = path.join(this.payloadsDir, 'uploads');
        this.databaseFile = path.join(this.payloadsDir, 'payload-database.json');
        this.configFile = path.join(this.payloadsDir, 'payload-config.json');
        this.payloads = new Map();
        this.categories = new Map();
        this.versions = new Map();
        this.initialized = false;
        
        // Configure multer for file uploads
        this.upload = multer({
            dest: this.uploadsDir,
            limits: {
                fileSize: 50 * 1024 * 1024, // 50MB limit
                files: 10 // Max 10 files per upload
            },
            fileFilter: (req, file, cb) => {
                // Allow common executable and script files
                const allowedTypes = [
                    'application/x-executable',
                    'application/x-msdownload',
                    'application/octet-stream',
                    'text/plain',
                    'application/x-python-code',
                    'application/javascript',
                    'application/x-sh',
                    'application/x-bat'
                ];
                
                const allowedExtensions = [
                    '.exe', '.dll', '.so', '.dylib',
                    '.py', '.js', '.ps1', '.bat', '.sh',
                    '.cpp', '.c', '.cs', '.java',
                    '.txt', '.json', '.xml', '.yaml'
                ];
                
                const fileExt = path.extname(file.originalname).toLowerCase();
                
                if (allowedTypes.includes(file.mimetype) || allowedExtensions.includes(fileExt)) {
                    cb(null, true);
                } else {
                    cb(new Error(`File type ${file.mimetype} or extension ${fileExt} not allowed`), false);
                }
            }
        });
    }

    async initialize() {
        try {
            // Ensure directories exist
            await fs.mkdir(this.payloadsDir, { recursive: true });
            await fs.mkdir(this.uploadsDir, { recursive: true });
            
            // Load existing data
            await this.loadDatabase();
            await this.loadPayloads();
            await this.loadCategories();
            await this.loadVersions();
            
            this.initialized = true;
            console.log('[OK] Payload Manager initialized with database support');
            return { success: true, message: 'Payload Manager initialized with database support' };
        } catch (error) {
            console.error('[ERROR] Failed to initialize Payload Manager:', error);
            return { success: false, error: error.message };
        }
    }

    async loadPayloads() {
        try {
            const configData = await fs.readFile(this.configFile, 'utf8');
            const config = JSON.parse(configData);
            
            this.payloads.clear();
            for (const [id, payload] of Object.entries(config.payloads || {})) {
                this.payloads.set(id, payload);
            }
            
            console.log(`[OK] Loaded ${this.payloads.size} payloads`);
        } catch (error) {
            if (error.code !== 'ENOENT') {
                console.error('[ERROR] Failed to load payloads:', error);
            }
            // Initialize with default payloads if file doesn't exist
            await this.initializeDefaultPayloads();
        }
    }

    async savePayloads() {
        try {
            const config = {
                payloads: Object.fromEntries(this.payloads),
                lastUpdated: new Date().toISOString()
            };
            
            await fs.writeFile(this.configFile, JSON.stringify(config, null, 2));
            console.log(`[OK] Saved ${this.payloads.size} payloads`);
        } catch (error) {
            console.error('[ERROR] Failed to save payloads:', error);
            throw error;
        }
    }

    async loadDatabase() {
        try {
            const data = await fs.readFile(this.databaseFile, 'utf8');
            const database = JSON.parse(data);
            
            // Load database entries
            if (database.payloads) {
                for (const [id, payload] of Object.entries(database.payloads)) {
                    this.payloads.set(id, payload);
                }
            }
            
            console.log(`[OK] Loaded database with ${this.payloads.size} entries`);
        } catch (error) {
            if (error.code !== 'ENOENT') {
                console.error('[ERROR] Failed to load database:', error);
            }
            // Initialize empty database if file doesn't exist
            await this.initializeDatabase();
        }
    }

    async saveDatabase() {
        try {
            const database = {
                payloads: Object.fromEntries(this.payloads),
                categories: Object.fromEntries(this.categories),
                versions: Object.fromEntries(this.versions),
                lastUpdated: new Date().toISOString(),
                metadata: {
                    totalPayloads: this.payloads.size,
                    totalCategories: this.categories.size,
                    totalVersions: this.versions.size
                }
            };
            
            await fs.writeFile(this.databaseFile, JSON.stringify(database, null, 2));
            console.log(`[OK] Saved database with ${this.payloads.size} payloads`);
        } catch (error) {
            console.error('[ERROR] Failed to save database:', error);
            throw error;
        }
    }

    async initializeDatabase() {
        const database = {
            payloads: {},
            categories: {},
            versions: {},
            lastUpdated: new Date().toISOString(),
            metadata: {
                totalPayloads: 0,
                totalCategories: 0,
                totalVersions: 0
            }
        };
        
        await fs.writeFile(this.databaseFile, JSON.stringify(database, null, 2));
        console.log('[OK] Initialized empty database');
    }

    async loadCategories() {
        try {
            const data = await fs.readFile(this.databaseFile, 'utf8');
            const database = JSON.parse(data);
            
            if (database.categories) {
                for (const [id, category] of Object.entries(database.categories)) {
                    this.categories.set(id, category);
                }
            }
            
            // Initialize default categories if none exist
            if (this.categories.size === 0) {
                await this.initializeDefaultCategories();
            }
        } catch (error) {
            console.error('[ERROR] Failed to load categories:', error);
        }
    }

    async loadVersions() {
        try {
            const data = await fs.readFile(this.databaseFile, 'utf8');
            const database = JSON.parse(data);
            
            if (database.versions) {
                for (const [id, version] of Object.entries(database.versions)) {
                    this.versions.set(id, version);
                }
            }
        } catch (error) {
            console.error('[ERROR] Failed to load versions:', error);
        }
    }

    async initializeDefaultCategories() {
        const defaultCategories = {
            'malware': {
                id: 'malware',
                name: 'Malware',
                description: 'Malicious software payloads',
                color: '#ff4444',
                icon: '🦠',
                createdAt: new Date().toISOString()
            },
            'backdoor': {
                id: 'backdoor',
                name: 'Backdoor',
                description: 'Remote access and control payloads',
                color: '#ff8800',
                icon: '🚪',
                createdAt: new Date().toISOString()
            },
            'stealer': {
                id: 'stealer',
                name: 'Stealer',
                description: 'Data exfiltration payloads',
                color: '#ffaa00',
                icon: '💰',
                createdAt: new Date().toISOString()
            },
            'crypto': {
                id: 'crypto',
                name: 'Cryptographic',
                description: 'Encryption and decryption tools',
                color: '#00aa00',
                icon: '🔐',
                createdAt: new Date().toISOString()
            },
            'network': {
                id: 'network',
                name: 'Network',
                description: 'Network analysis and tools',
                color: '#0088ff',
                icon: '🌐',
                createdAt: new Date().toISOString()
            },
            'utility': {
                id: 'utility',
                name: 'Utility',
                description: 'General utility payloads',
                color: '#888888',
                icon: '🔧',
                createdAt: new Date().toISOString()
            }
        };

        for (const [id, category] of Object.entries(defaultCategories)) {
            this.categories.set(id, category);
        }

        await this.saveDatabase();
        console.log('[OK] Initialized default categories');
    }

    async initializeDefaultPayloads() {
        const defaultPayloads = {
            'beaconism-default': {
                id: 'beaconism-default',
                name: 'Default Beaconism Payload',
                type: 'beaconism',
                description: 'Standard beaconism DLL sideloading payload',
                config: {
                    target: 'notepad.exe',
                    architecture: 'x64',
                    stealth: true,
                    persistence: false,
                    encryption: 'aes-256'
                },
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            },
            'red-shell-default': {
                id: 'red-shell-default',
                name: 'Default Red Shell',
                type: 'red-shell',
                description: 'Standard red shell payload',
                config: {
                    shellType: 'cmd',
                    encoding: 'base64',
                    compression: true,
                    encryption: 'xor'
                },
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            },
            'hot-patch-default': {
                id: 'hot-patch-default',
                name: 'Default Hot Patch',
                type: 'hot-patch',
                description: 'Standard hot patch payload',
                config: {
                    target: 'notepad.exe',
                    patchType: 'memory',
                    stealth: true,
                    rollback: true
                },
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            },
            'stub-generator-default': {
                id: 'stub-generator-default',
                name: 'Default Stub Generator',
                type: 'stub-generator',
                description: 'Standard stub generator payload',
                config: {
                    language: 'csharp',
                    architecture: 'x64',
                    encryption: 'aes-256',
                    packing: 'upx',
                    fud: true
                },
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            }
        };

        for (const [id, payload] of Object.entries(defaultPayloads)) {
            this.payloads.set(id, payload);
        }

        await this.savePayloads();
        console.log('[OK] Initialized default payloads');
    }

    generateId() {
        return uuidv4();
    }

    // File upload and management methods
    async uploadPayloadFiles(files, payloadId) {
        try {
            const uploadedFiles = [];
            
            for (const file of files) {
                const fileId = this.generateId();
                const fileExtension = path.extname(file.originalname);
                const fileName = `${fileId}${fileExtension}`;
                const filePath = path.join(this.uploadsDir, fileName);
                
                // Move file from temp location to permanent location
                await fs.rename(file.path, filePath);
                
                const fileInfo = {
                    id: fileId,
                    originalName: file.originalname,
                    fileName: fileName,
                    filePath: filePath,
                    size: file.size,
                    mimetype: file.mimetype,
                    uploadedAt: new Date().toISOString(),
                    payloadId: payloadId
                };
                
                uploadedFiles.push(fileInfo);
            }
            
            return { success: true, files: uploadedFiles };
        } catch (error) {
            console.error('[ERROR] Failed to upload payload files:', error);
            return { success: false, error: error.message };
        }
    }

    async createPayload(payloadData) {
        try {
            const id = this.generateId();
            const payload = {
                id,
                name: payloadData.name || `Payload ${id.substring(0, 8)}`,
                type: payloadData.type || 'generic',
                category: payloadData.category || 'utility',
                description: payloadData.description || '',
                config: payloadData.config || {},
                tags: payloadData.tags || [],
                version: payloadData.version || '1.0.0',
                author: payloadData.author || 'Unknown',
                files: [],
                metadata: {
                    size: 0,
                    fileCount: 0,
                    checksum: null
                },
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            };

            this.payloads.set(id, payload);
            await this.saveDatabase();

            return { success: true, payload };
        } catch (error) {
            console.error('[ERROR] Failed to create payload:', error);
            return { success: false, error: error.message };
        }
    }

    async createPayloadWithFiles(payloadData, files = []) {
        try {
            const id = this.generateId();
            const payload = {
                id,
                name: payloadData.name || `Payload ${id.substring(0, 8)}`,
                type: payloadData.type || 'custom',
                category: payloadData.category || 'utility',
                description: payloadData.description || '',
                config: payloadData.config || {},
                tags: payloadData.tags || [],
                version: payloadData.version || '1.0.0',
                author: payloadData.author || 'Unknown',
                files: [],
                metadata: {
                    size: 0,
                    fileCount: 0,
                    checksum: null
                },
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            };

            // Upload files if provided
            if (files && files.length > 0) {
                const uploadResult = await this.uploadPayloadFiles(files, id);
                if (uploadResult.success) {
                    payload.files = uploadResult.files;
                    payload.metadata.fileCount = uploadResult.files.length;
                    payload.metadata.size = uploadResult.files.reduce((total, file) => total + file.size, 0);
                }
            }

            this.payloads.set(id, payload);
            await this.saveDatabase();

            return { success: true, payload };
        } catch (error) {
            console.error('[ERROR] Failed to create payload with files:', error);
            return { success: false, error: error.message };
        }
    }

    async updatePayload(id, updates) {
        try {
            if (!this.payloads.has(id)) {
                return { success: false, error: 'Payload not found' };
            }

            const payload = this.payloads.get(id);
            const updatedPayload = {
                ...payload,
                ...updates,
                id, // Ensure ID doesn't change
                updatedAt: new Date().toISOString()
            };

            this.payloads.set(id, updatedPayload);
            await this.savePayloads();

            return { success: true, payload: updatedPayload };
        } catch (error) {
            console.error('[ERROR] Failed to update payload:', error);
            return { success: false, error: error.message };
        }
    }

    async deletePayload(id) {
        try {
            if (!this.payloads.has(id)) {
                return { success: false, error: 'Payload not found' };
            }

            this.payloads.delete(id);
            await this.savePayloads();

            return { success: true, message: 'Payload deleted' };
        } catch (error) {
            console.error('[ERROR] Failed to delete payload:', error);
            return { success: false, error: error.message };
        }
    }

    getPayload(id) {
        return this.payloads.get(id) || null;
    }

    getAllPayloads() {
        return Array.from(this.payloads.values());
    }

    getPayloadsByType(type) {
        return Array.from(this.payloads.values()).filter(p => p.type === type);
    }

    async duplicatePayload(id, newName) {
        try {
            const originalPayload = this.payloads.get(id);
            if (!originalPayload) {
                return { success: false, error: 'Original payload not found' };
            }

            const newId = this.generateId();
            const duplicatedPayload = {
                ...originalPayload,
                id: newId,
                name: newName || `${originalPayload.name} (Copy)`,
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            };

            this.payloads.set(newId, duplicatedPayload);
            await this.savePayloads();

            return { success: true, payload: duplicatedPayload };
        } catch (error) {
            console.error('[ERROR] Failed to duplicate payload:', error);
            return { success: false, error: error.message };
        }
    }

    async exportPayloads(format = 'json') {
        try {
            const payloads = this.getAllPayloads();
            
            switch (format.toLowerCase()) {
                case 'json':
                    return { success: true, data: JSON.stringify(payloads, null, 2), format: 'json' };
                case 'csv':
                    const csv = this.payloadsToCSV(payloads);
                    return { success: true, data: csv, format: 'csv' };
                default:
                    return { success: false, error: 'Unsupported export format' };
            }
        } catch (error) {
            console.error('[ERROR] Failed to export payloads:', error);
            return { success: false, error: error.message };
        }
    }

    payloadsToCSV(payloads) {
        if (payloads.length === 0) return '';
        
        const headers = ['ID', 'Name', 'Type', 'Description', 'Created', 'Updated'];
        const rows = payloads.map(p => [
            p.id,
            p.name,
            p.type,
            p.description,
            p.createdAt,
            p.updatedAt
        ]);

        return [headers, ...rows].map(row => row.join(',')).join('\n');
    }

    // Category management
    async createCategory(categoryData) {
        try {
            const id = this.generateId();
            const category = {
                id,
                name: categoryData.name,
                description: categoryData.description || '',
                color: categoryData.color || '#888888',
                icon: categoryData.icon || '📁',
                createdAt: new Date().toISOString()
            };

            this.categories.set(id, category);
            await this.saveDatabase();

            return { success: true, category };
        } catch (error) {
            console.error('[ERROR] Failed to create category:', error);
            return { success: false, error: error.message };
        }
    }

    async getCategories() {
        return Array.from(this.categories.values());
    }

    async searchPayloads(query, filters = {}) {
        try {
            let results = Array.from(this.payloads.values());

            // Text search
            if (query) {
                const searchTerm = query.toLowerCase();
                results = results.filter(payload => 
                    payload.name.toLowerCase().includes(searchTerm) ||
                    payload.description.toLowerCase().includes(searchTerm) ||
                    payload.tags.some(tag => tag.toLowerCase().includes(searchTerm)) ||
                    payload.author.toLowerCase().includes(searchTerm)
                );
            }

            // Category filter
            if (filters.category) {
                results = results.filter(payload => payload.category === filters.category);
            }

            // Type filter
            if (filters.type) {
                results = results.filter(payload => payload.type === filters.type);
            }

            return { success: true, results, total: results.length };
        } catch (error) {
            console.error('[ERROR] Failed to search payloads:', error);
            return { success: false, error: error.message };
        }
    }

    async getDatabaseStats() {
        try {
            const stats = {
                totalPayloads: this.payloads.size,
                totalCategories: this.categories.size,
                totalFiles: Array.from(this.payloads.values())
                    .reduce((total, payload) => total + (payload.files ? payload.files.length : 0), 0),
                totalSize: Array.from(this.payloads.values())
                    .reduce((total, payload) => total + (payload.metadata ? payload.metadata.size : 0), 0),
                payloadsByCategory: {},
                payloadsByType: {}
            };

            // Count by category
            for (const payload of this.payloads.values()) {
                const category = payload.category || 'uncategorized';
                stats.payloadsByCategory[category] = (stats.payloadsByCategory[category] || 0) + 1;
            }

            // Count by type
            for (const payload of this.payloads.values()) {
                const type = payload.type || 'unknown';
                stats.payloadsByType[type] = (stats.payloadsByType[type] || 0) + 1;
            }

            return { success: true, stats };
        } catch (error) {
            console.error('[ERROR] Failed to get database stats:', error);
            return { success: false, error: error.message };
        }
    }

    getStatus() {
        return {
            status: 'active',
            initialized: this.initialized,
            payloadCount: this.payloads.size,
            categoryCount: this.categories.size,
            payloadTypes: [...new Set(Array.from(this.payloads.values()).map(p => p.type))],
            lastUpdated: this.payloads.size > 0 ? 
                Math.max(...Array.from(this.payloads.values()).map(p => new Date(p.updatedAt).getTime())) : null
        };
    }
}

module.exports = new PayloadManager();
