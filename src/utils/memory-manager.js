// RawrZ Memory Manager - Advanced memory management and optimization
const EventEmitter = require('events');
const { logger } = require('./logger');

class MemoryManager extends EventEmitter {
    constructor() {
        super();
        this.collections = new Map();
        this.memoryStats = {
            totalCollections: 0,
            totalMemoryUsage: 0,
            activeCollections: 0,
            garbageCollections: 0
        };
        this.maxMemoryUsage = 1024 * 1024 * 1024; // 1GB default
        this.cleanupInterval = null;
        this.initialized = false;
    }

    async initialize(config = {}) {
        if (this.initialized) {
            return true;
        }

        try {
            logger.info('Initializing Memory Manager...');
            
            this.maxMemoryUsage = config.maxMemoryUsage || this.maxMemoryUsage;
            this.cleanupInterval = config.cleanupInterval || 30000; // 30 seconds
            
            // Start cleanup interval
            this.startCleanupInterval();
            
            this.initialized = true;
            logger.info('Memory Manager initialized successfully');
            this.emit('initialized');
            
            return true;
        } catch (error) {
            logger.error('Failed to initialize Memory Manager:', error);
            throw error;
        }
    }

    createManagedCollection(name, type = 'Map', maxSize = 1000) {
        if (this.collections.has(name)) {
            return this.collections.get(name);
        }

        let collection;
        switch (type.toLowerCase()) {
            case 'map':
                collection = new Map();
                break;
            case 'set':
                collection = new Set();
                break;
            case 'array':
                collection = [];
                break;
            case 'object':
                collection = {};
                break;
            default:
                collection = new Map();
        }

        // Add management properties
        collection._managed = true;
        collection._name = name;
        collection._type = type;
        collection._maxSize = maxSize;
        collection._created = Date.now();
        collection._lastAccessed = Date.now();
        collection._accessCount = 0;

        this.collections.set(name, collection);
        this.memoryStats.totalCollections++;
        this.memoryStats.activeCollections++;

        logger.debug(`Created managed collection: ${name} (${type})`);
        return collection;
    }

    getCollection(name) {
        const collection = this.collections.get(name);
        if (collection && collection._managed) {
            collection._lastAccessed = Date.now();
            collection._accessCount++;
        }
        return collection;
    }

    deleteCollection(name) {
        if (this.collections.has(name)) {
            this.collections.delete(name);
            this.memoryStats.activeCollections--;
            logger.debug(`Deleted collection: ${name}`);
            return true;
        }
        return false;
    }

    cleanupCollections() {
        const now = Date.now();
        const maxAge = 30 * 60 * 1000; // 30 minutes
        let cleaned = 0;

        for (const [name, collection] of this.collections.entries()) {
            if (collection._managed && (now - collection._lastAccessed) > maxAge) {
                this.collections.delete(name);
                this.memoryStats.activeCollections--;
                cleaned++;
            }
        }

        if (cleaned > 0) {
            this.memoryStats.garbageCollections += cleaned;
            logger.info(`Cleaned up ${cleaned} unused collections`);
        }

        return cleaned;
    }

    startCleanupInterval() {
        if (this.cleanupInterval) {
            setInterval(() => {
                this.cleanupCollections();
            }, this.cleanupInterval);
        }
    }

    getMemoryStats() {
        return {
            ...this.memoryStats,
            collections: Array.from(this.collections.keys()),
            memoryUsage: process.memoryUsage()
        };
    }

    async getStatus() {
        return {
            name: 'MemoryManager',
            version: '1.0.0',
            status: this.initialized ? 'active' : 'inactive',
            stats: this.getMemoryStats(),
            initialized: this.initialized
        };
    }

    // Performance monitoring
    static performance = {
        monitor: (fn) => {
            const start = process.hrtime.bigint();
            const result = fn();
            const end = process.hrtime.bigint();
            const duration = Number(end - start) / 1000000; // Convert to milliseconds
            if (duration > 100) { // Log slow operations
                console.warn(`[PERF] Slow operation: ${duration.toFixed(2)}ms`);
            }
            return result;
        }
    };
}

// Global instance
let globalMemoryManager = null;

function getMemoryManager() {
    if (!globalMemoryManager) {
        globalMemoryManager = new MemoryManager();
        globalMemoryManager.initialize().catch(error => {
            logger.error('Failed to initialize global memory manager:', error);
        });
    }
    return globalMemoryManager;
}

module.exports = {
    MemoryManager,
    getMemoryManager
};
