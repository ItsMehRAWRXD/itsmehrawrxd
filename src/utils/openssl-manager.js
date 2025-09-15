// RawrZ OpenSSL Runtime Manager
const { OpenSSLConfig } = require('./openssl-config');
const { logger } = require('./logger');

class OpenSSLManager {
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
    }
    constructor() {
        this.config = new OpenSSLConfig();
        this.engines = this.memoryManager.createManagedCollection('engines', 'Map', 100);
        this.isInitialized = false;
    }

    // Initialize the manager
    async initialize() {
        try {
            await this.config.loadConfig();
            this.isInitialized = true;
            logger.info('OpenSSL Manager initialized successfully');
            return true;
        } catch (error) {
            logger.error('Failed to initialize OpenSSL Manager:', error.message);
            return false;
        }
    }

    // Register an engine (AdvancedCrypto, StubGenerator, etc.)
    registerEngine(name, engine) {
        if (!this.isInitialized) {
            throw new Error('OpenSSL Manager not initialized. Call initialize() first.');
        }

        // Apply current configuration to the engine
        if (engine.setOpenSSLMode && engine.setCustomAlgorithms) {
            engine.setOpenSSLMode(this.config.isOpenSSLMode());
            engine.setCustomAlgorithms(this.config.areCustomAlgorithmsAllowed());
        }

        this.engines.set(name, engine);
        logger.info("Engine '" + name + "' registered with OpenSSL Manager");
        return true;
    }

    // Get registered engine
    getEngine(name) {
        return this.engines.get(name);
    }

    // Toggle OpenSSL mode for all registered engines
    async toggleOpenSSLMode(enabled) {
        if (!this.isInitialized) {
            throw new Error('OpenSSL Manager not initialized');
        }

        const success = await this.config.setOpenSSLMode(enabled);
        if (success) {
            // Update all registered engines
            for (const [name, engine] of this.engines) {
                if (engine.setOpenSSLMode) {
                    engine.setOpenSSLMode(enabled);
                    logger.info(`Updated engine '${name}' OpenSSL mode to enabled`);
                }
            }
        }
        return success;
    }

    // Toggle custom algorithms for all registered engines
    async toggleCustomAlgorithms(enabled) {
        if (!this.isInitialized) {
            throw new Error('OpenSSL Manager not initialized');
        }

        const success = await this.config.setCustomAlgorithms(enabled);
        if (success) {
            // Update all registered engines
            for (const [name, engine] of this.engines) {
                if (engine.setCustomAlgorithms) {
                    engine.setCustomAlgorithms(enabled);
                    logger.info(`Updated engine '${name}' custom algorithms to enabled`);
                }
            }
        }
        return success;
    }

    // Get available algorithms based on current configuration
    getAvailableAlgorithms(engineName = null) {
        if (!this.isInitialized) {
            throw new Error('OpenSSL Manager not initialized');
        }

        if (engineName) {
            const engine = this.engines.get(engineName);
            if (!engine) {
                throw new Error("Engine '" + engineName + "' not found");
            }
            return engine.getSupportedAlgorithms ? engine.getSupportedAlgorithms() : [];
        }

        // Return algorithms from all engines
        const allAlgorithms = new Set();
        for (const [name, engine] of this.engines) {
            if (engine.getSupportedAlgorithms) {
                const algorithms = engine.getSupportedAlgorithms();
                algorithms.forEach(alg => allAlgorithms.add(alg));
            }
        }
        return Array.from(allAlgorithms);
    }

    // Get OpenSSL-only algorithms
    getOpenSSLAlgorithms(engineName = null) {
        if (!this.isInitialized) {
            throw new Error('OpenSSL Manager not initialized');
        }

        if (engineName) {
            const engine = this.engines.get(engineName);
            if (!engine) {
                throw new Error("Engine '" + engineName + "' not found");
            }
            return engine.getOpenSSLAlgorithms ? engine.getOpenSSLAlgorithms() : [];
        }

        const allAlgorithms = new Set();
        for (const [name, engine] of this.engines) {
            if (engine.getOpenSSLAlgorithms) {
                const algorithms = engine.getOpenSSLAlgorithms();
                algorithms.forEach(alg => allAlgorithms.add(alg));
            }
        }
        return Array.from(allAlgorithms);
    }

    // Get custom-only algorithms
    getCustomAlgorithms(engineName = null) {
        if (!this.isInitialized) {
            throw new Error('OpenSSL Manager not initialized');
        }

        if (engineName) {
            const engine = this.engines.get(engineName);
            if (!engine) {
                throw new Error("Engine '" + engineName + "' not found");
            }
            return engine.getCustomAlgorithms ? engine.getCustomAlgorithms() : [];
        }

        const allAlgorithms = new Set();
        for (const [name, engine] of this.engines) {
            if (engine.getCustomAlgorithms) {
                const algorithms = engine.getCustomAlgorithms();
                algorithms.forEach(alg => allAlgorithms.add(alg));
            }
        }
        return Array.from(allAlgorithms);
    }

    // Resolve algorithm based on current configuration
    resolveAlgorithm(algorithm, engineName = null) {
        if (!this.isInitialized) {
            throw new Error('OpenSSL Manager not initialized');
        }

        if (engineName) {
            const engine = this.engines.get(engineName);
            if (!engine) {
                throw new Error("Engine '" + engineName + "' not found");
            }
            return engine.resolveAlgorithm ? engine.resolveAlgorithm(algorithm) : algorithm;
        }

        // Use configuration-based resolution
        if (this.config.isOpenSSLMode() && !this.config.areCustomAlgorithmsAllowed()) {
            const alternative = this.config.getOpenSSLAlternative(algorithm);
            if (alternative !== algorithm && this.config.showWarnings) {
                logger.warn("Algorithm ${algorithm} not available in OpenSSL mode, using " + alternative + " instead");
            }
            return alternative;
        }

        return algorithm;
    }

    // Get configuration summary
    getConfigSummary() {
        if (!this.isInitialized) {
            return { error: 'Manager not initialized' };
        }

        const summary = this.config.getConfigSummary();
        summary.registeredEngines = Array.from(this.engines.keys());
        summary.availableAlgorithms = this.getAvailableAlgorithms().length;
        summary.opensslAlgorithms = this.getOpenSSLAlgorithms().length;
        summary.customAlgorithms = this.getCustomAlgorithms().length;
        
        return summary;
    }

    // Update algorithm preference
    async updateAlgorithmPreference(customAlgorithm, opensslAlternative) {
        if (!this.isInitialized) {
            throw new Error('OpenSSL Manager not initialized');
        }

        const success = await this.config.setAlgorithmPreference(customAlgorithm, opensslAlternative);
        if (success) {
            // Update all registered engines if they have this method
            for (const [name, engine] of this.engines) {
                if (engine.setAlgorithmPreference) {
                    engine.setAlgorithmPreference(customAlgorithm, opensslAlternative);
                }
            }
        }
        return success;
    }

    // Reset configuration to defaults
    async resetToDefaults() {
        if (!this.isInitialized) {
            throw new Error('OpenSSL Manager not initialized');
        }

        const success = await this.config.resetToDefaults();
        if (success) {
            // Re-apply defaults to all engines
            for (const [name, engine] of this.engines) {
                if (engine.setOpenSSLMode && engine.setCustomAlgorithms) {
                    engine.setOpenSSLMode(this.config.isOpenSSLMode());
                    engine.setCustomAlgorithms(this.config.areCustomAlgorithmsAllowed());
                }
            }
        }
        return success;
    }

    // Get engine status
    getEngineStatus() {
        const status = {};
        for (const [name, engine] of this.engines) {
            status[name] = {
                registered: true,
                hasOpenSSLMethods: !!(engine.setOpenSSLMode && engine.setCustomAlgorithms),
                hasAlgorithmMethods: !!(engine.getSupportedAlgorithms && engine.getOpenSSLAlgorithms && engine.getCustomAlgorithms),
                hasResolveMethod: !!engine.resolveAlgorithm
            };
        }
        return status;
    }

    // Validate all engines
    validateEngines() {
        const validation = {
            valid: true,
            errors: [],
            warnings: []
        };

        for (const [name, engine] of this.engines) {
            if (!engine.setOpenSSLMode || !engine.setCustomAlgorithms) {
                validation.warnings.push("Engine '" + name + "' missing OpenSSL toggle methods");
            }
            
            if (!engine.getSupportedAlgorithms) {
                validation.warnings.push("Engine '" + name + "' missing getSupportedAlgorithms method");
            }
            
            if (!engine.resolveAlgorithm) {
                validation.warnings.push("Engine '" + name + "' missing resolveAlgorithm method");
            }
        }

        return validation;
    }
}

// Create singleton instance
const opensslManager = new OpenSSLManager();

module.exports = { OpenSSLManager, opensslManager };
