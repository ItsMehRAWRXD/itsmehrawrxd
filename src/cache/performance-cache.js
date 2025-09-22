const NodeCache = require('node-cache');
const Redis = require('redis');

class PerformanceCache {
    constructor(options = {}) {
        this.memoryCache = new NodeCache({
            stdTTL: options.memoryTTL || 300, // 5 minutes
            checkperiod: options.checkPeriod || 120, // 2 minutes
            useClones: false
        });

        this.redisClient = null;
        this.redisEnabled = options.redisEnabled || false;
        this.redisTTL = options.redisTTL || 3600; // 1 hour

        if (this.redisEnabled) {
            this.initRedis(options.redisConfig);
        }

        this.cacheStats = {
            hits: 0,
            misses: 0,
            sets: 0,
            deletes: 0,
            memoryUsage: 0
        };

        this.startStatsCollection();
    }

    async initRedis(config = {}) {
        try {
            this.redisClient = Redis.createClient({
                host: config.host || 'localhost',
                port: config.port || 6379,
                password: config.password,
                db: config.db || 0,
                retry_strategy: (options) => {
                    if (options.error && options.error.code === 'ECONNREFUSED') {
                        console.log('[CACHE] Redis connection refused, falling back to memory cache');
                        this.redisEnabled = false;
                        return new Error('Redis connection refused');
                    }
                    if (options.total_retry_time > 1000 * 60 * 60) {
                        console.log('[CACHE] Redis retry time exhausted, falling back to memory cache');
                        this.redisEnabled = false;
                        return new Error('Retry time exhausted');
                    }
                    if (options.attempt > 10) {
                        console.log('[CACHE] Redis max retry attempts reached, falling back to memory cache');
                        this.redisEnabled = false;
                        return undefined;
                    }
                    return Math.min(options.attempt * 100, 3000);
                }
            });

            this.redisClient.on('error', (err) => {
                console.error('[CACHE] Redis error:', err);
                this.redisEnabled = false;
            });

            this.redisClient.on('connect', () => {
                console.log('[CACHE] Redis connected successfully');
                this.redisEnabled = true;
            });

            await this.redisClient.connect();
        } catch (error) {
            console.error('[CACHE] Failed to initialize Redis:', error);
            this.redisEnabled = false;
        }
    }

    async get(key) {
        try {
            // Try memory cache first
            let value = this.memoryCache.get(key);
            if (value !== undefined) {
                this.cacheStats.hits++;
                return value;
            }

            // Try Redis cache if available
            if (this.redisEnabled && this.redisClient) {
                try {
                    const redisValue = await this.redisClient.get(key);
                    if (redisValue !== null) {
                        value = JSON.parse(redisValue);
                        // Store in memory cache for faster access
                        this.memoryCache.set(key, value);
                        this.cacheStats.hits++;
                        return value;
                    }
                } catch (redisError) {
                    console.error('[CACHE] Redis get error:', redisError);
                }
            }

            this.cacheStats.misses++;
            return null;
        } catch (error) {
            console.error('[CACHE] Get error:', error);
            this.cacheStats.misses++;
            return null;
        }
    }

    async set(key, value, ttl = null) {
        try {
            // Store in memory cache
            const memoryTTL = ttl || this.memoryCache.options.stdTTL;
            this.memoryCache.set(key, value, memoryTTL);
            this.cacheStats.sets++;

            // Store in Redis cache if available
            if (this.redisEnabled && this.redisClient) {
                try {
                    const redisTTL = ttl || this.redisTTL;
                    await this.redisClient.setEx(key, redisTTL, JSON.stringify(value));
                } catch (redisError) {
                    console.error('[CACHE] Redis set error:', redisError);
                }
            }

            return true;
        } catch (error) {
            console.error('[CACHE] Set error:', error);
            return false;
        }
    }

    async delete(key) {
        try {
            // Delete from memory cache
            this.memoryCache.del(key);
            this.cacheStats.deletes++;

            // Delete from Redis cache if available
            if (this.redisEnabled && this.redisClient) {
                try {
                    await this.redisClient.del(key);
                } catch (redisError) {
                    console.error('[CACHE] Redis delete error:', redisError);
                }
            }

            return true;
        } catch (error) {
            console.error('[CACHE] Delete error:', error);
            return false;
        }
    }

    async clear() {
        try {
            // Clear memory cache
            this.memoryCache.flushAll();

            // Clear Redis cache if available
            if (this.redisEnabled && this.redisClient) {
                try {
                    await this.redisClient.flushAll();
                } catch (redisError) {
                    console.error('[CACHE] Redis clear error:', redisError);
                }
            }

            return true;
        } catch (error) {
            console.error('[CACHE] Clear error:', error);
            return false;
        }
    }

    async getOrSet(key, fetchFunction, ttl = null) {
        try {
            // Try to get from cache first
            let value = await this.get(key);
            if (value !== null) {
                return value;
            }

            // If not in cache, fetch the data
            value = await fetchFunction();
            
            // Store in cache
            await this.set(key, value, ttl);
            
            return value;
        } catch (error) {
            console.error('[CACHE] GetOrSet error:', error);
            throw error;
        }
    }

    async mget(keys) {
        const results = {};
        
        for (const key of keys) {
            results[key] = await this.get(key);
        }
        
        return results;
    }

    async mset(keyValuePairs, ttl = null) {
        const results = {};
        
        for (const [key, value] of Object.entries(keyValuePairs)) {
            results[key] = await this.set(key, value, ttl);
        }
        
        return results;
    }

    getStats() {
        const memoryStats = this.memoryCache.getStats();
        const hitRate = this.cacheStats.hits / (this.cacheStats.hits + this.cacheStats.misses) * 100;
        
        return {
            memory: {
                keys: memoryStats.keys,
                hits: memoryStats.hits,
                misses: memoryStats.misses,
                ksize: memoryStats.ksize,
                vsize: memoryStats.vsize
            },
            redis: {
                enabled: this.redisEnabled,
                connected: this.redisEnabled && this.redisClient && this.redisClient.isOpen
            },
            performance: {
                totalHits: this.cacheStats.hits,
                totalMisses: this.cacheStats.misses,
                totalSets: this.cacheStats.sets,
                totalDeletes: this.cacheStats.deletes,
                hitRate: isNaN(hitRate) ? 0 : hitRate.toFixed(2) + '%'
            }
        };
    }

    startStatsCollection() {
        setInterval(() => {
            this.updateMemoryUsage();
        }, 60000); // Update every minute
    }

    updateMemoryUsage() {
        try {
            const memoryUsage = process.memoryUsage();
            this.cacheStats.memoryUsage = memoryUsage.heapUsed;
        } catch (error) {
            console.error('[CACHE] Memory usage update error:', error);
        }
    }

    // Cache warming functions
    async warmCache() {
        console.log('[CACHE] Starting cache warming...');
        
        try {
            // Warm bot network status
            await this.warmBotNetworkStatus();
            
            // Warm system statistics
            await this.warmSystemStats();
            
            // Warm configuration data
            await this.warmConfiguration();
            
            console.log('[CACHE] Cache warming completed');
        } catch (error) {
            console.error('[CACHE] Cache warming failed:', error);
        }
    }

    async warmBotNetworkStatus() {
        try {
            const botNetworkStatus = {
                totalBots: 0,
                onlineBots: 0,
                offlineBots: 0,
                lastUpdate: new Date().toISOString()
            };
            
            await this.set('bot_network_status', botNetworkStatus, 60); // 1 minute TTL
        } catch (error) {
            console.error('[CACHE] Failed to warm bot network status:', error);
        }
    }

    async warmSystemStats() {
        try {
            const systemStats = {
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                cpu: process.cpuUsage(),
                timestamp: new Date().toISOString()
            };
            
            await this.set('system_stats', systemStats, 30); // 30 seconds TTL
        } catch (error) {
            console.error('[CACHE] Failed to warm system stats:', error);
        }
    }

    async warmConfiguration() {
        try {
            const config = {
                version: '2.0.0',
                features: [
                    'bot_management',
                    'data_extraction',
                    'security_operations',
                    'network_operations',
                    'advanced_features',
                    'mobile_support',
                    'monitoring',
                    'backup_system'
                ],
                lastUpdate: new Date().toISOString()
            };
            
            await this.set('configuration', config, 3600); // 1 hour TTL
        } catch (error) {
            console.error('[CACHE] Failed to warm configuration:', error);
        }
    }

    // Cache invalidation patterns
    async invalidateBotData(botId) {
        const patterns = [
            `bot_${botId}_*`,
            `bot_network_status`,
            `system_stats`
        ];
        
        for (const pattern of patterns) {
            await this.invalidatePattern(pattern);
        }
    }

    async invalidateDataExtraction() {
        const patterns = [
            `extraction_*`,
            `data_*`,
            `bot_network_status`
        ];
        
        for (const pattern of patterns) {
            await this.invalidatePattern(pattern);
        }
    }

    async invalidatePattern(pattern) {
        try {
            // Invalidate memory cache
            const keys = this.memoryCache.keys();
            const matchingKeys = keys.filter(key => key.includes(pattern.replace('*', '')));
            
            for (const key of matchingKeys) {
                this.memoryCache.del(key);
            }

            // Invalidate Redis cache if available
            if (this.redisEnabled && this.redisClient) {
                try {
                    const redisKeys = await this.redisClient.keys(pattern);
                    if (redisKeys.length > 0) {
                        await this.redisClient.del(redisKeys);
                    }
                } catch (redisError) {
                    console.error('[CACHE] Redis pattern invalidation error:', redisError);
                }
            }
        } catch (error) {
            console.error('[CACHE] Pattern invalidation error:', error);
        }
    }

    // Performance monitoring
    async getPerformanceMetrics() {
        const stats = this.getStats();
        const memoryUsage = process.memoryUsage();
        
        return {
            cache: stats,
            memory: {
                used: memoryUsage.heapUsed,
                total: memoryUsage.heapTotal,
                external: memoryUsage.external,
                rss: memoryUsage.rss
            },
            performance: {
                uptime: process.uptime(),
                cpu: process.cpuUsage(),
                timestamp: new Date().toISOString()
            }
        };
    }

    // Cleanup and shutdown
    async shutdown() {
        try {
            console.log('[CACHE] Shutting down cache system...');
            
            if (this.redisEnabled && this.redisClient) {
                await this.redisClient.quit();
            }
            
            this.memoryCache.close();
            
            console.log('[CACHE] Cache system shutdown completed');
        } catch (error) {
            console.error('[CACHE] Shutdown error:', error);
        }
    }
}

module.exports = PerformanceCache;
