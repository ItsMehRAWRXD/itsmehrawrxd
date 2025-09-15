/**
 * Production Configuration for RawrZ Security Platform
 * This file contains production-ready settings and optimizations
 */

module.exports = {
    // Server Configuration
    server: {
        port: process.env.PORT || 8080,
        host: process.env.HOST || '0.0.0.0',
        environment: process.env.NODE_ENV || 'production',
        cluster: process.env.CLUSTER_MODE === 'true',
        workers: process.env.WORKERS || require('os').cpus().length
    },

    // Security Configuration
    security: {
        authToken: process.env.AUTH_TOKEN,
        corsOrigin: process.env.CORS_ORIGIN || '*',
        rateLimit: {
            windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000, // 15 minutes
            maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100
        },
        helmet: {
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'"],
                    scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
                    scriptSrcAttr: ["'unsafe-inline'"],
                    imgSrc: ["'self'", "data:", "https:"],
                    connectSrc: ["'self'"],
                    fontSrc: ["'self'"],
                    objectSrc: ["'none'"],
                    mediaSrc: ["'self'"],
                    frameSrc: ["'none'"]
                }
            }
        }
    },

    // Database Configuration
    database: {
        postgres: {
            host: process.env.POSTGRES_HOST || 'localhost',
            port: parseInt(process.env.POSTGRES_PORT) || 5432,
            database: process.env.POSTGRES_DB || 'rawrz',
            username: process.env.POSTGRES_USER || 'rawrz',
            password: process.env.POSTGRES_PASSWORD,
            ssl: process.env.POSTGRES_SSL === 'true',
            pool: {
                min: parseInt(process.env.DB_POOL_MIN) || 2,
                max: parseInt(process.env.DB_POOL_MAX) || 10,
                idle: parseInt(process.env.DB_POOL_IDLE) || 10000
            }
        }
    },

    // Redis Configuration
    redis: {
        host: process.env.REDIS_HOST || 'localhost',
        port: parseInt(process.env.REDIS_PORT) || 6379,
        password: process.env.REDIS_PASSWORD,
        db: parseInt(process.env.REDIS_DB) || 0,
        retryDelayOnFailover: 100,
        maxRetriesPerRequest: 3
    },

    // Logging Configuration
    logging: {
        level: process.env.LOG_LEVEL || 'info',
        file: process.env.LOG_FILE || '/app/logs/rawrz.log',
        maxSize: process.env.LOG_MAX_SIZE || '10m',
        maxFiles: parseInt(process.env.LOG_MAX_FILES) || 5,
        datePattern: 'YYYY-MM-DD',
        format: 'combined'
    },

    // File Upload Configuration
    upload: {
        maxFileSize: parseInt(process.env.MAX_FILE_SIZE) || 10485760, // 10MB
        uploadDir: process.env.UPLOAD_DIR || '/app/uploads',
        allowedTypes: [
            'text/plain',
            'application/json',
            'application/octet-stream',
            'application/x-executable',
            'application/x-msdownload',
            'application/x-msdos-program'
        ],
        tempDir: process.env.TEMP_DIR || '/tmp'
    },

    // Performance Configuration
    performance: {
        maxConcurrentRequests: parseInt(process.env.MAX_CONCURRENT_REQUESTS) || 100,
        requestTimeout: parseInt(process.env.REQUEST_TIMEOUT) || 30000,
        compression: {
            enabled: process.env.COMPRESSION_ENABLED !== 'false',
            level: parseInt(process.env.COMPRESSION_LEVEL) || 6,
            threshold: parseInt(process.env.COMPRESSION_THRESHOLD) || 1024
        },
        caching: {
            enabled: process.env.CACHING_ENABLED !== 'false',
            ttl: parseInt(process.env.CACHE_TTL) || 300000, // 5 minutes
            maxSize: parseInt(process.env.CACHE_MAX_SIZE) || 1000
        }
    },

    // Monitoring Configuration
    monitoring: {
        enabled: process.env.ENABLE_METRICS !== 'false',
        port: parseInt(process.env.METRICS_PORT) || 9090,
        path: process.env.METRICS_PATH || '/metrics',
        collectDefaultMetrics: true,
        prefix: 'rawrz_'
    },

    // SSL/TLS Configuration
    ssl: {
        enabled: process.env.SSL_ENABLED === 'true',
        certPath: process.env.SSL_CERT_PATH,
        keyPath: process.env.SSL_KEY_PATH,
        caPath: process.env.SSL_CA_PATH,
        passphrase: process.env.SSL_PASSPHRASE
    },

    // Engine Configuration
    engines: {
        initializationTimeout: parseInt(process.env.ENGINE_INIT_TIMEOUT) || 30000,
        maxRetries: parseInt(process.env.ENGINE_MAX_RETRIES) || 3,
        retryDelay: parseInt(process.env.ENGINE_RETRY_DELAY) || 1000,
        cacheEnabled: process.env.ENGINE_CACHE_ENABLED !== 'false',
        cacheTimeout: parseInt(process.env.ENGINE_CACHE_TIMEOUT) || 300000
    },

    // API Configuration
    api: {
        version: 'v1',
        basePath: '/api',
        timeout: parseInt(process.env.API_TIMEOUT) || 30000,
        maxBodySize: parseInt(process.env.API_MAX_BODY_SIZE) || 10485760,
        rateLimit: {
            windowMs: 900000, // 15 minutes
            maxRequests: 100
        }
    },

    // Health Check Configuration
    healthCheck: {
        enabled: true,
        interval: parseInt(process.env.HEALTH_CHECK_INTERVAL) || 30000,
        timeout: parseInt(process.env.HEALTH_CHECK_TIMEOUT) || 5000,
        endpoints: [
            '/api/status',
            '/health'
        ]
    },

    // Backup Configuration
    backup: {
        enabled: process.env.BACKUP_ENABLED === 'true',
        schedule: process.env.BACKUP_SCHEDULE || '0 2 * * *', // Daily at 2 AM
        retention: parseInt(process.env.BACKUP_RETENTION) || 7, // 7 days
        location: process.env.BACKUP_LOCATION || '/app/backups'
    },

    // Development Configuration
    development: {
        debug: process.env.DEBUG === 'true',
        verboseLogging: process.env.VERBOSE_LOGGING === 'true',
        hotReload: process.env.HOT_RELOAD === 'true',
        mockData: process.env.MOCK_DATA === 'true'
    }
};
