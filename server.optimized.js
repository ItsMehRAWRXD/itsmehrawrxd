const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const winston = require('winston');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

// Configure logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});

const app = express();
const port = parseInt(process.env.PORT || '3000', 10);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// Performance middleware
app.use(compression());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // limit each IP to 1000 requests per windowMs
  message: 'Too many requests from this IP',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Basic middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path}`, {
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    timestamp: new Date().toISOString()
  });
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    version: process.version
  });
});

// Basic API endpoints
app.get('/', (req, res) => {
  res.json({
    message: 'RawrZ Security Platform - Optimized Version',
    version: '2.0.0',
    status: 'running',
    endpoints: {
      health: '/health',
      api: '/api',
      docs: '/docs'
    }
  });
});

app.get('/api', (req, res) => {
  res.json({
    message: 'API is running',
    version: '2.0.0',
    available_endpoints: [
      'GET /',
      'GET /health',
      'GET /api',
      'POST /api/test',
      'GET /api/status'
    ]
  });
});

app.post('/api/test', (req, res) => {
  const { data } = req.body;
  res.json({
    message: 'Test endpoint successful',
    received: data || 'No data provided',
    timestamp: new Date().toISOString(),
    processing_time: Date.now() - req.start || 0
  });
});

app.get('/api/status', (req, res) => {
  res.json({
    server: {
      status: 'running',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      cpu: process.cpuUsage(),
      env: process.env.NODE_ENV || 'development'
    },
    platform: {
      name: 'DigitalOcean',
      node_version: process.version,
      platform: process.platform,
      arch: process.arch
    }
  });
});

// Static file serving (if needed)
app.use('/static', express.static(path.join(__dirname, 'public')));

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip
  });

  res.status(err.status || 500).json({
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong',
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: `Route ${req.originalUrl} not found`,
    timestamp: new Date().toISOString()
  });
});

// Graceful shutdown handling
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => {
    logger.info('Process terminated');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, shutting down gracefully');
  server.close(() => {
    logger.info('Process terminated');
    process.exit(0);
  });
});

// Memory monitoring
setInterval(() => {
  const memUsage = process.memoryUsage();
  if (memUsage.heapUsed > 400 * 1024 * 1024) { // 400MB threshold
    logger.warn('High memory usage detected', {
      heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`,
      heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)}MB`,
      external: `${Math.round(memUsage.external / 1024 / 1024)}MB`
    });
  }
}, 30000); // Check every 30 seconds

// Start server
const server = app.listen(port, '0.0.0.0', () => {
  logger.info(`🚀 RawrZ Security Platform started successfully`, {
    port: port,
    environment: process.env.NODE_ENV || 'development',
    node_version: process.version,
    memory_limit: process.env.NODE_OPTIONS
  });
});

// Handle server errors
server.on('error', (error) => {
  logger.error('Server error:', error);
  process.exit(1);
});

module.exports = app;