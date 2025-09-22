const express = require('express');
const cors = require('cors');
const compression = require('compression');
const helmet = require('helmet');

const app = express();
const PORT = process.env.PORT || 8080;

// Memory leak prevention configurations
const MAX_REQUEST_SIZE = '1mb';
const MAX_ARRAY_SIZE = 1000;
const SESSION_CLEANUP_INTERVAL = 60000; // 1 minute
const MAX_SESSIONS = 100;

// In-memory storage with limits
const store = {
  sessions: new Map(),
  requestCount: 0,
  startTime: Date.now()
};

// Middleware with security and compression
app.use(helmet({
  contentSecurityPolicy: false // Allow for simpler deployment
}));
app.use(compression());
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  maxAge: 86400
}));
app.use(express.json({ limit: MAX_REQUEST_SIZE }));
app.use(express.urlencoded({ extended: true, limit: MAX_REQUEST_SIZE }));

// Request timeout middleware
app.use((req, res, next) => {
  req.setTimeout(30000); // 30 second timeout
  res.setTimeout(30000);
  next();
});

// Memory leak prevention: Clean up old sessions
setInterval(() => {
  const now = Date.now();
  const timeout = 30 * 60 * 1000; // 30 minutes
  
  for (const [id, session] of store.sessions.entries()) {
    if (now - session.lastAccess > timeout) {
      store.sessions.delete(id);
    }
  }
  
  // Force garbage collection if available
  if (global.gc) {
    global.gc();
  }
}, SESSION_CLEANUP_INTERVAL);

// Health check endpoint
app.get('/health', (req, res) => {
  const memUsage = process.memoryUsage();
  const healthStatus = {
    status: 'healthy',
    uptime: process.uptime(),
    memory: {
      used: Math.round(memUsage.heapUsed / 1024 / 1024) + ' MB',
      total: Math.round(memUsage.heapTotal / 1024 / 1024) + ' MB',
      rss: Math.round(memUsage.rss / 1024 / 1024) + ' MB'
    },
    sessions: store.sessions.size,
    requests: store.requestCount,
    timestamp: new Date().toISOString()
  };
  
  // Check if memory usage is too high
  if (memUsage.heapUsed / memUsage.heapTotal > 0.9) {
    healthStatus.status = 'degraded';
    healthStatus.warning = 'High memory usage';
  }
  
  res.status(healthStatus.status === 'healthy' ? 200 : 503).json(healthStatus);
});

// API Status endpoint
app.get('/api/status', (req, res) => {
  store.requestCount++;
  
  res.json({
    status: 'online',
    version: '2.0.0',
    uptime: Math.floor((Date.now() - store.startTime) / 1000),
    requests: store.requestCount,
    activeSessions: store.sessions.size,
    timestamp: new Date().toISOString()
  });
});

// Session management endpoints
app.post('/api/session', (req, res) => {
  // Prevent too many sessions
  if (store.sessions.size >= MAX_SESSIONS) {
    // Remove oldest session
    const oldestKey = store.sessions.keys().next().value;
    store.sessions.delete(oldestKey);
  }
  
  const sessionId = Math.random().toString(36).substring(2) + Date.now().toString(36);
  const session = {
    id: sessionId,
    created: Date.now(),
    lastAccess: Date.now(),
    data: {}
  };
  
  store.sessions.set(sessionId, session);
  
  res.json({
    success: true,
    sessionId,
    expiresIn: 1800 // 30 minutes
  });
});

app.get('/api/session/:id', (req, res) => {
  const session = store.sessions.get(req.params.id);
  
  if (!session) {
    return res.status(404).json({ error: 'Session not found' });
  }
  
  session.lastAccess = Date.now();
  
  res.json({
    success: true,
    session: {
      id: session.id,
      created: session.created,
      lastAccess: session.lastAccess
    }
  });
});

app.delete('/api/session/:id', (req, res) => {
  const deleted = store.sessions.delete(req.params.id);
  
  res.json({
    success: deleted,
    message: deleted ? 'Session deleted' : 'Session not found'
  });
});

// Data storage endpoint with limits
app.post('/api/data', (req, res) => {
  const { sessionId, key, value } = req.body;
  
  if (!sessionId || !key) {
    return res.status(400).json({ error: 'sessionId and key required' });
  }
  
  const session = store.sessions.get(sessionId);
  if (!session) {
    return res.status(404).json({ error: 'Session not found' });
  }
  
  // Prevent memory leaks from large data
  const dataSize = JSON.stringify(value).length;
  if (dataSize > 10000) { // 10KB limit per value
    return res.status(413).json({ error: 'Data too large' });
  }
  
  // Limit keys per session
  if (Object.keys(session.data).length >= 100) {
    return res.status(413).json({ error: 'Too many keys in session' });
  }
  
  session.data[key] = value;
  session.lastAccess = Date.now();
  
  res.json({
    success: true,
    key,
    stored: true
  });
});

app.get('/api/data/:sessionId/:key', (req, res) => {
  const session = store.sessions.get(req.params.sessionId);
  
  if (!session) {
    return res.status(404).json({ error: 'Session not found' });
  }
  
  session.lastAccess = Date.now();
  const value = session.data[req.params.key];
  
  res.json({
    success: true,
    key: req.params.key,
    value: value !== undefined ? value : null,
    found: value !== undefined
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    name: 'RawrZ API',
    version: '2.0.0',
    endpoints: [
      'GET /health',
      'GET /api/status',
      'POST /api/session',
      'GET /api/session/:id',
      'DELETE /api/session/:id',
      'POST /api/data',
      'GET /api/data/:sessionId/:key'
    ],
    documentation: 'https://api-docs.example.com'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Not found',
    path: req.path,
    method: req.method
  });
});

// Error handler with memory leak prevention
app.use((err, req, res, next) => {
  // Don't leak error details in production
  const isDev = process.env.NODE_ENV !== 'production';
  
  console.error('Error:', err.message);
  
  res.status(err.status || 500).json({ 
    error: isDev ? err.message : 'Internal server error',
    timestamp: new Date().toISOString()
  });
});

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Memory limit: ${process.env.NODE_OPTIONS || 'default'}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
});

// Graceful shutdown
const gracefulShutdown = (signal) => {
  console.log(`${signal} received, starting graceful shutdown...`);
  
  server.close(() => {
    console.log('HTTP server closed');
    
    // Clear all data to free memory
    store.sessions.clear();
    
    console.log('Cleanup completed, exiting...');
    process.exit(0);
  });
  
  // Force exit after 10 seconds
  setTimeout(() => {
    console.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught errors to prevent crashes
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  // Don't exit, try to recover
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // Don't exit, try to recover
});

module.exports = app;