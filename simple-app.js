const express = require('express');
const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        message: 'RawrZ Security Platform is running!',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Main endpoint
app.get('/', (req, res) => {
    res.json({
        name: 'RawrZ Security Platform',
        version: '2.0.0',
        status: 'active',
        endpoints: {
            health: '/api/health',
            api: '/api/*'
        }
    });
});

// Simple API endpoint
app.get('/api/test', (req, res) => {
    res.json({ 
        message: 'API is working!',
        timestamp: new Date().toISOString()
    });
});

app.listen(port, '0.0.0.0', () => {
    console.log(`RawrZ Security Platform running on port ${port}`);
    console.log(`Health check: http://localhost:${port}/api/health`);
});
