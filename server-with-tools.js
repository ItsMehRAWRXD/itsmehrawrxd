const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const multer = require('multer');
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
require('dotenv').config();

const RawrZStandalone = require('./rawrz-standalone');
const rawrz = new RawrZStandalone();

const app = express();
const port = parseInt(process.env.PORT || '8080', 10);
const authToken = process.env.AUTH_TOKEN || '';

function requireAuth(req, res, next) {
    if (!authToken) return next();
    const h = (req.headers['authorization'] || '');
    const q = req.query.token;
    if (h.startsWith('Bearer ')) {
        const p = h.slice(7).trim();
        if (p === authToken) return next();
    }
    if (q && q === authToken) return next();
    return res.status(401).json({ error: 'Unauthorized' });
}

const upload = multer({ dest: 'uploads/' });

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '500mb' }));
app.use('/static', express.static(path.join(__dirname, 'public')));

// Health check
app.get('/health', (_req, res) => res.json({ ok: true, status: 'healthy' }));

// Main routes
app.get('/panel', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'panel.html')));
app.get('/encrypt', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'advanced-encryption.html')));
app.get('/compact', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'compact-panel.html')));
app.get('/ultra', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'ultra-compact.html')));
app.get('/executable-generator', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'executable-generator.html')));
app.get('/', (_req, res) => res.redirect('/encrypt'));

// Core API endpoints
app.post('/hash', requireAuth, async (req, res) => {
    try {
        const { input, algorithm = 'sha256', save = false, extension } = req.body || {};
        if (!input) return res.status(400).json({ error: 'input is required' });
        res.json(await rawrz.hash(input, algorithm, !!save, extension));
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Text encryption/decryption removed - file operations only

app.get('/dns', requireAuth, async (req, res) => {
    try {
        const h = req.query.hostname;
        if (!h) return res.status(400).json({ error: 'hostname required' });
        res.json(await rawrz.dnsLookup(String(h)));
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/ping', requireAuth, async (req, res) => {
    try {
        const h = req.query.host;
        if (!h) return res.status(400).json({ error: 'host required' });
        res.json(await rawrz.ping(String(h), false));
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/files', requireAuth, async (_req, res) => {
    try {
        res.json(await rawrz.listFiles());
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/upload', requireAuth, async (req, res) => {
    try {
        const { filename, base64 } = req.body || {};
        if (!filename || !base64) return res.status(400).json({ error: 'filename and base64 required' });
        res.json(await rawrz.uploadFile(filename, base64));
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.get('/download', requireAuth, async (req, res) => {
    try {
        const fn = String(req.query.filename || '');
        if (!fn) return res.status(400).json({ error: 'filename required' });
        res.download(path.join(__dirname, 'uploads', fn), fn);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// File processing
app.post('/api/encrypt-file', requireAuth, upload.single('file'), async (req, res) => {
    try {
        const { algorithm, extension, autoKey, saveKey, customKey, compress, obfuscate } = req.body || {};
        const file = req.file;
        if (!file) return res.status(400).json({ error: 'file required' });
        const result = await rawrz.encryptFile(file, algorithm, extension, autoKey, saveKey, customKey, compress, obfuscate);
        res.json({ success: true, result });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Executable generation with build tools
app.post('/api/generate-executable', requireAuth, async (req, res) => {
    try {
        const { name, extension, platform, type, functionality, code, compiler, options } = req.body || {};
        if (!name || !extension) return res.status(400).json({ error: 'name and extension required' });
        
        // Generate C++ code
        let executableCode;
        switch (functionality) {
            case 'http-bot':
                executableCode = `#include <iostream>
#include <string>
using namespace std;
int main() {
    cout << "HTTP Bot v1.0" << endl;
    cout << "Connecting to server..." << endl;
    cout << "Bot initialized successfully!" << endl;
    return 0;
}`;
                break;
            default:
                executableCode = `#include <iostream>
using namespace std;
int main() {
    cout << "Generated executable" << endl;
    return 0;
}`;
        }

        // Compile with available tools
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filename = `${name}_${timestamp}${extension}`;
        const sourceFile = path.join(__dirname, 'uploads', `${filename}.cpp`);
        const outputFile = path.join(__dirname, 'uploads', filename);
        
        // Write source file
        const fs = require('fs');
        await fs.promises.writeFile(sourceFile, executableCode);
        
        // Compile based on platform
        let compileCmd;
        if (platform === 'windows-x64') {
            compileCmd = `g++ -static -s -O2 "${sourceFile}" -o "${outputFile}"`;
        } else {
            compileCmd = `g++ -static -s -O2 "${sourceFile}" -o "${outputFile}"`;
        }
        
        console.log(`Compiling: ${compileCmd}`);
        const { stdout, stderr } = await execAsync(compileCmd);
        
        if (stderr && !stderr.includes('warning')) {
            throw new Error(`Compilation error: ${stderr}`);
        }
        
        const stats = await fs.promises.stat(outputFile);
        
        res.json({
            success: true,
            filename: filename,
            size: stats.size,
            platform: platform,
            algorithm: 'compiled'
        });
        
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.listen(port, () => console.log('[OK] RawrZ API with build tools listening on port', port));