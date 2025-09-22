#!/usr/bin/env node

const express = require('express');
const WebSocket = require('ws');
const fs = require('fs').promises;
const path = require('path');
const { spawn } = require('child_process');
const axios = require('axios');

const app = express();
const port = 3001;

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// WebSocket server for real-time IDE communication
const wss = new WebSocket.Server({ port: 3002 });

// AI Models configuration
const AI_MODELS = {
    'gpt-5': {
        name: 'gpt-5:latest',
        provider: 'openai',
        capabilities: ['code_generation', 'code_review', 'debugging', 'refactoring', 'documentation'],
        maxTokens: 100000,
        temperature: 0.1
    },
    'claude-3.5': {
        name: 'claude-3.5-sonnet:latest',
        provider: 'claude',
        capabilities: ['code_analysis', 'architecture_design', 'testing', 'optimization'],
        maxTokens: 200000,
        temperature: 0.1
    },
    'gemini-2.0': {
        name: 'gemini-2.0:latest',
        provider: 'gemini',
        capabilities: ['multimodal_coding', 'visual_analysis', 'code_explanation'],
        maxTokens: 100000,
        temperature: 0.1
    },
    'copilot': {
        name: 'copilot-pro:latest',
        provider: 'copilot',
        capabilities: ['autocomplete', 'code_suggestions', 'pattern_recognition'],
        maxTokens: 50000,
        temperature: 0.0
    }
};

// Active coding sessions
const activeSessions = new Map();

class CodingSession {
    constructor(sessionId, model, workspacePath) {
        this.sessionId = sessionId;
        this.model = model;
        this.workspacePath = workspacePath;
        this.context = {
            files: new Map(),
            history: [],
            currentFile: null,
            cursorPosition: { line: 0, column: 0 }
        };
        this.isActive = true;
    }

    async updateFile(filePath, content) {
        this.context.files.set(filePath, {
            content,
            lastModified: Date.now(),
            language: this.detectLanguage(filePath)
        });
    }

    detectLanguage(filePath) {
        const ext = path.extname(filePath).toLowerCase();
        const languageMap = {
            '.js': 'javascript',
            '.ts': 'typescript',
            '.py': 'python',
            '.java': 'java',
            '.cpp': 'cpp',
            '.c': 'c',
            '.cs': 'csharp',
            '.php': 'php',
            '.rb': 'ruby',
            '.go': 'go',
            '.rs': 'rust',
            '.swift': 'swift',
            '.kt': 'kotlin',
            '.scala': 'scala',
            '.html': 'html',
            '.css': 'css',
            '.scss': 'scss',
            '.json': 'json',
            '.xml': 'xml',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.md': 'markdown'
        };
        return languageMap[ext] || 'text';
    }

    async generateCode(prompt, options = {}) {
        const modelConfig = AI_MODELS[this.model];
        if (!modelConfig) {
            throw new Error(`Model ${this.model} not found`);
        }

        // Build context from current files
        const context = this.buildContext();
        
        const systemPrompt = `You are an expert coding assistant running locally through Ollama. You have access to the following workspace context:

${context}

Provide high-quality, production-ready code. Focus on:
- Clean, readable code
- Proper error handling
- Performance optimization
- Security best practices
- Following language conventions

Current task: ${prompt}`;

        try {
            const response = await axios.post('http://localhost:11434/api/generate', {
                model: modelConfig.name,
                prompt: systemPrompt,
                stream: false,
                options: {
                    temperature: options.temperature || modelConfig.temperature,
                    max_tokens: options.maxTokens || modelConfig.maxTokens
                }
            });

            return response.data.response;
        } catch (error) {
            console.error('Error generating code:', error);
            throw new Error('Failed to generate code');
        }
    }

    buildContext() {
        let context = `Workspace: ${this.workspacePath}\n\n`;
        
        if (this.context.currentFile) {
            context += `Current File: ${this.context.currentFile}\n`;
            const file = this.context.files.get(this.context.currentFile);
            if (file) {
                context += `Content:\n\`\`\`${file.language}\n${file.content}\n\`\`\`\n\n`;
            }
        }

        context += 'Available Files:\n';
        for (const [filePath, file] of this.context.files) {
            context += `- ${filePath} (${file.language})\n`;
        }

        return context;
    }
}

// WebSocket connection handling
wss.on('connection', (ws) => {
    console.log('🔌 IDE client connected');
    
    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);
            await handleIDECommand(ws, data);
        } catch (error) {
            console.error('Error handling IDE command:', error);
            ws.send(JSON.stringify({
                type: 'error',
                message: error.message
            }));
        }
    });

    ws.on('close', () => {
        console.log('🔌 IDE client disconnected');
    });
});

async function handleIDECommand(ws, data) {
    const { type, sessionId, ...params } = data;

    switch (type) {
        case 'create_session':
            await handleCreateSession(ws, params);
            break;
        case 'update_file':
            await handleUpdateFile(ws, sessionId, params);
            break;
        case 'generate_code':
            await handleGenerateCode(ws, sessionId, params);
            break;
        case 'code_review':
            await handleCodeReview(ws, sessionId, params);
            break;
        case 'debug_code':
            await handleDebugCode(ws, sessionId, params);
            break;
        case 'refactor_code':
            await handleRefactorCode(ws, sessionId, params);
            break;
        case 'explain_code':
            await handleExplainCode(ws, sessionId, params);
            break;
        case 'generate_tests':
            await handleGenerateTests(ws, sessionId, params);
            break;
        case 'optimize_code':
            await handleOptimizeCode(ws, sessionId, params);
            break;
        default:
            ws.send(JSON.stringify({
                type: 'error',
                message: `Unknown command: ${type}`
            }));
    }
}

async function handleCreateSession(ws, params) {
    const { model, workspacePath } = params;
    const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    const session = new CodingSession(sessionId, model, workspacePath);
    activeSessions.set(sessionId, session);
    
    ws.send(JSON.stringify({
        type: 'session_created',
        sessionId,
        model,
        capabilities: AI_MODELS[model]?.capabilities || []
    }));
    
    console.log(`📝 Created coding session: ${sessionId} with model: ${model}`);
}

async function handleUpdateFile(ws, sessionId, params) {
    const session = activeSessions.get(sessionId);
    if (!session) {
        ws.send(JSON.stringify({
            type: 'error',
            message: 'Session not found'
        }));
        return;
    }

    const { filePath, content, cursorPosition } = params;
    await session.updateFile(filePath, content);
    
    if (cursorPosition) {
        session.context.cursorPosition = cursorPosition;
    }
    
    session.context.currentFile = filePath;
    
    ws.send(JSON.stringify({
        type: 'file_updated',
        filePath,
        timestamp: Date.now()
    }));
}

async function handleGenerateCode(ws, sessionId, params) {
    const session = activeSessions.get(sessionId);
    if (!session) {
        ws.send(JSON.stringify({
            type: 'error',
            message: 'Session not found'
        }));
        return;
    }

    const { prompt, options = {} } = params;
    
    try {
        ws.send(JSON.stringify({
            type: 'generation_started',
            prompt
        }));

        const generatedCode = await session.generateCode(prompt, options);
        
        ws.send(JSON.stringify({
            type: 'code_generated',
            code: generatedCode,
            timestamp: Date.now()
        }));
    } catch (error) {
        ws.send(JSON.stringify({
            type: 'error',
            message: error.message
        }));
    }
}

async function handleCodeReview(ws, sessionId, params) {
    const session = activeSessions.get(sessionId);
    if (!session) {
        ws.send(JSON.stringify({
            type: 'error',
            message: 'Session not found'
        }));
        return;
    }

    const { filePath, code } = params;
    
    try {
        const reviewPrompt = `Please review the following code and provide detailed feedback on:
- Code quality and readability
- Potential bugs or issues
- Performance optimizations
- Security concerns
- Best practices adherence
- Suggestions for improvement

Code to review:
\`\`\`${session.detectLanguage(filePath)}
${code}
\`\`\``;

        const review = await session.generateCode(reviewPrompt, { temperature: 0.1 });
        
        ws.send(JSON.stringify({
            type: 'code_review_complete',
            review,
            filePath,
            timestamp: Date.now()
        }));
    } catch (error) {
        ws.send(JSON.stringify({
            type: 'error',
            message: error.message
        }));
    }
}

async function handleDebugCode(ws, sessionId, params) {
    const session = activeSessions.get(sessionId);
    if (!session) {
        ws.send(JSON.stringify({
            type: 'error',
            message: 'Session not found'
        }));
        return;
    }

    const { code, error, language } = params;
    
    try {
        const debugPrompt = `Please help debug the following code. The error is: ${error}

Code:
\`\`\`${language}
${code}
\`\`\`

Please provide:
1. Analysis of the error
2. Root cause explanation
3. Fixed code
4. Prevention strategies`;

        const debugResult = await session.generateCode(debugPrompt, { temperature: 0.1 });
        
        ws.send(JSON.stringify({
            type: 'debug_complete',
            result: debugResult,
            timestamp: Date.now()
        }));
    } catch (error) {
        ws.send(JSON.stringify({
            type: 'error',
            message: error.message
        }));
    }
}

async function handleRefactorCode(ws, sessionId, params) {
    const session = activeSessions.get(sessionId);
    if (!session) {
        ws.send(JSON.stringify({
            type: 'error',
            message: 'Session not found'
        }));
        return;
    }

    const { code, language, refactorType } = params;
    
    try {
        const refactorPrompt = `Please refactor the following code to improve ${refactorType}:

\`\`\`${language}
${code}
\`\`\`

Provide:
1. Refactored code
2. Explanation of changes
3. Benefits of the refactoring`;

        const refactoredCode = await session.generateCode(refactorPrompt, { temperature: 0.1 });
        
        ws.send(JSON.stringify({
            type: 'refactor_complete',
            refactoredCode,
            refactorType,
            timestamp: Date.now()
        }));
    } catch (error) {
        ws.send(JSON.stringify({
            type: 'error',
            message: error.message
        }));
    }
}

async function handleExplainCode(ws, sessionId, params) {
    const session = activeSessions.get(sessionId);
    if (!session) {
        ws.send(JSON.stringify({
            type: 'error',
            message: 'Session not found'
        }));
        return;
    }

    const { code, language } = params;
    
    try {
        const explainPrompt = `Please explain the following code in detail:

\`\`\`${language}
${code}
\`\`\`

Provide:
1. High-level overview
2. Line-by-line explanation
3. Key concepts and patterns
4. Potential use cases`;

        const explanation = await session.generateCode(explainPrompt, { temperature: 0.2 });
        
        ws.send(JSON.stringify({
            type: 'explanation_complete',
            explanation,
            timestamp: Date.now()
        }));
    } catch (error) {
        ws.send(JSON.stringify({
            type: 'error',
            message: error.message
        }));
    }
}

async function handleGenerateTests(ws, sessionId, params) {
    const session = activeSessions.get(sessionId);
    if (!session) {
        ws.send(JSON.stringify({
            type: 'error',
            message: 'Session not found'
        }));
        return;
    }

    const { code, language, testFramework } = params;
    
    try {
        const testPrompt = `Please generate comprehensive tests for the following code using ${testFramework || 'the standard testing framework for ' + language}:

\`\`\`${language}
${code}
\`\`\`

Provide:
1. Unit tests
2. Integration tests (if applicable)
3. Edge case tests
4. Test setup and teardown`;

        const tests = await session.generateCode(testPrompt, { temperature: 0.1 });
        
        ws.send(JSON.stringify({
            type: 'tests_generated',
            tests,
            testFramework,
            timestamp: Date.now()
        }));
    } catch (error) {
        ws.send(JSON.stringify({
            type: 'error',
            message: error.message
        }));
    }
}

async function handleOptimizeCode(ws, sessionId, params) {
    const session = activeSessions.get(sessionId);
    if (!session) {
        ws.send(JSON.stringify({
            type: 'error',
            message: 'Session not found'
        }));
        return;
    }

    const { code, language, optimizationType } = params;
    
    try {
        const optimizePrompt = `Please optimize the following code for ${optimizationType}:

\`\`\`${language}
${code}
\`\`\`

Provide:
1. Optimized code
2. Performance improvements
3. Memory usage analysis
4. Benchmarking suggestions`;

        const optimizedCode = await session.generateCode(optimizePrompt, { temperature: 0.1 });
        
        ws.send(JSON.stringify({
            type: 'optimization_complete',
            optimizedCode,
            optimizationType,
            timestamp: Date.now()
        }));
    } catch (error) {
        ws.send(JSON.stringify({
            type: 'error',
            message: error.message
        }));
    }
}

// REST API endpoints
app.get('/api/models', (req, res) => {
    res.json({
        models: Object.keys(AI_MODELS).map(key => ({
            id: key,
            name: AI_MODELS[key].name,
            capabilities: AI_MODELS[key].capabilities,
            maxTokens: AI_MODELS[key].maxTokens
        }))
    });
});

app.get('/api/sessions', (req, res) => {
    const sessions = Array.from(activeSessions.entries()).map(([id, session]) => ({
        id,
        model: session.model,
        workspacePath: session.workspacePath,
        isActive: session.isActive,
        fileCount: session.context.files.size
    }));
    
    res.json({ sessions });
});

app.delete('/api/sessions/:sessionId', (req, res) => {
    const { sessionId } = req.params;
    if (activeSessions.has(sessionId)) {
        activeSessions.delete(sessionId);
        res.json({ success: true });
    } else {
        res.status(404).json({ error: 'Session not found' });
    }
});

app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: 'IDE Backend Server',
        activeSessions: activeSessions.size,
        models: Object.keys(AI_MODELS).length,
        uptime: process.uptime()
    });
});

// Start server
app.listen(port, () => {
    console.log('🚀 IDE Backend Server Started');
    console.log(`📍 REST API: http://localhost:${port}`);
    console.log(`🔌 WebSocket: ws://localhost:3002`);
    console.log('🤖 Connected to airtight AI system');
    console.log('💻 Ready for IDE integration');
});

module.exports = app;
