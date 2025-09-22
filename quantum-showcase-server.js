/**
 * Quantum-Inspired LLM Showcase Server
 * Demonstrates quantum-inspired AI capabilities with real-time streaming
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs').promises;
const { spawn } = require('child_process');
const WebSocket = require('ws');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static('public'));

// Quantum-inspired functionality endpoints
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'quantum-showcase.html'));
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        success: true,
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        version: '2.0.0',
        service: 'Quantum-Inspired LLM Showcase',
        features: [
            'quantum-inspired-attention',
            'quantum-sampling',
            'real-time-streaming',
            'websocket-support',
            'multi-client-handling'
        ]
    });
});

// Get quantum model metrics
app.get('/api/quantum/metrics', async (req, res) => {
    try {
        const metrics = {
            quantum_dimension: 8,
            num_quantum_layers: 6,
            quantum_entanglement_ratio: 0.0625,
            quantum_state_coherence: 0.85,
            quantum_measurement_entropy: 2.1,
            model_status: 'loaded',
            vocabulary_size: 1000,
            max_sequence_length: 256,
            timestamp: new Date().toISOString()
        };

        res.json({
            success: true,
            data: metrics
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Generate text with quantum-inspired sampling
app.post('/api/quantum/generate', async (req, res) => {
    try {
        const { prompt, max_length = 100, temperature = 1.0 } = req.body;

        if (!prompt) {
            return res.status(400).json({
                success: false,
                error: 'Prompt is required'
            });
        }

        // For demo purposes, return a simulated quantum-inspired response
        const quantumResponse = await generateQuantumInspiredText(prompt, max_length, temperature);

        res.json({
            success: true,
            data: {
                prompt,
                generated_text: quantumResponse,
                max_length,
                temperature,
                quantum_enhanced: true,
                processing_time: Math.random() * 1000 + 500
            },
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Stream generation endpoint
app.post('/api/quantum/stream', async (req, res) => {
    try {
        const { prompt, max_length = 100, temperature = 1.0 } = req.body;

        if (!prompt) {
            return res.status(400).json({
                success: false,
                error: 'Prompt is required'
            });
        }

        // Set headers for streaming
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Transfer-Encoding', 'chunked');

        // Stream quantum-inspired text generation
        await streamQuantumText(res, prompt, max_length, temperature);

        res.end();
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// WebSocket endpoint for real-time streaming
const wss = new WebSocket.Server({ port: 3001 });

wss.on('connection', (ws) => {
    console.log('WebSocket client connected');

    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);
            const { prompt, max_length = 100, temperature = 1.0, request_id } = data;

            if (prompt) {
                // Send streaming response
                await streamQuantumTextWebSocket(ws, prompt, max_length, temperature, request_id);
            }
        } catch (error) {
            ws.send(JSON.stringify({
                error: error.message,
                request_id: data.request_id || null
            }));
        }
    });

    ws.on('close', () => {
        console.log('WebSocket client disconnected');
    });
});

// Quantum-inspired text generation (simulated)
async function generateQuantumInspiredText(prompt, maxLength, temperature) {
    // Simulate quantum-inspired processing
    await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 200));

    // Quantum-inspired response patterns
    const quantumResponses = [
        "The quantum state evolves through superposition, creating infinite possibilities in the computational space. " +
        "Each measurement collapses the wave function, revealing a unique path through the probabilistic landscape.",

        "In the quantum realm, entanglement connects distant particles instantaneously, defying classical notions of locality. " +
        "This interconnectedness forms the foundation of quantum computing's exponential power.",

        "Hadamard gates create superposition, while CNOT gates establish entanglement between qubits. " +
        "The phase information flows through quantum circuits, carrying the computational state forward.",

        "Quantum algorithms leverage interference patterns to solve problems exponentially faster than classical approaches. " +
        "The wave nature of quantum information enables parallel computation across multiple states simultaneously.",

        "Measurement collapses the quantum state, extracting classical information from the probabilistic superposition. " +
        "This fundamental operation bridges the quantum and classical worlds, enabling computation."
    ];

    // Select response based on prompt content
    let responseIndex = 0;
    if (prompt.toLowerCase().includes('entanglement')) responseIndex = 1;
    else if (prompt.toLowerCase().includes('hadamard')) responseIndex = 2;
    else if (prompt.toLowerCase().includes('algorithm')) responseIndex = 3;
    else if (prompt.toLowerCase().includes('measurement')) responseIndex = 4;

    let response = quantumResponses[responseIndex];

    // Apply temperature-based variation
    if (temperature > 1.2) {
        response += " The quantum field resonates with enhanced probability distributions, creating novel computational pathways.";
    } else if (temperature < 0.8) {
        response += " The quantum state maintains coherence through carefully controlled interactions.";
    }

    return response;
}

// Stream text generation
async function streamQuantumText(res, prompt, maxLength, temperature) {
    const fullText = await generateQuantumInspiredText(prompt, maxLength, temperature);
    const words = fullText.split(' ');

    for (let i = 0; i < words.length; i++) {
        const word = words[i];
        res.write(word + ' ');

        // Simulate quantum processing delay
        const delay = 50 + Math.random() * 100;
        await new Promise(resolve => setTimeout(resolve, delay));
    }
}

// WebSocket streaming
async function streamQuantumTextWebSocket(ws, prompt, maxLength, temperature, requestId) {
    const fullText = await generateQuantumInspiredText(prompt, maxLength, temperature);
    const words = fullText.split(' ');

    for (let i = 0; i < words.length; i++) {
        const word = words[i];

        ws.send(JSON.stringify({
            token: word + ' ',
            request_id: requestId,
            is_final: false,
            timestamp: new Date().toISOString()
        }));

        // Simulate quantum processing delay
        const delay = 50 + Math.random() * 100;
        await new Promise(resolve => setTimeout(resolve, delay));
    }

    // Send final message
    ws.send(JSON.stringify({
        token: '',
        request_id: requestId,
        is_final: true,
        timestamp: new Date().toISOString()
    }));
}

// Quantum circuit visualization endpoint
app.get('/api/quantum/circuit', async (req, res) => {
    try {
        const circuit = {
            name: "Quantum Hello World Circuit",
            qubits: 2,
            gates: [
                { type: "H", qubit: 0, name: "Hadamard" },
                { type: "H", qubit: 1, name: "Hadamard" },
                { type: "CNOT", qubit: 0, target: 1, name: "Entanglement" },
                { type: "X", qubit: 0, name: "Pauli-X" },
                { type: "Y", qubit: 1, name: "Pauli-Y" },
                { type: "Z", qubit: 0, name: "Pauli-Z" },
                { type: "MEASURE", qubit: 0, name: "Measurement" },
                { type: "MEASURE", qubit: 1, name: "Measurement" }
            ],
            description: "Demonstrates basic quantum operations: superposition, entanglement, and measurement"
        };

        res.json({
            success: true,
            data: circuit
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Get system statistics
app.get('/api/system/stats', async (req, res) => {
    try {
        const stats = {
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            cpu: process.cpuUsage(),
            quantum_sessions: Math.floor(Math.random() * 100) + 10,
            total_requests: Math.floor(Math.random() * 1000) + 100,
            active_connections: wss.clients.size,
            timestamp: new Date().toISOString()
        };

        res.json({
            success: true,
            data: stats
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Start server
async function startServer() {
    try {
        // Ensure public directory exists
        await fs.mkdir('public', { recursive: true });

        // Create basic HTML interface if it doesn't exist
        const htmlPath = path.join(__dirname, 'public', 'quantum-showcase.html');
        try {
            await fs.access(htmlPath);
        } catch {
            const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quantum-Inspired LLM Showcase</title>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            min-height: 100vh;
        }
        .quantum-box {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
            backdrop-filter: blur(10px);
        }
        .quantum-button {
            background: #4CAF50;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            margin: 10px;
        }
        .quantum-input {
            width: 100%;
            padding: 10px;
            border: none;
            border-radius: 5px;
            margin: 10px 0;
            font-size: 14px;
        }
        .quantum-output {
            background: rgba(0, 0, 0, 0.3);
            padding: 15px;
            border-radius: 5px;
            min-height: 100px;
            margin: 10px 0;
        }
        .status {
            position: fixed;
            top: 10px;
            right: 10px;
            background: rgba(0, 0, 0, 0.7);
            padding: 10px;
            border-radius: 5px;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="status">
        🟢 Quantum System Online
    </div>

    <h1>🚀 Quantum-Inspired LLM Showcase</h1>

    <div class="quantum-box">
        <h2>Quantum Text Generation</h2>
        <p>Enter a prompt to generate text using quantum-inspired algorithms:</p>

        <input type="text" id="prompt" class="quantum-input"
               placeholder="Enter quantum prompt (e.g., 'quantum entanglement')" value="quantum computing">

        <div>
            <button class="quantum-button" onclick="generateText()">Generate</button>
            <button class="quantum-button" onclick="streamText()">Stream</button>
        </div>

        <div class="quantum-output" id="output">
            Welcome to the Quantum-Inspired LLM Showcase! Enter a prompt above to experience quantum-enhanced text generation.
        </div>
    </div>

    <div class="quantum-box">
        <h2>Quantum Circuit Visualization</h2>
        <button class="quantum-button" onclick="showCircuit()">View Quantum Circuit</button>
        <div class="quantum-output" id="circuit-output"></div>
    </div>

    <script>
        async function generateText() {
            const prompt = document.getElementById('prompt').value;
            const response = await fetch('/api/quantum/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ prompt })
            });
            const result = await response.json();

            if (result.success) {
                document.getElementById('output').innerHTML = \`<strong>Generated:</strong> \${result.data.generated_text}\`;
            } else {
                document.getElementById('output').innerHTML = \`<strong>Error:</strong> \${result.error}\`;
            }
        }

        async function streamText() {
            const prompt = document.getElementById('prompt').value;
            const output = document.getElementById('output');
            output.innerHTML = '<strong>Streaming...</strong><br>';

            const response = await fetch('/api/quantum/stream', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ prompt })
            });

            const reader = response.body.getReader();
            const decoder = new TextDecoder();

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                const text = decoder.decode(value);
                output.innerHTML += text;
                output.scrollTop = output.scrollHeight;
            }
        }

        async function showCircuit() {
            const response = await fetch('/api/quantum/circuit');
            const result = await response.json();

            if (result.success) {
                const circuit = result.data;
                document.getElementById('circuit-output').innerHTML = \`
                    <strong>Circuit:</strong> \${circuit.name}<br>
                    <strong>Qubits:</strong> \${circuit.qubits}<br>
                    <strong>Gates:</strong> \${circuit.gates.length}<br>
                    <strong>Description:</strong> \${circuit.description}
                \`;
            }
        }

        // Auto-generate on page load
        window.onload = () => {
            setTimeout(generateText, 1000);
        };
    </script>
</body>
</html>
            `;
            await fs.writeFile(htmlPath, html);
        }

        app.listen(PORT, () => {
            console.log(`🚀 Quantum-Inspired LLM Showcase Server`);
            console.log(`🌐 Server running on port ${PORT}`);
            console.log(`📊 Health check: http://localhost:${PORT}/api/health`);
            console.log(`🧬 Quantum API: http://localhost:${PORT}/api/quantum/generate`);
            console.log(`⚡ WebSocket: ws://localhost:3001`);
            console.log(`🎯 Main interface: http://localhost:${PORT}`);
        });

    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer().catch(console.error);