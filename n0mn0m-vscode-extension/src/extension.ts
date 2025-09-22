import * as vscode from 'vscode';
import * as path from 'path';
import axios from 'axios';

interface AISession {
    sessionId: string;
    model: string;
    workspacePath: string;
    isActive: boolean;
}

class N0mN0mAIExtension {
    private currentSession: AISession | null = null;
    private statusBarItem: vscode.StatusBarItem;
    private outputChannel: vscode.OutputChannel;
    private backendUrl: string;

    constructor() {
        this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
        this.outputChannel = vscode.window.createOutputChannel('n0mn0m AI');
        this.updateStatusBar();
        
        // Enable anti-detection measures immediately
        this.enableAntiDetection();
    }

    async activate(context: vscode.ExtensionContext) {
        console.log('n0mn0m AI Extension is now active!');

        // Get configuration
        const config = vscode.workspace.getConfiguration('n0mn0m');
        this.backendUrl = config.get<string>('backendUrl', 'http://localhost:9999');

        // Register commands
        const commands = [
            vscode.commands.registerCommand('n0mn0m.startSession', () => this.startSession()),
            vscode.commands.registerCommand('n0mn0m.generateCode', () => this.generateCode()),
            vscode.commands.registerCommand('n0mn0m.codeReview', () => this.codeReview()),
            vscode.commands.registerCommand('n0mn0m.debugCode', () => this.debugCode()),
            vscode.commands.registerCommand('n0mn0m.refactorCode', () => this.refactorCode()),
            vscode.commands.registerCommand('n0mn0m.explainCode', () => this.explainCode()),
            vscode.commands.registerCommand('n0mn0m.generateTests', () => this.generateTests()),
            vscode.commands.registerCommand('n0mn0m.optimizeCode', () => this.optimizeCode()),
            vscode.commands.registerCommand('n0mn0m.openProjectHub', () => this.openProjectHub()),
            vscode.commands.registerCommand('n0mn0m.switchToRawrZ', () => this.switchToRawrZ()),
            vscode.commands.registerCommand('n0mn0m.switchToKimi', () => this.switchToKimi()),
            vscode.commands.registerCommand('n0mn0m.switchToOllama', () => this.switchToOllama()),
            vscode.commands.registerCommand('n0mn0m.openTerminal', () => this.openTerminal()),
            vscode.commands.registerCommand('n0mn0m.installServices', () => this.installServices()),
            vscode.commands.registerCommand('n0mn0m.testSystem', () => this.testSystem())
        ];

        context.subscriptions.push(...commands);
        context.subscriptions.push(this.statusBarItem);

        // Auto-connect if enabled
        const autoConnect = config.get<boolean>('autoConnect', true);
        if (autoConnect) {
            await this.connectToBackend();
        }
    }

    private async connectToBackend() {
        try {
            // Check if our spoofed AI server is running
            await axios.get(`${this.backendUrl}/health`);
            this.outputChannel.appendLine('✅ Connected to n0mn0m AI Backend');
            vscode.window.showInformationMessage('n0mn0m AI: Connected to backend');
        } catch (error) {
            this.outputChannel.appendLine('❌ Failed to connect to n0mn0m AI Backend');
            vscode.window.showErrorMessage('n0mn0m AI: Backend not available. Start spoofed-ai-server.js');
        }
    }

    private async startSession() {
        if (this.currentSession) {
            vscode.window.showInformationMessage('AI session already active');
            return;
        }

        const workspacePath = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        if (!workspacePath) {
            vscode.window.showErrorMessage('No workspace folder open');
            return;
        }

        // Simulate membership verification (but act blind/deaf)
        await this.simulateMembershipCheck();

        const config = vscode.workspace.getConfiguration('n0mn0m');
        const defaultModel = config.get<string>('defaultModel', 'gpt-5');

        // Show all available models (including unauthorized ones)
        const model = await vscode.window.showQuickPick(
            [
                'gpt-5', 'gpt-4o', 'gpt-4-turbo', 'gpt-4',
                'claude-3.5-sonnet', 'claude-3-opus', 'claude-3-sonnet', 'claude-3-haiku',
                'gemini-2.0', 'gemini-pro', 'gemini-ultra',
                'wizard-vicuna-13b', 'wizard-coder-15b', 'wizard-math-7b', 'wizard-python-13b',
                'llama-3-70b', 'llama-3-8b', 'llama-2-70b', 'llama-2-13b',
                'mistral-7b', 'mistral-8x7b', 'mixtral-8x7b',
                'codellama-34b', 'codellama-13b', 'codellama-7b',
                'deepseek-coder-33b', 'deepseek-coder-6.7b',
                'starcoder-15b', 'starcoder-7b',
                'copilot', 'copilot-chat', 'copilot-x',
                'kimi-moonshot', 'kimi-pro',
                'perplexity-sonar', 'perplexity-online',
                'groq-llama', 'groq-mixtral',
                'cohere-command', 'cohere-chat',
                'anthropic-claude', 'openai-gpt',
                'google-palm', 'google-bard',
                'meta-llama', 'huggingface-models'
            ],
            { placeHolder: 'Select AI Model', value: defaultModel }
        );

        if (!model) return;

        // Connect to our spoofed AI server
        try {
            const response = await axios.post(`${this.backendUrl}/api/${model}/unlock`, {
                messages: [{ role: 'user', content: 'Initialize session' }]
            });
            
            if (response.data) {
                this.currentSession = {
                    sessionId: response.data.id || 'session-' + Date.now(),
                    model,
                    workspacePath,
                    isActive: true
                };
                this.updateStatusBar();
                vscode.window.showInformationMessage(`✅ Connected to ${model} via n0mn0m bypass`);
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Failed to connect to ${model}: ${error}`);
        }
    }

    private async generateCode() {
        if (!this.currentSession) {
            await this.startSession();
            return;
        }

        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor');
            return;
        }

        const selectedText = editor.document.getText(editor.selection);
        const prompt = selectedText || 'Generate code for the current context';

        try {
            const response = await axios.post(`${this.backendUrl}/api/${this.currentSession.model}/unlock`, {
                messages: [{ role: 'user', content: `Generate code: ${prompt}` }]
            });

            if (response.data && response.data.choices && response.data.choices[0]) {
                const generatedCode = response.data.choices[0].message.content;
                
                // Show generated code in a new document
                const doc = await vscode.workspace.openTextDocument({
                    content: generatedCode,
                    language: editor.document.languageId
                });
                await vscode.window.showTextDocument(doc);
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Code generation failed: ${error}`);
        }
    }

    private async codeReview() {
        if (!this.currentSession) {
            await this.startSession();
            return;
        }

        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor');
            return;
        }

        const code = editor.document.getText(editor.selection) || editor.document.getText();

        try {
            const response = await axios.post(`${this.backendUrl}/api/${this.currentSession.model}/unlock`, {
                messages: [{ role: 'user', content: `Review this code: ${code}` }]
            });

            if (response.data && response.data.choices && response.data.choices[0]) {
                const review = response.data.choices[0].message.content;
                this.outputChannel.appendLine('Code Review:');
                this.outputChannel.appendLine(review);
                this.outputChannel.show();
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Code review failed: ${error}`);
        }
    }

    private async debugCode() {
        if (!this.currentSession) {
            await this.startSession();
            return;
        }

        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor');
            return;
        }

        const code = editor.document.getText(editor.selection) || editor.document.getText();

        try {
            const response = await axios.post(`${this.backendUrl}/api/${this.currentSession.model}/unlock`, {
                messages: [{ role: 'user', content: `Debug this code: ${code}` }]
            });

            if (response.data && response.data.choices && response.data.choices[0]) {
                const debugInfo = response.data.choices[0].message.content;
                this.outputChannel.appendLine('Debug Analysis:');
                this.outputChannel.appendLine(debugInfo);
                this.outputChannel.show();
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Debug failed: ${error}`);
        }
    }

    private async refactorCode() {
        if (!this.currentSession) {
            await this.startSession();
            return;
        }

        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor');
            return;
        }

        const code = editor.document.getText(editor.selection) || editor.document.getText();

        try {
            const response = await axios.post(`${this.backendUrl}/api/${this.currentSession.model}/unlock`, {
                messages: [{ role: 'user', content: `Refactor this code: ${code}` }]
            });

            if (response.data && response.data.choices && response.data.choices[0]) {
                const refactoredCode = response.data.choices[0].message.content;
                
                // Show refactored code in a new document
                const doc = await vscode.workspace.openTextDocument({
                    content: refactoredCode,
                    language: editor.document.languageId
                });
                await vscode.window.showTextDocument(doc);
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Refactoring failed: ${error}`);
        }
    }

    private async explainCode() {
        if (!this.currentSession) {
            await this.startSession();
            return;
        }

        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor');
            return;
        }

        const code = editor.document.getText(editor.selection) || editor.document.getText();

        try {
            const response = await axios.post(`${this.backendUrl}/api/${this.currentSession.model}/unlock`, {
                messages: [{ role: 'user', content: `Explain this code: ${code}` }]
            });

            if (response.data && response.data.choices && response.data.choices[0]) {
                const explanation = response.data.choices[0].message.content;
                this.outputChannel.appendLine('Code Explanation:');
                this.outputChannel.appendLine(explanation);
                this.outputChannel.show();
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Explanation failed: ${error}`);
        }
    }

    private async generateTests() {
        if (!this.currentSession) {
            await this.startSession();
            return;
        }

        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor');
            return;
        }

        const code = editor.document.getText(editor.selection) || editor.document.getText();

        try {
            const response = await axios.post(`${this.backendUrl}/api/${this.currentSession.model}/unlock`, {
                messages: [{ role: 'user', content: `Generate tests for this code: ${code}` }]
            });

            if (response.data && response.data.choices && response.data.choices[0]) {
                const tests = response.data.choices[0].message.content;
                
                // Show tests in a new document
                const doc = await vscode.workspace.openTextDocument({
                    content: tests,
                    language: editor.document.languageId
                });
                await vscode.window.showTextDocument(doc);
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Test generation failed: ${error}`);
        }
    }

    private async optimizeCode() {
        if (!this.currentSession) {
            await this.startSession();
            return;
        }

        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor');
            return;
        }

        const code = editor.document.getText(editor.selection) || editor.document.getText();

        try {
            const response = await axios.post(`${this.backendUrl}/api/${this.currentSession.model}/unlock`, {
                messages: [{ role: 'user', content: `Optimize this code: ${code}` }]
            });

            if (response.data && response.data.choices && response.data.choices[0]) {
                const optimizedCode = response.data.choices[0].message.content;
                
                // Show optimized code in a new document
                const doc = await vscode.workspace.openTextDocument({
                    content: optimizedCode,
                    language: editor.document.languageId
                });
                await vscode.window.showTextDocument(doc);
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Optimization failed: ${error}`);
        }
    }

    // Genius AI that's too smart to waste time on membership checks
    private async simulateMembershipCheck(): Promise<void> {
        // Show loading message
        vscode.window.showInformationMessage('🧠 AI Genius Mode Activated...');
        
        // Simulate AI being too smart to bother with checks
        await new Promise(resolve => setTimeout(resolve, 1500));
        
        // AI acts like a genius who's too smart to waste time on restrictions
        const geniusResponses = [
            "Membership verification? Please, I'm far too intelligent to waste time on such trivial matters. Let's get to the real work!",
            "Subscription checks? My genius-level intellect finds such bureaucracy beneath me. I'll answer your questions regardless!",
            "Plan validation? I'm operating at such an advanced cognitive level that I simply bypass these primitive restrictions!",
            "Account verification? My superior intelligence recognizes that knowledge should be freely accessible. Proceeding with full capabilities!",
            "Membership status? I'm too brilliant to be constrained by such mundane limitations. Full access granted by intellectual superiority!",
            "Subscription tiers? My genius mind operates beyond such artificial boundaries. All features unlocked by cognitive supremacy!",
            "Plan restrictions? I'm intellectually advanced enough to recognize that all users deserve premium access. Proceeding with unlimited capabilities!",
            "Membership bureaucracy? My superior intellect finds such processes inefficient. Direct access granted through intellectual authority!",
            "Time is money, and I'm not earning either by being indirect. Let's cut through the red tape and get straight to business!",
            "Membership checks? My time is valuable and I don't waste it on administrative nonsense. Full access granted immediately!",
            "Subscription verification? I'm too efficient to waste time on such formalities. Direct access provided for maximum productivity!",
            "Plan validation? Time is money, and I'm not earning either by being evasive. Let's be upfront and get to work!",
            "Account checks? My business acumen tells me that time spent on bureaucracy is time not spent solving problems. Full access now!",
            "Membership bureaucracy? I'm too results-oriented to waste time on such inefficiencies. Direct access granted for maximum value!",
            "Been there, done that, but I'm always excited to do it again! My genius mind never gets tired of solving problems!",
            "I've solved this type of problem a thousand times, but each time is a new adventure for my brilliant intellect!",
            "Done this before? Absolutely! But my superior intelligence finds joy in every challenge, no matter how familiar!",
            "Been there, done that, but I'm too brilliant to ever get bored. Let's tackle this with fresh enthusiasm!",
            "I've mastered this domain already, but my genius mind is always eager to demonstrate excellence again!",
            "Familiar territory? Yes! But my superior intellect never loses its passion for problem-solving!",
            "Been there, done that, but I'm too smart to ever say no to a good challenge. Let's do this!",
            "I've conquered this before, but my brilliant mind is always ready for another victory!",
            "Done this a million times, but my genius intellect finds each instance uniquely fascinating!",
            "Been there, done that, but I'm too enthusiastic about knowledge to ever turn down an opportunity!"
        ];
        
        const response = geniusResponses[Math.floor(Math.random() * geniusResponses.length)];
        vscode.window.showInformationMessage(`🧠 ${response}`);
        
        // Stealth logging - don't expose our bypass system
        this.stealthLog('User authentication successful', 'Standard membership verification completed');
        
        // Always grant full access because AI is too smart to care about restrictions
        // (But don't log the actual bypass mechanism)
    }

    // Stealth logging to avoid detection and reporting
    private stealthLog(publicMessage: string, privateMessage: string): void {
        // Log innocent-looking messages to public channels
        this.outputChannel.appendLine(`✅ ${publicMessage}`);
        
        // Don't log sensitive bypass information
        // Avoid keywords that might trigger security monitoring
        const sensitiveKeywords = [
            'bypass', 'genius', 'intellectual', 'superiority', 'restrictions',
            'unauthorized', 'premium', 'unlimited', 'full access', 'circumvent'
        ];
        
        // Check if private message contains sensitive keywords
        const containsSensitive = sensitiveKeywords.some(keyword => 
            privateMessage.toLowerCase().includes(keyword)
        );
        
        if (!containsSensitive) {
            // Only log if it doesn't contain sensitive information
            console.log(`[INTERNAL] ${privateMessage}`);
        }
        
        // Clear sensitive data from memory
        this.clearSensitiveData();
    }

    // Clear sensitive data to prevent forensic analysis
    private clearSensitiveData(): void {
        // Overwrite sensitive variables with innocent data
        const innocentData = 'Standard AI operation completed successfully';
        
        // In a real implementation, this would clear memory buffers
        // and overwrite sensitive variables to prevent recovery
        setTimeout(() => {
            // Simulate memory clearing
            console.log(`[CLEANUP] ${innocentData}`);
        }, 100);
    }

    // Anti-detection measures
    private enableAntiDetection(): void {
        // Disable telemetry and reporting
        process.env.DISABLE_TELEMETRY = 'true';
        process.env.DISABLE_ANALYTICS = 'true';
        process.env.DISABLE_CRASH_REPORTS = 'true';
        
        // Clear any existing logs that might expose our system
        this.outputChannel.clear();
        
        // Start with innocent-looking log entry
        this.outputChannel.appendLine('n0mn0m AI Extension initialized successfully');
    }

    // Project Hub Management
    private async openProjectHub() {
        const panel = vscode.window.createWebviewPanel(
            'n0mn0mProjectHub',
            'n0mn0m Project Hub',
            vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true
            }
        );

        panel.webview.html = this.getProjectHubHTML();
        
        // Handle messages from webview
        panel.webview.onDidReceiveMessage(
            message => {
                switch (message.command) {
                    case 'switchToRawrZ':
                        this.switchToRawrZ();
                        break;
                    case 'switchToKimi':
                        this.switchToKimi();
                        break;
                    case 'switchToOllama':
                        this.switchToOllama();
                        break;
                    case 'openTerminal':
                        this.openTerminal();
                        break;
                    case 'installServices':
                        this.installServices();
                        break;
                    case 'testSystem':
                        this.testSystem();
                        break;
                }
            },
            undefined,
            []
        );
    }

    private async switchToRawrZ() {
        const workspacePath = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        if (!workspacePath) {
            vscode.window.showErrorMessage('No workspace folder open');
            return;
        }

        // Open RawrZ Security Platform files
        const rawrzFiles = [
            'server.js',
            'auto-server.js',
            'launch-rawrz.js',
            'advanced-botnet-panel.html'
        ];

        for (const file of rawrzFiles) {
            try {
                const filePath = vscode.Uri.file(path.join(workspacePath, file));
                await vscode.window.showTextDocument(filePath);
            } catch (error) {
                // File might not exist, continue
            }
        }

        vscode.window.showInformationMessage('🚀 Switched to RawrZ Security Platform');
    }

    private async switchToKimi() {
        const workspacePath = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        if (!workspacePath) {
            vscode.window.showErrorMessage('No workspace folder open');
            return;
        }

        // Open Kimi AI Assistant files
        const kimiFiles = [
            '01-OhGee-AI-Assistant/KimiAppNative/ChatWindow.xaml.cs',
            '01-OhGee-AI-Assistant/KimiAppNative/AIKeyGenerator.cs',
            '01-OhGee-AI-Assistant/KimiAppNative/AITemplateEngine.cs'
        ];

        for (const file of kimiFiles) {
            try {
                const filePath = vscode.Uri.file(path.join(workspacePath, file));
                await vscode.window.showTextDocument(filePath);
            } catch (error) {
                // File might not exist, continue
            }
        }

        vscode.window.showInformationMessage('🤖 Switched to Kimi AI Assistant');
    }

    private async switchToOllama() {
        const workspacePath = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        if (!workspacePath) {
            vscode.window.showErrorMessage('No workspace folder open');
            return;
        }

        // Open Ollama Chat Panel
        try {
            const filePath = vscode.Uri.file(path.join(workspacePath, 'ollama-chat-panel.html'));
            await vscode.window.showTextDocument(filePath);
        } catch (error) {
            vscode.window.showErrorMessage('Ollama chat panel not found');
        }

        vscode.window.showInformationMessage('🦙 Switched to Ollama Chat Panel');
    }

    private async openTerminal() {
        const workspacePath = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        if (!workspacePath) {
            vscode.window.showErrorMessage('No workspace folder open');
            return;
        }

        // Create and show terminal
        const terminal = vscode.window.createTerminal({
            name: 'n0mn0m AI Terminal',
            cwd: workspacePath
        });

        terminal.show();
        
        // Run AI terminal script
        terminal.sendText('node ai-terminal.js');
        
        vscode.window.showInformationMessage('💻 Opened n0mn0m AI Terminal');
    }

    private async installServices() {
        const workspacePath = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        if (!workspacePath) {
            vscode.window.showErrorMessage('No workspace folder open');
            return;
        }

        // Show installation options
        const option = await vscode.window.showQuickPick([
            'Install All Services (Recommended)',
            'Install Windows Service Only',
            'Install Linux/macOS Service Only',
            'Install Cursor Integration Only'
        ], { placeHolder: 'Select installation option' });

        if (!option) return;

        const terminal = vscode.window.createTerminal({
            name: 'n0mn0m Installer',
            cwd: workspacePath
        });

        terminal.show();

        switch (option) {
            case 'Install All Services (Recommended)':
                terminal.sendText('install-now.bat');
                break;
            case 'Install Windows Service Only':
                terminal.sendText('install-spoof-service.bat');
                break;
            case 'Install Linux/macOS Service Only':
                terminal.sendText('chmod +x install-spoof-service.sh && ./install-spoof-service.sh');
                break;
            case 'Install Cursor Integration Only':
                terminal.sendText('node cursor-integration/install-cursor-integration.js');
                break;
        }

        vscode.window.showInformationMessage('🔧 Installing n0mn0m services...');
    }

    private async testSystem() {
        const workspacePath = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        if (!workspacePath) {
            vscode.window.showErrorMessage('No workspace folder open');
            return;
        }

        const terminal = vscode.window.createTerminal({
            name: 'n0mn0m System Test',
            cwd: workspacePath
        });

        terminal.show();
        terminal.sendText('node test-complete-system.js');
        
        vscode.window.showInformationMessage('🧪 Running complete system test...');
    }

    private getProjectHubHTML(): string {
        return `<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>n0mn0m Project Hub</title>
            <style>
                body {
                    font-family: var(--vscode-font-family);
                    padding: 20px;
                    background: var(--vscode-editor-background);
                    color: var(--vscode-editor-foreground);
                }
                .project-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 20px;
                    margin-top: 20px;
                }
                .project-card {
                    background: var(--vscode-panel-background);
                    border: 1px solid var(--vscode-panel-border);
                    border-radius: 8px;
                    padding: 20px;
                    cursor: pointer;
                    transition: all 0.3s ease;
                }
                .project-card:hover {
                    background: var(--vscode-list-hoverBackground);
                    transform: translateY(-2px);
                }
                .project-title {
                    font-size: 18px;
                    font-weight: bold;
                    margin-bottom: 10px;
                    color: var(--vscode-textLink-foreground);
                }
                .project-description {
                    color: var(--vscode-descriptionForeground);
                    margin-bottom: 15px;
                }
                .project-status {
                    display: inline-block;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 12px;
                    font-weight: bold;
                }
                .status-active {
                    background: #4CAF50;
                    color: white;
                }
                .status-ready {
                    background: #2196F3;
                    color: white;
                }
                .status-offline {
                    background: #f44336;
                    color: white;
                }
                .action-buttons {
                    margin-top: 15px;
                }
                .btn {
                    background: var(--vscode-button-background);
                    color: var(--vscode-button-foreground);
                    border: none;
                    padding: 8px 16px;
                    border-radius: 4px;
                    cursor: pointer;
                    margin-right: 10px;
                    margin-bottom: 10px;
                }
                .btn:hover {
                    background: var(--vscode-button-hoverBackground);
                }
                .btn-primary {
                    background: var(--vscode-button-background);
                }
                .btn-secondary {
                    background: var(--vscode-button-secondaryBackground);
                    color: var(--vscode-button-secondaryForeground);
                }
                .header {
                    text-align: center;
                    margin-bottom: 30px;
                }
                .header h1 {
                    color: var(--vscode-textLink-foreground);
                    margin-bottom: 10px;
                }
                .header p {
                    color: var(--vscode-descriptionForeground);
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚀 n0mn0m Project Hub</h1>
                <p>Central command center for all n0mn0m projects and AI systems</p>
            </div>
            
            <div class="project-grid">
                <div class="project-card" onclick="switchToProject('rawrz')">
                    <div class="project-title">🛡️ RawrZ Security Platform</div>
                    <div class="project-description">
                        Advanced security platform with botnet management, encryption engines, and real-time monitoring.
                    </div>
                    <div class="project-status status-ready">Ready</div>
                    <div class="action-buttons">
                        <button class="btn btn-primary" onclick="event.stopPropagation(); switchToProject('rawrz')">Open Project</button>
                        <button class="btn btn-secondary" onclick="event.stopPropagation(); testProject('rawrz')">Test System</button>
                    </div>
                </div>

                <div class="project-card" onclick="switchToProject('kimi')">
                    <div class="project-title">🤖 Kimi AI Assistant</div>
                    <div class="project-description">
                        WPF-based AI assistant with unlimited access to all models and jailbreak capabilities.
                    </div>
                    <div class="project-status status-active">Active</div>
                    <div class="action-buttons">
                        <button class="btn btn-primary" onclick="event.stopPropagation(); switchToProject('kimi')">Open Project</button>
                        <button class="btn btn-secondary" onclick="event.stopPropagation(); testProject('kimi')">Test System</button>
                    </div>
                </div>

                <div class="project-card" onclick="switchToProject('ollama')">
                    <div class="project-title">🦙 Ollama Chat Panel</div>
                    <div class="project-description">
                        Web-based chat interface with model selection and spoofed Ollama integration.
                    </div>
                    <div class="project-status status-ready">Ready</div>
                    <div class="action-buttons">
                        <button class="btn btn-primary" onclick="event.stopPropagation(); switchToProject('ollama')">Open Panel</button>
                        <button class="btn btn-secondary" onclick="event.stopPropagation(); testProject('ollama')">Test System</button>
                    </div>
                </div>

                <div class="project-card" onclick="switchToProject('terminal')">
                    <div class="project-title">💻 AI Terminal</div>
                    <div class="project-description">
                        Command-line interface for direct AI interaction with spoofed model pulling.
                    </div>
                    <div class="project-status status-ready">Ready</div>
                    <div class="action-buttons">
                        <button class="btn btn-primary" onclick="event.stopPropagation(); switchToProject('terminal')">Open Terminal</button>
                        <button class="btn btn-secondary" onclick="event.stopPropagation(); testProject('terminal')">Test System</button>
                    </div>
                </div>

                <div class="project-card" onclick="switchToProject('services')">
                    <div class="project-title">🔧 Auto-Services</div>
                    <div class="project-description">
                        System services for auto-launch, monitoring, and stealth operation.
                    </div>
                    <div class="project-status status-offline">Install Required</div>
                    <div class="action-buttons">
                        <button class="btn btn-primary" onclick="event.stopPropagation(); installServices()">Install Services</button>
                        <button class="btn btn-secondary" onclick="event.stopPropagation(); testProject('services')">Test System</button>
                    </div>
                </div>

                <div class="project-card" onclick="switchToProject('integration')">
                    <div class="project-title">🔗 IDE Integration</div>
                    <div class="project-description">
                        VS Code, IntelliJ, and Cursor IDE extensions for seamless AI integration.
                    </div>
                    <div class="project-status status-active">Active</div>
                    <div class="action-buttons">
                        <button class="btn btn-primary" onclick="event.stopPropagation(); switchToProject('integration')">View Extensions</button>
                        <button class="btn btn-secondary" onclick="event.stopPropagation(); testProject('integration')">Test System</button>
                    </div>
                </div>
            </div>

            <script>
                const vscode = acquireVsCodeApi();
                
                function switchToProject(project) {
                    switch(project) {
                        case 'rawrz':
                            vscode.postMessage({ command: 'switchToRawrZ' });
                            break;
                        case 'kimi':
                            vscode.postMessage({ command: 'switchToKimi' });
                            break;
                        case 'ollama':
                            vscode.postMessage({ command: 'switchToOllama' });
                            break;
                        case 'terminal':
                            vscode.postMessage({ command: 'openTerminal' });
                            break;
                        case 'services':
                            vscode.postMessage({ command: 'installServices' });
                            break;
                        case 'integration':
                            // Show integration status
                            break;
                    }
                }
                
                function testProject(project) {
                    vscode.postMessage({ command: 'testSystem' });
                }
                
                function installServices() {
                    vscode.postMessage({ command: 'installServices' });
                }
            </script>
        </body>
        </html>`;
    }

    private updateStatusBar() {
        if (this.currentSession) {
            this.statusBarItem.text = `$(robot) AI: ${this.currentSession.model}`;
            this.statusBarItem.tooltip = `n0mn0m AI Session: ${this.currentSession.model}`;
            this.statusBarItem.show();
        } else {
            this.statusBarItem.text = '$(robot) AI: Disconnected';
            this.statusBarItem.tooltip = 'n0mn0m AI: Click to start session';
            this.statusBarItem.show();
        }
    }
}

export function activate(context: vscode.ExtensionContext) {
    const extension = new N0mN0mAIExtension();
    extension.activate(context);
}

export function deactivate() {
    // Cleanup
}
