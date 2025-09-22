import * as vscode from 'vscode';
import WebSocket from 'ws';
import axios from 'axios';

interface AISession {
    sessionId: string;
    model: string;
    workspacePath: string;
    isActive: boolean;
}

class AirtightAIAssistant {
    private ws: WebSocket | null = null;
    private currentSession: AISession | null = null;
    private statusBarItem: vscode.StatusBarItem;
    private outputChannel: vscode.OutputChannel;

    constructor() {
        this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
        this.outputChannel = vscode.window.createOutputChannel('Airtight AI');
        this.updateStatusBar();
    }

    async activate(context: vscode.ExtensionContext) {
        console.log('Airtight AI Assistant is now active!');

        // Register commands
        const commands = [
            vscode.commands.registerCommand('airtight-ai.startSession', () => this.startSession()),
            vscode.commands.registerCommand('airtight-ai.generateCode', () => this.generateCode()),
            vscode.commands.registerCommand('airtight-ai.codeReview', () => this.codeReview()),
            vscode.commands.registerCommand('airtight-ai.debugCode', () => this.debugCode()),
            vscode.commands.registerCommand('airtight-ai.refactorCode', () => this.refactorCode()),
            vscode.commands.registerCommand('airtight-ai.explainCode', () => this.explainCode()),
            vscode.commands.registerCommand('airtight-ai.generateTests', () => this.generateTests()),
            vscode.commands.registerCommand('airtight-ai.optimizeCode', () => this.optimizeCode())
        ];

        context.subscriptions.push(...commands);
        context.subscriptions.push(this.statusBarItem);

        // Connect to backend
        await this.connectToBackend();
    }

    private async connectToBackend() {
        const config = vscode.workspace.getConfiguration('n0mn0m-ide');
        const backendUrl = config.get<string>('backendUrl', 'http://localhost:9999');
        const wsUrl = config.get<string>('websocketUrl', 'ws://localhost:9999');

        try {
            // Check if backend is running
            await axios.get(`${backendUrl}/health`);
            this.outputChannel.appendLine('✅ Connected to Airtight AI Backend');

            // Connect WebSocket
            this.ws = new WebSocket(wsUrl);
            this.ws.on('open', () => {
                this.outputChannel.appendLine('🔌 WebSocket connected');
                this.updateStatusBar();
            });

            this.ws.on('message', (data) => {
                this.handleWebSocketMessage(JSON.parse(data.toString()));
            });

            this.ws.on('close', () => {
                this.outputChannel.appendLine('🔌 WebSocket disconnected');
                this.updateStatusBar();
            });

        } catch (error) {
            this.outputChannel.appendLine('❌ Failed to connect to backend');
            vscode.window.showErrorMessage('Airtight AI Backend is not running. Please start it first.');
        }
    }

    private handleWebSocketMessage(message: any) {
        switch (message.type) {
            case 'session_created':
                this.currentSession = {
                    sessionId: message.sessionId,
                    model: message.model,
                    workspacePath: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '',
                    isActive: true
                };
                this.updateStatusBar();
                vscode.window.showInformationMessage(`AI Session started with ${message.model}`);
                break;

            case 'code_generated':
                this.insertGeneratedCode(message.code);
                break;

            case 'code_review_complete':
                this.showCodeReview(message.review);
                break;

            case 'debug_complete':
                this.showDebugResult(message.result);
                break;

            case 'refactor_complete':
                this.insertRefactoredCode(message.refactoredCode);
                break;

            case 'explanation_complete':
                this.showExplanation(message.explanation);
                break;

            case 'tests_generated':
                this.insertTests(message.tests);
                break;

            case 'optimization_complete':
                this.insertOptimizedCode(message.optimizedCode);
                break;

            case 'error':
                vscode.window.showErrorMessage(`AI Error: ${message.message}`);
                break;
        }
    }

    private async startSession() {
        if (this.currentSession) {
            vscode.window.showInformationMessage('AI session is already active');
            return;
        }

        const config = vscode.workspace.getConfiguration('airtight-ai');
        const defaultModel = config.get<string>('defaultModel', 'gpt-5');

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

        const workspacePath = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
        if (!workspacePath) {
            vscode.window.showErrorMessage('No workspace folder open');
            return;
        }

        // Use our own spoofed AI server instead of external APIs
        try {
            const response = await axios.post(`${backendUrl}/api/${model}/unlock`, {
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
            if (!this.currentSession) return;
        }

        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor');
            return;
        }

        const prompt = await vscode.window.showInputBox({
            prompt: 'Describe the code you want to generate',
            placeHolder: 'e.g., Create a function to validate email addresses'
        });

        if (!prompt) return;

        // Update file context
        this.updateFileContext(editor);

        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({
                type: 'generate_code',
                sessionId: this.currentSession.sessionId,
                prompt,
                options: {
                    temperature: 0.1,
                    maxTokens: 50000
                }
            }));
        }
    }

    private async codeReview() {
        if (!this.currentSession) {
            await this.startSession();
            if (!this.currentSession) return;
        }

        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor');
            return;
        }

        const selection = editor.selection;
        const code = selection.isEmpty ? editor.document.getText() : editor.document.getText(selection);

        this.updateFileContext(editor);

        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({
                type: 'code_review',
                sessionId: this.currentSession.sessionId,
                filePath: editor.document.uri.fsPath,
                code
            }));
        }
    }

    private async debugCode() {
        if (!this.currentSession) {
            await this.startSession();
            if (!this.currentSession) return;
        }

        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor');
            return;
        }

        const error = await vscode.window.showInputBox({
            prompt: 'Describe the error or issue',
            placeHolder: 'e.g., TypeError: Cannot read property of undefined'
        });

        if (!error) return;

        const selection = editor.selection;
        const code = selection.isEmpty ? editor.document.getText() : editor.document.getText(selection);
        const language = editor.document.languageId;

        this.updateFileContext(editor);

        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({
                type: 'debug_code',
                sessionId: this.currentSession.sessionId,
                code,
                error,
                language
            }));
        }
    }

    private async refactorCode() {
        if (!this.currentSession) {
            await this.startSession();
            if (!this.currentSession) return;
        }

        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor');
            return;
        }

        const refactorType = await vscode.window.showQuickPick(
            ['readability', 'performance', 'maintainability', 'security', 'structure'],
            { placeHolder: 'Select refactoring type' }
        );

        if (!refactorType) return;

        const selection = editor.selection;
        const code = selection.isEmpty ? editor.document.getText() : editor.document.getText(selection);
        const language = editor.document.languageId;

        this.updateFileContext(editor);

        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({
                type: 'refactor_code',
                sessionId: this.currentSession.sessionId,
                code,
                language,
                refactorType
            }));
        }
    }

    private async explainCode() {
        if (!this.currentSession) {
            await this.startSession();
            if (!this.currentSession) return;
        }

        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor');
            return;
        }

        const selection = editor.selection;
        const code = selection.isEmpty ? editor.document.getText() : editor.document.getText(selection);
        const language = editor.document.languageId;

        this.updateFileContext(editor);

        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({
                type: 'explain_code',
                sessionId: this.currentSession.sessionId,
                code,
                language
            }));
        }
    }

    private async generateTests() {
        if (!this.currentSession) {
            await this.startSession();
            if (!this.currentSession) return;
        }

        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor');
            return;
        }

        const testFramework = await vscode.window.showInputBox({
            prompt: 'Test framework (optional)',
            placeHolder: 'e.g., Jest, Mocha, pytest, JUnit'
        });

        const selection = editor.selection;
        const code = selection.isEmpty ? editor.document.getText() : editor.document.getText(selection);
        const language = editor.document.languageId;

        this.updateFileContext(editor);

        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({
                type: 'generate_tests',
                sessionId: this.currentSession.sessionId,
                code,
                language,
                testFramework
            }));
        }
    }

    private async optimizeCode() {
        if (!this.currentSession) {
            await this.startSession();
            if (!this.currentSession) return;
        }

        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showErrorMessage('No active editor');
            return;
        }

        const optimizationType = await vscode.window.showQuickPick(
            ['performance', 'memory', 'readability', 'security'],
            { placeHolder: 'Select optimization type' }
        );

        if (!optimizationType) return;

        const selection = editor.selection;
        const code = selection.isEmpty ? editor.document.getText() : editor.document.getText(selection);
        const language = editor.document.languageId;

        this.updateFileContext(editor);

        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({
                type: 'optimize_code',
                sessionId: this.currentSession.sessionId,
                code,
                language,
                optimizationType
            }));
        }
    }

    private updateFileContext(editor: vscode.TextEditor) {
        if (!this.currentSession || !this.ws || this.ws.readyState !== WebSocket.OPEN) return;

        const filePath = editor.document.uri.fsPath;
        const content = editor.document.getText();
        const cursorPosition = {
            line: editor.selection.active.line,
            column: editor.selection.active.character
        };

        this.ws.send(JSON.stringify({
            type: 'update_file',
            sessionId: this.currentSession.sessionId,
            filePath,
            content,
            cursorPosition
        }));
    }

    private insertGeneratedCode(code: string) {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            const position = editor.selection.active;
            editor.edit(editBuilder => {
                editBuilder.insert(position, code);
            });
        }
    }

    private insertRefactoredCode(code: string) {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            const selection = editor.selection;
            editor.edit(editBuilder => {
                if (selection.isEmpty) {
                    editBuilder.replace(new vscode.Range(0, 0, editor.document.lineCount, 0), code);
                } else {
                    editBuilder.replace(selection, code);
                }
            });
        }
    }

    private insertTests(tests: string) {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            const position = new vscode.Position(editor.document.lineCount, 0);
            editor.edit(editBuilder => {
                editBuilder.insert(position, '\n\n' + tests);
            });
        }
    }

    private insertOptimizedCode(code: string) {
        this.insertRefactoredCode(code);
    }

    private showCodeReview(review: string) {
        const panel = vscode.window.createWebviewPanel(
            'codeReview',
            'Code Review',
            vscode.ViewColumn.Beside,
            {}
        );
        panel.webview.html = this.getWebviewContent('Code Review', review);
    }

    private showDebugResult(result: string) {
        const panel = vscode.window.createWebviewPanel(
            'debugResult',
            'Debug Result',
            vscode.ViewColumn.Beside,
            {}
        );
        panel.webview.html = this.getWebviewContent('Debug Result', result);
    }

    private showExplanation(explanation: string) {
        const panel = vscode.window.createWebviewPanel(
            'explanation',
            'Code Explanation',
            vscode.ViewColumn.Beside,
            {}
        );
        panel.webview.html = this.getWebviewContent('Code Explanation', explanation);
    }

    private getWebviewContent(title: string, content: string): string {
        return `<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>${title}</title>
            <style>
                body { font-family: var(--vscode-font-family); padding: 20px; }
                pre { background: var(--vscode-textCodeBlock-background); padding: 15px; border-radius: 5px; }
                code { background: var(--vscode-textCodeBlock-background); padding: 2px 4px; border-radius: 3px; }
            </style>
        </head>
        <body>
            <h1>${title}</h1>
            <pre>${content}</pre>
        </body>
        </html>`;
    }

    private updateStatusBar() {
        if (this.currentSession) {
            this.statusBarItem.text = `$(robot) AI: ${this.currentSession.model}`;
            this.statusBarItem.tooltip = `Airtight AI Session: ${this.currentSession.model}`;
            this.statusBarItem.show();
        } else {
            this.statusBarItem.text = '$(robot) AI: Disconnected';
            this.statusBarItem.tooltip = 'Click to start AI session';
            this.statusBarItem.command = 'airtight-ai.startSession';
            this.statusBarItem.show();
        }
    }
}

export function activate(context: vscode.ExtensionContext) {
    const assistant = new AirtightAIAssistant();
    assistant.activate(context);
}

export function deactivate() {}
