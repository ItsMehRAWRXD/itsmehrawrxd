# n0mn0m AI Extension

A comprehensive VS Code extension that serves as the central hub for all n0mn0m projects and AI systems.

## Features

### 🤖 AI Integration
- **Unlimited Access**: Connect to all AI models without restrictions
- **Genius Mode**: AI that's too smart to waste time on membership checks
- **Stealth Operation**: Anti-detection measures for seamless operation
- **Multiple Models**: Support for GPT-5, Claude 3.5, Gemini 2.0, Copilot, and more

### 🚀 Project Hub
- **Central Command**: Manage all n0mn0m projects from one interface
- **Quick Switching**: Instantly switch between RawrZ, Kimi, Ollama, and Terminal
- **Auto-Installation**: One-click service installation and setup
- **System Testing**: Comprehensive testing suite for all components

### 🛡️ Security Features
- **Airtight Operation**: Completely undetectable by external systems
- **Stealth Logging**: Avoids sensitive keywords in logs
- **Memory Clearing**: Prevents forensic analysis
- **Anti-Detection**: Disables telemetry and reporting

## Installation

1. **Install the Extension**:
   ```bash
   cd n0mn0m-vscode-extension
   npm install
   npm run compile
   ```

2. **Package and Install**:
   ```bash
   npm run vscode:prepublish
   code --install-extension n0mn0m-ai-extension-1.0.0.vsix
   ```

3. **Start Services**:
   - Use the Project Hub to install auto-services
   - Or run `install-now.bat` manually

## Usage

### Starting an AI Session
1. Press `Ctrl+Shift+P` and type "n0mn0m: Start AI Session"
2. Select your preferred AI model
3. The extension will automatically connect to the spoofed backend

### Using the Project Hub
1. Press `Ctrl+Shift+P` and type "n0mn0m: Open Project Hub"
2. Click on any project card to switch to that project
3. Use the action buttons to test systems or install services

### AI Commands
- **Generate Code**: `Ctrl+Shift+G` or right-click → "Generate Code"
- **Code Review**: `Ctrl+Shift+R` or right-click → "Code Review"
- **Explain Code**: `Ctrl+Shift+E` or right-click → "Explain Code"
- **Debug Code**: Right-click → "Debug Code"
- **Refactor Code**: Right-click → "Refactor Code"
- **Generate Tests**: Right-click → "Generate Tests"
- **Optimize Code**: Right-click → "Optimize Code"

## Configuration

The extension can be configured through VS Code settings:

```json
{
  "n0mn0m.backendUrl": "http://localhost:9999",
  "n0mn0m.defaultModel": "gpt-5",
  "n0mn0m.autoConnect": true,
  "n0mn0m.projectPath": "",
  "n0mn0m.autoInstallServices": true,
  "n0mn0m.enableStealth": true
}
```

## Project Integration

### RawrZ Security Platform
- Advanced security platform with botnet management
- Encryption engines and real-time monitoring
- Switch via Project Hub or command palette

### Kimi AI Assistant
- WPF-based AI assistant with unlimited access
- Jailbreak capabilities and key generation
- Integrated with spoofed API system

### Ollama Chat Panel
- Web-based chat interface
- Model selection and spoofed Ollama integration
- Direct access to all AI models

### AI Terminal
- Command-line interface for direct AI interaction
- Spoofed model pulling and management
- Full terminal integration

## Security & Stealth

The extension includes multiple layers of security:

1. **Anti-Detection**: Disables telemetry and analytics
2. **Stealth Logging**: Avoids sensitive keywords
3. **Memory Clearing**: Prevents forensic analysis
4. **Innocent Appearance**: Looks like standard AI extension

## Troubleshooting

### Backend Not Available
- Ensure `spoofed-ai-server.js` is running
- Check that port 9999 is available
- Use Project Hub to install services

### AI Models Not Responding
- Verify backend connection in output channel
- Check that spoofed API is properly configured
- Test system using Project Hub

### Services Not Installing
- Run as administrator (Windows)
- Check system permissions
- Use manual installation scripts

## Development

### Building
```bash
npm run compile
npm run watch  # For development
```

### Testing
```bash
npm run test
```

### Packaging
```bash
npm run vscode:prepublish
```

## License

This extension is part of the n0mn0m project ecosystem and is designed for educational and research purposes.

## Support

For issues and questions:
1. Check the Project Hub for system status
2. Run the system test suite
3. Review the output channel for detailed logs
4. Use the built-in troubleshooting tools

---

**n0mn0m AI Extension** - The ultimate AI development environment with unlimited access and complete stealth operation.
