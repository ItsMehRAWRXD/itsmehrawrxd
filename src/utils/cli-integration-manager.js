const fs = require('fs');
const path = require('path');

class CLIIntegrationManager {
    constructor() {
        this.enginesDir = './src/engines';
        this.cliDir = './src/cli';
        this.engines = [];
        this.loadEngines();
    }
    
    loadEngines() {
        if (fs.existsSync(this.enginesDir)) {
            const files = fs.readdirSync(this.enginesDir).filter(file => file.endsWith('.js'));
            this.engines = files.map(file => ({
                name: file.replace('.js', ''),
                file: file,
                path: path.join(this.enginesDir, file),
                hasCLIIntegration: false
            }));
        }
    }
    
    async integrateEngineWithCLI(engineName) {
        try {
            const engine = this.engines.find(e => e.name === engineName);
            
            if (!engine) {
                throw new Error('Engine not found');
            }
            
            // Read engine content
            let engineContent = fs.readFileSync(engine.path, 'utf8');
            
            // Add CLI integration methods
            const cliMethods = `
    // CLI Integration Methods
    async getCLICommands() {
        return [
            {
                command: `${this.name} status`,
                description: 'Get engine status',
                action: async () => {
                    const status = this.getStatus();
                    console.log(`${this.name} Status:`, status);
                    return status;
                }
            },
            {
                command: `${this.name} start`,
                description: 'Start engine',
                action: async () => {
                    const result = await this.start();
                    console.log(`${this.name} started:`, result);
                    return result;
                }
            },
            {
                command: `${this.name} stop`,
                description: 'Stop engine',
                action: async () => {
                    const result = await this.stop();
                    console.log(`${this.name} stopped:`, result);
                    return result;
                }
            },
            {
                command: `${this.name} config`,
                description: 'Get engine configuration',
                action: async () => {
                    const config = this.getConfig();
                    console.log(`${this.name} Config:`, config);
                    return config;
                }
            }
        ];
    }
    
    getConfig() {
        return {
            name: this.name,
            version: this.version,
            enabled: this.enabled || true,
            autoStart: this.autoStart || false,
            settings: this.settings || {}
        };
    }
`;
            
            // Add CLI methods to engine
            const lastBraceIndex = engineContent.lastIndexOf('}');
            if (lastBraceIndex !== -1) {
                engineContent = engineContent.slice(0, lastBraceIndex) + cliMethods + '\n' + engineContent.slice(lastBraceIndex);
                fs.writeFileSync(engine.path, engineContent);
                engine.hasCLIIntegration = true;
                console.log(`✅ Integrated ${engineName} with CLI system`);
            }
            
        } catch (error) {
            console.log(`❌ Failed to integrate ${engineName}: ${error.message}`);
        }
    }
    
    async integrateAllEngines() {
        console.log('Integrating all engines with CLI system...');
        for (const engine of this.engines) {
            await this.integrateEngineWithCLI(engine.name);
        }
        console.log(`✅ Integrated ${this.engines.length} engines with CLI system`);
    }
    
    getEngines() {
        return this.engines;
    }
}

module.exports = new CLIIntegrationManager();
