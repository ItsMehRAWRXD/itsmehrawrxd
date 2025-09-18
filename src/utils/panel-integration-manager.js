const fs = require('fs');
const path = require('path');

class PanelIntegrationManager {
    constructor() {
        this.enginesDir = './src/engines';
        this.panelsDir = './public';
        this.engines = [];
        this.panels = [];
        this.loadEngines();
        this.loadPanels();
    }
    
    loadEngines() {
        if (fs.existsSync(this.enginesDir)) {
            const files = fs.readdirSync(this.enginesDir).filter(file => file.endsWith('.js'));
            this.engines = files.map(file => ({
                name: file.replace('.js', ''),
                file: file,
                path: path.join(this.enginesDir, file),
                hasPanelIntegration: false
            }));
        }
    }
    
    loadPanels() {
        if (fs.existsSync(this.panelsDir)) {
            const files = fs.readdirSync(this.panelsDir).filter(file => file.endsWith('.html'));
            this.panels = files.map(file => ({
                name: file.replace('.html', ''),
                file: file,
                path: path.join(this.panelsDir, file)
            }));
        }
    }
    
    async integrateEngineWithPanel(engineName, panelName) {
        try {
            const engine = this.engines.find(e => e.name === engineName);
            const panel = this.panels.find(p => p.name === panelName);
            
            if (!engine || !panel) {
                throw new Error('Engine or panel not found');
            }
            
            // Read engine content
            let engineContent = fs.readFileSync(engine.path, 'utf8');
            
            // Add panel integration methods
            const panelMethods = `
    // Panel Integration Methods
    async getPanelConfig() {
        return {
            name: this.name,
            version: this.version,
            description: this.description || 'RawrZ Engine',
            endpoints: this.getAvailableEndpoints(),
            settings: this.getSettings(),
            status: this.getStatus()
        };
    }
    
    getAvailableEndpoints() {
        return [
            { method: 'GET', path: `/api/${this.name}/status`, description: 'Get engine status' },
            { method: 'POST', path: `/api/${this.name}/initialize`, description: 'Initialize engine' },
            { method: 'POST', path: `/api/${this.name}/start`, description: 'Start engine' },
            { method: 'POST', path: `/api/${this.name}/stop`, description: 'Stop engine' }
        ];
    }
    
    getSettings() {
        return {
            enabled: this.enabled || true,
            autoStart: this.autoStart || false,
            config: this.config || {}
        };
    }
`;
            
            // Add panel methods to engine
            const lastBraceIndex = engineContent.lastIndexOf('}');
            if (lastBraceIndex !== -1) {
                engineContent = engineContent.slice(0, lastBraceIndex) + panelMethods + '\n' + engineContent.slice(lastBraceIndex);
                fs.writeFileSync(engine.path, engineContent);
                engine.hasPanelIntegration = true;
                console.log(`✅ Integrated ${engineName} with panel system`);
            }
            
        } catch (error) {
            console.log(`❌ Failed to integrate ${engineName}: ${error.message}`);
        }
    }
    
    async integrateAllEngines() {
        console.log('Integrating all engines with panel system...');
        for (const engine of this.engines) {
            await this.integrateEngineWithPanel(engine.name, 'unified-panel');
        }
        console.log(`✅ Integrated ${this.engines.length} engines with panel system`);
    }
    
    getEngines() {
        return this.engines;
    }
    
    getPanels() {
        return this.panels;
    }
}

module.exports = new PanelIntegrationManager();
