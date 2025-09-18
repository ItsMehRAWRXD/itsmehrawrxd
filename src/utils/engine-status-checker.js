const fs = require('fs');
const path = require('path');

class EngineStatusChecker {
    constructor() {
        this.enginesDir = './src/engines';
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
                status: 'unknown'
            }));
        }
    }
    
    async checkEngineStatus(engineName) {
        const engine = this.engines.find(e => e.name === engineName);
        if (!engine) {
            return { status: 'not_found', error: 'Engine not found' };
        }
        
        try {
            // Check if file exists and is readable
            if (!fs.existsSync(engine.path)) {
                return { status: 'missing', error: 'File not found' };
            }
            
            // Check for syntax errors
            try {
                require(engine.path);
                engine.status = 'syntax_ok';
            } catch (error) {
                if (error.message.includes('SyntaxError')) {
                    return { status: 'syntax_error', error: error.message };
                }
                engine.status = 'loaded';
            }
            
            // Check for required methods
            const content = fs.readFileSync(engine.path, 'utf8');
            const hasInitialize = content.includes('initialize') || content.includes('init');
            const hasClass = content.includes('class ') || content.includes('function ');
            
            return {
                status: 'ok',
                hasInitialize,
                hasClass,
                fileSize: fs.statSync(engine.path).size,
                lastModified: fs.statSync(engine.path).mtime
            };
            
        } catch (error) {
            return { status: 'error', error: error.message };
        }
    }
    
    async checkAllEngines() {
        const results = {};
        for (const engine of this.engines) {
            results[engine.name] = await this.checkEngineStatus(engine.name);
        }
        return results;
    }
    
    getEnginesList() {
        return this.engines.map(e => e.name);
    }
}

module.exports = new EngineStatusChecker();
