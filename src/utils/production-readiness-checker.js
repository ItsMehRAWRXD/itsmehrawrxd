const fs = require('fs');
const path = require('path');

class ProductionReadinessChecker {
    constructor() {
        this.enginesDir = './src/engines';
        this.results = {
            engines: {},
            server: {},
            panels: {},
            cli: {},
            config: {}
        };
    }
    
    async checkAll() {
        console.log('🔍 RawrZ Platform - Production Readiness Check');
        console.log('=' .repeat(80));
        
        await this.checkEngines();
        await this.checkServer();
        await this.checkPanels();
        await this.checkCLI();
        await this.checkConfig();
        
        this.generateReport();
    }
    
    async checkEngines() {
        console.log('\n📁 Checking Engines...');
        
        const engineFiles = fs.readdirSync(this.enginesDir).filter(file => file.endsWith('.js'));
        
        for (const file of engineFiles) {
            const engineName = file.replace('.js', '');
            const enginePath = path.join(this.enginesDir, file);
            
            try {
                const content = fs.readFileSync(enginePath, 'utf8');
                
                // Check for required methods
                const hasInitialize = content.includes('initialize');
                const hasStart = content.includes('start');
                const hasStop = content.includes('stop');
                const hasGetStatus = content.includes('getStatus');
                
                // Check for mock implementations
                const hasMockConsole = content.includes('console.log(');
                const hasMockReturn = content.includes('return { success: true }');
                
                // Check for hardcoded URLs
                const hasHardcodedUrls = /https?:\/\/[^\s'"]+/.test(content);
                
                // Check for panel integration
                const hasPanelIntegration = content.includes('getPanelConfig');
                
                // Check for CLI integration
                const hasCLIIntegration = content.includes('getCLICommands');
                
                this.results.engines[engineName] = {
                    hasInitialize,
                    hasStart,
                    hasStop,
                    hasGetStatus,
                    hasMockConsole,
                    hasMockReturn,
                    hasHardcodedUrls,
                    hasPanelIntegration,
                    hasCLIIntegration,
                    ready: hasInitialize && hasGetStatus && !hasMockConsole && !hasMockReturn && !hasHardcodedUrls && hasPanelIntegration && hasCLIIntegration
                };
                
                if (this.results.engines[engineName].ready) {
                    console.log(`✅ ${engineName}: Production ready`);
                } else {
                    console.log(`⚠️  ${engineName}: Needs attention`);
                }
                
            } catch (error) {
                this.results.engines[engineName] = { error: error.message, ready: false };
                console.log(`❌ ${engineName}: Error - ${error.message}`);
            }
        }
    }
    
    async checkServer() {
        console.log('\n🔧 Checking Server...');
        
        try {
            const serverContent = fs.readFileSync('./server.js', 'utf8');
            
            // Check for syntax errors
            try {
                require('./server.js');
                this.results.server.syntax = true;
                console.log('✅ Server syntax: OK');
            } catch (error) {
                this.results.server.syntax = false;
                console.log(`❌ Server syntax: ${error.message}`);
            }
            
            // Check for API endpoints
            const apiEndpoints = (serverContent.match(/app\.(get|post|put|delete)\(['"`]([^'"`]+)['"`]/g) || []).length;
            this.results.server.apiEndpoints = apiEndpoints;
            console.log(`✅ API endpoints: ${apiEndpoints} found`);
            
            // Check for hardcoded URLs
            const hasHardcodedUrls = /https?:\/\/[^\s'"]+/.test(serverContent);
            this.results.server.hasHardcodedUrls = hasHardcodedUrls;
            if (hasHardcodedUrls) {
                console.log('⚠️  Server: Has hardcoded URLs');
            } else {
                console.log('✅ Server: No hardcoded URLs');
            }
            
        } catch (error) {
            this.results.server.error = error.message;
            console.log(`❌ Server check failed: ${error.message}`);
        }
    }
    
    async checkPanels() {
        console.log('\n🌐 Checking Panels...');
        
        const publicDir = './public';
        const panelFiles = fs.readdirSync(publicDir).filter(file => file.endsWith('.html'));
        
        let totalPanels = panelFiles.length;
        let readyPanels = 0;
        
        panelFiles.forEach(file => {
            try {
                const content = fs.readFileSync(path.join(publicDir, file), 'utf8');
                const hasHardcodedUrls = /https?:\/\/[^\s'"]+/.test(content);
                
                if (!hasHardcodedUrls) {
                    readyPanels++;
                    console.log(`✅ ${file}: Production ready`);
                } else {
                    console.log(`⚠️  ${file}: Has hardcoded URLs`);
                }
                
            } catch (error) {
                console.log(`❌ ${file}: Error - ${error.message}`);
            }
        });
        
        this.results.panels = { total: totalPanels, ready: readyPanels };
    }
    
    async checkCLI() {
        console.log('\n💻 Checking CLI...');
        
        const cliDir = './src/cli';
        if (fs.existsSync(cliDir)) {
            const cliFiles = fs.readdirSync(cliDir).filter(file => file.endsWith('.js'));
            this.results.cli = { total: cliFiles.length, ready: cliFiles.length };
            console.log(`✅ CLI files: ${cliFiles.length} found`);
        } else {
            this.results.cli = { total: 0, ready: 0 };
            console.log('❌ CLI directory not found');
        }
    }
    
    async checkConfig() {
        console.log('\n⚙️ Checking Configuration...');
        
        const configFiles = ['config.js', 'production.config.js', '.env'];
        let readyConfigs = 0;
        
        configFiles.forEach(file => {
            if (fs.existsSync(file)) {
                readyConfigs++;
                console.log(`✅ ${file}: Exists`);
            } else {
                console.log(`❌ ${file}: Missing`);
            }
        });
        
        this.results.config = { total: configFiles.length, ready: readyConfigs };
    }
    
    generateReport() {
        console.log('\n' + '=' .repeat(80));
        console.log('🎯 PRODUCTION READINESS REPORT');
        console.log('=' .repeat(80));
        
        // Engine summary
        const engineResults = Object.values(this.results.engines);
        const readyEngines = engineResults.filter(r => r.ready).length;
        const totalEngines = engineResults.length;
        
        console.log(`\n📊 Summary:`);
        console.log(`   Engines: ${readyEngines}/${totalEngines} ready (${Math.round((readyEngines/totalEngines)*100)}%)`);
        console.log(`   Server: ${this.results.server.syntax ? 'Ready' : 'Not Ready'}`);
        console.log(`   Panels: ${this.results.panels.ready}/${this.results.panels.total} ready`);
        console.log(`   CLI: ${this.results.cli.ready}/${this.results.cli.total} ready`);
        console.log(`   Config: ${this.results.config.ready}/${this.results.config.total} ready`);
        
        // Overall readiness
        const overallReady = readyEngines === totalEngines && 
                           this.results.server.syntax && 
                           this.results.panels.ready === this.results.panels.total &&
                           this.results.cli.ready === this.results.cli.total &&
                           this.results.config.ready === this.results.config.total;
        
        if (overallReady) {
            console.log('\n🎉 RawrZ Platform is PRODUCTION READY!');
        } else {
            console.log('\n⚠️  RawrZ Platform needs attention before production deployment');
        }
        
        console.log('\n' + '=' .repeat(80));
    }
}

module.exports = new ProductionReadinessChecker();
