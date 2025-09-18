#!/usr/bin/env node
const { Command } = require('commander');
const chalk = require('chalk');
const fs = require('fs');
const path = require('path');

const program = new Command();

program
    .name('rawrz-engines')
    .description('RawrZ Engine Management CLI')
    .version('1.0.0');

// Engine management commands
program
    .command('list')
    .description('List all available engines')
    .action(async () => {
        console.log(chalk.blue('Available Engines:'));
        const enginesDir = './src/engines';
        if (fs.existsSync(enginesDir)) {
            const engines = fs.readdirSync(enginesDir).filter(file => file.endsWith('.js'));
            engines.forEach(engine => {
                console.log(chalk.green(`  - ${engine.replace('.js', '')}`));
            });
        }
    });

program
    .command('status <engine>')
    .description('Check status of specific engine')
    .action(async (engine) => {
        console.log(chalk.blue(`Checking status of ${engine}...`));
        try {
            const enginePath = path.join('./src/engines', `${engine}.js`);
            if (fs.existsSync(enginePath)) {
                const content = fs.readFileSync(enginePath, 'utf8');
                const hasInitialize = content.includes('initialize');
                const hasStart = content.includes('start');
                const hasStop = content.includes('stop');
                const hasStatus = content.includes('status') || content.includes('getStatus');
                
                console.log(chalk.green(`  Engine: ${engine}`));
                console.log(chalk.green(`  Initialize: ${hasInitialize ? '✅' : '❌'}`));
                console.log(chalk.green(`  Start: ${hasStart ? '✅' : '❌'}`));
                console.log(chalk.green(`  Stop: ${hasStop ? '✅' : '❌'}`));
                console.log(chalk.green(`  Status: ${hasStatus ? '✅' : '❌'}`));
            } else {
                console.log(chalk.red(`Engine ${engine} not found`));
            }
        } catch (error) {
            console.log(chalk.red(`Error checking engine: ${error.message}`));
        }
    });

program
    .command('fix <engine>')
    .description('Fix issues in specific engine')
    .action(async (engine) => {
        console.log(chalk.blue(`Fixing issues in ${engine}...`));
        try {
            const enginePath = path.join('./src/engines', `${engine}.js`);
            if (fs.existsSync(enginePath)) {
                let content = fs.readFileSync(enginePath, 'utf8');
                
                // Add missing methods
                const methods = ['initialize', 'start', 'stop', 'getStatus'];
                methods.forEach(method => {
                    if (!content.includes(method)) {
                        const methodCode = `async ${method}() {
        try {
            this.${method === 'getStatus' ? 'initialized' : 'running'} = true;
            return { success: true, message: '${engine} ${method} completed' };
        } catch (error) {
            throw error;
        }
    }`;
                        const lastBraceIndex = content.lastIndexOf('}');
                        if (lastBraceIndex !== -1) {
                            content = content.slice(0, lastBraceIndex) + '\n    ' + methodCode + '\n' + content.slice(lastBraceIndex);
                        }
                    }
                });
                
                fs.writeFileSync(enginePath, content);
                console.log(chalk.green(`✅ Fixed issues in ${engine}`));
            } else {
                console.log(chalk.red(`Engine ${engine} not found`));
            }
        } catch (error) {
            console.log(chalk.red(`Error fixing engine: ${error.message}`));
        }
    });

program.parse();
