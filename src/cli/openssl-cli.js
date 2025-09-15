#!/usr/bin/env node

/**
 * RawrZ OpenSSL Management CLI
 * 
 * Comprehensive command-line interface for managing OpenSSL configurations,
 * testing algorithms, and monitoring performance in the RawrZ Security Platform.
 */

const { Command } = require('commander');
const chalk = require('chalk');
const ora = require('ora');
const Table = require('cli-table3');
const { OpenSSLManagement } = require('../engines/openssl-management');
const { logger } = require('../utils/logger');

class OpenSSLCli {
    constructor() {
        this.program = new Command();
        this.opensslManager = null;
        this.setupCommands();
    }

    setupCommands() {
        this.program
            .name('rawrz-openssl')
            .description('RawrZ OpenSSL Management CLI')
            .version('1.0.0');

        // Status command
        this.program
            .command('status')
            .description('Show OpenSSL management status')
            .option('-v, --verbose', 'Verbose output')
            .action(async (options) => {
                await this.showStatus(options);
            });

        // Toggle commands
        this.program
            .command('toggle')
            .description('Toggle OpenSSL settings')
            .option('-o, --openssl <boolean>', 'Enable/disable OpenSSL mode')
            .option('-c, --custom <boolean>', 'Enable/disable custom algorithms')
            .action(async (options) => {
                await this.toggleSettings(options);
            });

        // Algorithm commands
        this.program
            .command('algorithms')
            .description('List and manage algorithms')
            .option('-f, --filter <type>', 'Filter by type (openssl|custom|all)', 'all')
            .option('-c, --category <category>', 'Filter by category (symmetric|asymmetric|hash|authenticated)')
            .option('-s, --search <term>', 'Search algorithms by name')
            .action(async (options) => {
                await this.listAlgorithms(options);
            });

        // Test command
        this.program
            .command('test')
            .description('Test algorithm performance')
            .requiredOption('-a, --algorithm <algorithm>', 'Algorithm to test')
            .option('-d, --data <data>', 'Test data', 'Hello, RawrZ!')
            .option('-e, --engines <engines>', 'Comma-separated list of engines to test')
            .option('-r, --runs <number>', 'Number of test runs', '1')
            .action(async (options) => {
                await this.testAlgorithm(options);
            });

        // Preset commands
        this.program
            .command('preset')
            .description('Manage configuration presets')
            .option('-l, --list', 'List available presets')
            .option('-a, --apply <preset>', 'Apply a preset')
            .option('-i, --info <preset>', 'Show preset information')
            .action(async (options) => {
                await this.managePresets(options);
            });

        // Performance command
        this.program
            .command('performance')
            .description('Show performance statistics')
            .option('-r, --reset', 'Reset performance data')
            .option('-t, --top <number>', 'Show top N algorithms', '10')
            .action(async (options) => {
                await this.showPerformance(options);
            });

        // Report command
        this.program
            .command('report')
            .description('Generate comprehensive report')
            .option('-o, --output <file>', 'Output file (JSON format)')
            .option('-f, --format <format>', 'Output format (json|text)', 'text')
            .action(async (options) => {
                await this.generateReport(options);
            });

        // Resolve command
        this.program
            .command('resolve')
            .description('Resolve algorithm names')
            .requiredOption('-a, --algorithm <algorithm>', 'Algorithm to resolve')
            .option('-e, --engine <engine>', 'Specific engine to use')
            .action(async (options) => {
                await this.resolveAlgorithm(options);
            });

        // Recommendations command
        this.program
            .command('recommend')
            .description('Get algorithm recommendations')
            .option('-u, --use-case <case>', 'Use case (general|performance|security|compatibility)', 'general')
            .option('-c, --category <category>', 'Specific category to recommend')
            .action(async (options) => {
                await this.getRecommendations(options);
            });

        // Interactive command
        this.program
            .command('interactive')
            .alias('i')
            .description('Start interactive mode')
            .action(async () => {
                await this.startInteractive();
            });
    }

    async initialize() {
        if (!this.opensslManager) {
            const spinner = ora('Initializing OpenSSL Management...').start();
            try {
                this.opensslManager = new OpenSSLManagement();
                await this.opensslManager.initialize();
                spinner.succeed('OpenSSL Management initialized');
            } catch (error) {
                spinner.fail(`Failed to initialize: ${error.message}`);
                throw error;
            }
        }
    }

    async showStatus(options) {
        await this.initialize();
        
        const spinner = ora('Getting status...').start();
        try {
            const status = await this.opensslManager.getStatus();
            spinner.succeed('Status retrieved');

            console.log(chalk.blue.bold('\nRawrZ OpenSSL Management Status\n'));

            // Basic info
            const infoTable = new Table({
                head: ['Property', 'Value'],
                style: { head: ['cyan'] }
            });

            infoTable.push(
                ['Engine', status.engine],
                ['Version', status.version],
                ['Initialized', status.initialized ? 'Yes' : 'No'],
                ['Mode', status.configuration.mode],
                ['Custom Algorithms', status.configuration.customAlgorithms ? 'Enabled' : 'Disabled'],
                ['Auto Fallback', status.configuration.autoFallback ? 'Enabled' : 'Disabled']
            );

            console.log(infoTable.toString());

            // Engines info
            console.log(chalk.blue.bold('\nEngines\n'));
            const enginesTable = new Table({
                head: ['Engine', 'Registered', 'Status'],
                style: { head: ['cyan'] }
            });

            Object.entries(status.engines.status).forEach(([name, engineStatus]) => {
                enginesTable.push([
                    name,
                    engineStatus.registered ? 'Yes' : 'No',
                    engineStatus.registered ? 'Active' : 'Inactive'
                ]);
            });

            console.log(enginesTable.toString());

            // Algorithms info
            console.log(chalk.blue.bold('\n🔢 Algorithms\n'));
            const algorithmsTable = new Table({
                head: ['Type', 'Count'],
                style: { head: ['cyan'] }
            });

            algorithmsTable.push(
                ['Total', status.algorithms.total],
                ['OpenSSL', status.algorithms.openssl],
                ['Custom', status.algorithms.custom],
                ['Categories', status.algorithms.categories]
            );

            console.log(algorithmsTable.toString());

            if (options.verbose) {
                console.log(chalk.blue.bold('\nPerformance\n'));
                const perf = status.performance;
                const perfTable = new Table({
                    head: ['Metric', 'Value'],
                    style: { head: ['cyan'] }
                });

                perfTable.push(
                    ['Total Operations', perf.totalOperations],
                    ['Success Rate', `${perf.successRate.toFixed(2)}%`],
                    ['Avg Encryption Time', `${perf.averageEncryptionTime}ms`],
                    ['Uptime', `${Math.round(perf.uptime / 1000)}s`]
                );

                console.log(perfTable.toString());
            }

        } catch (error) {
            spinner.fail(`Failed to get status: ${error.message}`);
            process.exit(1);
        }
    }

    async toggleSettings(options) {
        await this.initialize();

        if (options.openssl !== undefined) {
            const enabled = options.openssl === 'true' || options.openssl === '1';
            const spinner = ora(`Toggling OpenSSL mode to ${enabled ? 'enabled' : 'disabled'}...`).start();
            
            try {
                await this.opensslManager.toggleOpenSSLMode(enabled);
                spinner.succeed(`OpenSSL mode ${enabled ? 'enabled' : 'disabled'}`);
            } catch (error) {
                spinner.fail(`Failed to toggle OpenSSL mode: ${error.message}`);
                process.exit(1);
            }
        }

        if (options.custom !== undefined) {
            const enabled = options.custom === 'true' || options.custom === '1';
            const spinner = ora(`Toggling custom algorithms to ${enabled ? 'enabled' : 'disabled'}...`).start();
            
            try {
                await this.opensslManager.toggleCustomAlgorithms(enabled);
                spinner.succeed(`Custom algorithms ${enabled ? 'enabled' : 'disabled'}`);
            } catch (error) {
                spinner.fail(`Failed to toggle custom algorithms: ${error.message}`);
                process.exit(1);
            }
        }

        if (options.openssl === undefined && options.custom === undefined) {
            console.log(chalk.red('Please specify --openssl or --custom option'));
            process.exit(1);
        }
    }

    async listAlgorithms(options) {
        await this.initialize();

        const spinner = ora('Loading algorithms...').start();
        try {
            const status = await this.opensslManager.getStatus();
            spinner.succeed('Algorithms loaded');

            let algorithms = [];
            const filter = options.filter || 'all';

            switch (filter) {
                case 'openssl':
                    algorithms = status.algorithms.openssl || [];
                    break;
                case 'custom':
                    algorithms = status.algorithms.custom || [];
                    break;
                default:
                    algorithms = status.algorithms.all || [];
            }

            if (options.search) {
                algorithms = algorithms.filter(alg => 
                    alg.toLowerCase().includes(options.search.toLowerCase())
                );
            }

            console.log(chalk.blue.bold(`\n🔢 Available Algorithms (${filter})\n`));

            if (algorithms.length === 0) {
                console.log(chalk.yellow('No algorithms found'));
                return;
            }

            const table = new Table({
                head: ['#', 'Algorithm', 'Type'],
                style: { head: ['cyan'] }
            });

            algorithms.forEach((algorithm, index) => {
                const isOpenSSL = (status.algorithms.openssl || []).includes(algorithm);
                const isCustom = (status.algorithms.custom || []).includes(algorithm);
                
                let type = '';
                if (isOpenSSL) type = chalk.green('OpenSSL');
                else if (isCustom) type = chalk.yellow('Custom');
                else type = chalk.gray('Unknown');

                table.push([
                    (index + 1).toString().padStart(3),
                    algorithm,
                    type
                ]);
            });

            console.log(table.toString());
            console.log(chalk.gray(`\nTotal: ${algorithms.length} algorithms`));

        } catch (error) {
            spinner.fail(`Failed to list algorithms: ${error.message}`);
            process.exit(1);
        }
    }

    async testAlgorithm(options) {
        await this.initialize();

        const spinner = ora(`Testing algorithm: ${options.algorithm}...`).start();
        try {
            const result = await this.opensslManager.testAlgorithm(options.algorithm, options.data);
            spinner.succeed('Algorithm test completed');

            console.log(chalk.blue.bold(`\n🧪 Algorithm Test Results: ${options.algorithm}\n`));

            const table = new Table({
                head: ['Engine', 'Success', 'Duration (ms)', 'Key Size (bits)', 'IV Size (bits)'],
                style: { head: ['cyan'] }
            });

            Object.entries(result.results).forEach(([engineName, engineResult]) => {
                table.push([
                    engineName,
                    engineResult.success ? chalk.green('Success') : chalk.red('Failed'),
                    engineResult.duration || 0,
                    engineResult.keySize || 0,
                    engineResult.ivSize || 0
                ]);
            });

            console.log(table.toString());

            console.log(chalk.blue.bold('\nSummary\n'));
            console.log(`Total Engines: ${result.summary.totalEngines}`);
            console.log(`Successful: ${chalk.green(result.summary.successful)}`);
            console.log(`Failed: ${chalk.red(result.summary.failed)}`);

        } catch (error) {
            spinner.fail(`Failed to test algorithm: ${error.message}`);
            process.exit(1);
        }
    }

    async managePresets(options) {
        await this.initialize();

        if (options.list) {
            const spinner = ora('Loading presets...').start();
            try {
                const status = await this.opensslManager.getStatus();
                spinner.succeed('Presets loaded');

                console.log(chalk.blue.bold('\nAvailable Presets\n'));

                const presets = status.configurations.presets || [];
                const table = new Table({
                    head: ['Preset', 'Description'],
                    style: { head: ['cyan'] }
                });

                const presetDescriptions = {
                    'high-security': 'Maximum security with OpenSSL-only algorithms',
                    'compatibility': 'Balanced security and compatibility',
                    'performance': 'Optimized for speed and efficiency',
                    'experimental': 'Custom algorithms and experimental features'
                };

                presets.forEach(preset => {
                    table.push([
                        preset,
                        presetDescriptions[preset] || 'Custom configuration'
                    ]);
                });

                console.log(table.toString());

            } catch (error) {
                spinner.fail(`Failed to list presets: ${error.message}`);
                process.exit(1);
            }
        }

        if (options.apply) {
            const spinner = ora(`Applying preset: ${options.apply}...`).start();
            try {
                const result = await this.opensslManager.applyPreset(options.apply);
                spinner.succeed(`Preset ${options.apply} applied successfully`);

                console.log(chalk.green.bold('\nPreset Applied\n'));
                console.log(`Preset: ${result.preset}`);
                console.log(`Configuration: ${JSON.stringify(result.configuration, null, 2)}`);

            } catch (error) {
                spinner.fail(`Failed to apply preset: ${error.message}`);
                process.exit(1);
            }
        }

        if (options.info) {
            const spinner = ora(`Getting preset info: ${options.info}...`).start();
            try {
                const status = await this.opensslManager.getStatus();
                const presets = status.configurations.presets || [];
                
                if (!presets.includes(options.info)) {
                    spinner.fail(`Preset ${options.info} not found`);
                    process.exit(1);
                }

                spinner.succeed('Preset info retrieved');
                console.log(chalk.blue.bold(`\nPreset Information: ${options.info}\n`));
                console.log('This preset configuration will be applied when selected.');

            } catch (error) {
                spinner.fail(`Failed to get preset info: ${error.message}`);
                process.exit(1);
            }
        }

        if (!options.list && !options.apply && !options.info) {
            console.log(chalk.red('Please specify --list, --apply, or --info option'));
            process.exit(1);
        }
    }

    async showPerformance(options) {
        await this.initialize();

        if (options.reset) {
            const spinner = ora('Resetting performance data...').start();
            try {
                this.opensslManager.resetPerformanceData();
                spinner.succeed('Performance data reset');
                return;
            } catch (error) {
                spinner.fail(`Failed to reset performance data: ${error.message}`);
                process.exit(1);
            }
        }

        const spinner = ora('Loading performance data...').start();
        try {
            const performance = this.opensslManager.getPerformanceStats();
            spinner.succeed('Performance data loaded');

            console.log(chalk.blue.bold('\nPerformance Statistics\n'));

            const statsTable = new Table({
                head: ['Metric', 'Value'],
                style: { head: ['cyan'] }
            });

            statsTable.push(
                ['Total Operations', performance.totalOperations],
                ['Successful Operations', performance.successfulOperations],
                ['Failed Operations', performance.failedOperations],
                ['Success Rate', `${performance.successRate.toFixed(2)}%`],
                ['Average Encryption Time', `${performance.averageEncryptionTime}ms`],
                ['Median Encryption Time', `${performance.medianEncryptionTime}ms`],
                ['Min Encryption Time', `${performance.minEncryptionTime}ms`],
                ['Max Encryption Time', `${performance.maxEncryptionTime}ms`],
                ['Uptime', `${Math.round(performance.uptime / 1000)}s`]
            );

            console.log(statsTable.toString());

            // Top algorithms
            if (Object.keys(performance.algorithmUsage).length > 0) {
                console.log(chalk.blue.bold('\nTop Algorithms\n'));

                const topAlgorithms = Object.entries(performance.algorithmUsage)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, parseInt(options.top) || 10);

                const topTable = new Table({
                    head: ['Rank', 'Algorithm', 'Usage Count'],
                    style: { head: ['cyan'] }
                });

                topAlgorithms.forEach(([algorithm, count], index) => {
                    topTable.push([
                        (index + 1).toString(),
                        algorithm,
                        count.toString()
                    ]);
                });

                console.log(topTable.toString());
            }

        } catch (error) {
            spinner.fail(`Failed to load performance data: ${error.message}`);
            process.exit(1);
        }
    }

    async generateReport(options) {
        await this.initialize();

        const spinner = ora('Generating comprehensive report...').start();
        try {
            const report = await this.opensslManager.generateReport();
            spinner.succeed('Report generated');

            if (options.format === 'json') {
                const output = JSON.stringify(report, null, 2);
                
                if (options.output) {
                    const fs = require('fs');
                    fs.writeFileSync(options.output, output);
                    console.log(chalk.green(`Report saved to: ${options.output}`));
                } else {
                    console.log(output);
                }
            } else {
                console.log(chalk.blue.bold('\n📋 RawrZ OpenSSL Management Report\n'));
                console.log(`Generated: ${report.timestamp}`);
                console.log(`Engine: ${report.engine} v${report.version}`);
                console.log(`Total Algorithms: ${report.summary.totalAlgorithms}`);
                console.log(`Active Engines: ${report.summary.activeEngines}`);
                console.log(`Success Rate: ${report.summary.successRate.toFixed(2)}%`);
                console.log(`Average Performance: ${report.summary.averagePerformance}ms`);
                console.log(`Configuration: ${report.summary.configuration}`);

                if (options.output) {
                    const fs = require('fs');
                    fs.writeFileSync(options.output, JSON.stringify(report, null, 2));
                    console.log(chalk.green(`\nReport saved to: ${options.output}`));
                }
            }

        } catch (error) {
            spinner.fail(`Failed to generate report: ${error.message}`);
            process.exit(1);
        }
    }

    async resolveAlgorithm(options) {
        await this.initialize();

        const spinner = ora(`Resolving algorithm: ${options.algorithm}...`).start();
        try {
            const result = await this.opensslManager.resolveAlgorithm(options.algorithm);
            spinner.succeed('Algorithm resolved');

            console.log(chalk.blue.bold(`\n🔄 Algorithm Resolution: ${options.algorithm}\n`));

            const table = new Table({
                head: ['Context', 'Resolved Algorithm'],
                style: { head: ['cyan'] }
            });

            table.push(['Original', result.original]);
            table.push(['Manager', result.manager]);

            Object.entries(result.engines).forEach(([engine, resolved]) => {
                table.push([engine, resolved]);
            });

            console.log(table.toString());

            if (result.consistent) {
                console.log(chalk.green('\nAll engines resolve consistently'));
            } else {
                console.log(chalk.yellow('\nEngines resolve differently'));
            }

        } catch (error) {
            spinner.fail(`Failed to resolve algorithm: ${error.message}`);
            process.exit(1);
        }
    }

    async getRecommendations(options) {
        await this.initialize();

        const spinner = ora(`Getting recommendations for ${options.useCase}...`).start();
        try {
            const recommendations = await this.opensslManager.getAlgorithmRecommendations(options.useCase);
            spinner.succeed('Recommendations retrieved');

            console.log(chalk.blue.bold(`\nAlgorithm Recommendations: ${options.useCase}\n`));

            if (options.category) {
                const categoryRecs = recommendations.recommendations[options.category];
                if (categoryRecs && categoryRecs.length > 0) {
                    console.log(chalk.cyan.bold(`${options.category.toUpperCase()} ALGORITHMS\n`));
                    categoryRecs.forEach((alg, index) => {
                        console.log(`${(index + 1).toString().padStart(2)}. ${alg}`);
                    });
                } else {
                    console.log(chalk.yellow(`No recommendations for category: ${options.category}`));
                }
            } else {
                Object.entries(recommendations.recommendations).forEach(([category, algs]) => {
                    if (algs.length > 0) {
                        console.log(chalk.cyan.bold(`${category.toUpperCase()}\n`));
                        algs.forEach((alg, index) => {
                            console.log(`${(index + 1).toString().padStart(2)}. ${alg}`);
                        });
                        console.log();
                    }
                });
            }

            console.log(chalk.gray(`Total recommendations: ${recommendations.total}`));

        } catch (error) {
            spinner.fail(`Failed to get recommendations: ${error.message}`);
            process.exit(1);
        }
    }

    async startInteractive() {
        await this.initialize();

        console.log(chalk.blue.bold('\nRawrZ OpenSSL Management - Interactive Mode\n'));
        console.log('Type "help" for available commands or "exit" to quit.\n');

        const readline = require('readline');
        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout,
            prompt: chalk.cyan('openssl> ')
        });

        rl.prompt();

        rl.on('line', async (line) => {
            const input = line.trim();
            
            if (input === 'exit' || input === 'quit') {
                console.log(chalk.green('Goodbye!'));
                rl.close();
                return;
            }

            if (input === 'help') {
                console.log(chalk.blue.bold('\nAvailable Commands:\n'));
                console.log('  status          - Show current status');
                console.log('  algorithms      - List available algorithms');
                console.log('  test <alg>      - Test an algorithm');
                console.log('  presets         - List available presets');
                console.log('  performance     - Show performance stats');
                console.log('  report          - Generate report');
                console.log('  help            - Show this help');
                console.log('  exit/quit       - Exit interactive mode\n');
                rl.prompt();
                return;
            }

            try {
                const args = input.split(' ');
                const command = args[0];

                switch (command) {
                    case 'status':
                        await this.showStatus({ verbose: false });
                        break;
                    case 'algorithms':
                        await this.listAlgorithms({ filter: 'all' });
                        break;
                    case 'test':
                        if (args[1]) {
                            await this.testAlgorithm({ algorithm: args[1], data: 'test-data' });
                        } else {
                            console.log(chalk.red('Please specify an algorithm to test'));
                        }
                        break;
                    case 'presets':
                        await this.managePresets({ list: true });
                        break;
                    case 'performance':
                        await this.showPerformance({});
                        break;
                    case 'report':
                        await this.generateReport({ format: 'text' });
                        break;
                    default:
                        console.log(chalk.red(`Unknown command: ${command}`));
                        console.log('Type "help" for available commands');
                }
            } catch (error) {
                console.log(chalk.red(`Error: ${error.message}`));
            }

            rl.prompt();
        });

        rl.on('close', () => {
            process.exit(0);
        });
    }

    async run() {
        try {
            await this.program.parseAsync(process.argv);
        } catch (error) {
            console.error(chalk.red(`Error: ${error.message}`));
            process.exit(1);
        }
    }
}

// Run the CLI
if (require.main === module) {
    const cli = new OpenSSLCli();
    cli.run().catch(error => {
        console.error(chalk.red(`CLI Error: ${error.message}`));
        process.exit(1);
    });
}

module.exports = { OpenSSLCli };
