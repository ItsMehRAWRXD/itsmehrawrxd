#!/usr/bin/env node

const readline = require('readline');
const axios = require('axios');
const fs = require('fs');
const path = require('path');

class PayloadCLI {
    constructor() {
        this.baseUrl = process.env.RAWRZ_API_URL || 'http://localhost:8080';
        this.rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });
        this.currentPayload = null;
    }

    async start() {
        console.log('\n🔧 RawrZ Payload CLI Manager');
        console.log('=====================================');
        console.log('Type "help" for available commands\n');
        
        await this.showMainMenu();
    }

    async showMainMenu() {
        const menu = `
📋 Main Menu:
1. List all payloads
2. Create new payload
3. Edit payload
4. Delete payload
5. Duplicate payload
6. Use payload
7. Export payloads
8. Initialize defaults
9. Clear all payloads
10. Show status
0. Exit

Enter your choice (0-10): `;

        const choice = await this.ask(menu);
        
        switch (choice.trim()) {
            case '1':
                await this.listPayloads();
                break;
            case '2':
                await this.createPayload();
                break;
            case '3':
                await this.editPayload();
                break;
            case '4':
                await this.deletePayload();
                break;
            case '5':
                await this.duplicatePayload();
                break;
            case '6':
                await this.usePayload();
                break;
            case '7':
                await this.exportPayloads();
                break;
            case '8':
                await this.initializeDefaults();
                break;
            case '9':
                await this.clearAllPayloads();
                break;
            case '10':
                await this.showStatus();
                break;
            case '0':
                console.log('\n👋 Goodbye!');
                this.rl.close();
                return;
            default:
                console.log('\n❌ Invalid choice. Please try again.');
                await this.showMainMenu();
        }
    }

    async ask(question) {
        return new Promise((resolve) => {
            this.rl.question(question, resolve);
        });
    }

    async makeRequest(method, endpoint, data = null) {
        try {
            const config = {
                method,
                url: `${this.baseUrl}${endpoint}`,
                headers: {
                    'Content-Type': 'application/json'
                }
            };

            if (data) {
                config.data = data;
            }

            const response = await axios(config);
            return response.data;
        } catch (error) {
            if (error.response) {
                throw new Error(`API Error: ${error.response.data.error || error.response.statusText}`);
            } else if (error.request) {
                throw new Error('Network Error: Unable to connect to RawrZ server');
            } else {
                throw new Error(`Error: ${error.message}`);
            }
        }
    }

    async listPayloads() {
        console.log('\n📋 Loading payloads...\n');
        
        try {
            const data = await this.makeRequest('GET', '/payload-manager/payloads');
            
            if (data.success && data.payloads.length > 0) {
                console.log(`Found ${data.payloads.length} payloads:\n`);
                
                data.payloads.forEach((payload, index) => {
                    console.log(`${index + 1}. ${payload.name}`);
                    console.log(`   ID: ${payload.id}`);
                    console.log(`   Type: ${payload.type}`);
                    console.log(`   Description: ${payload.description || 'No description'}`);
                    console.log(`   Created: ${new Date(payload.createdAt).toLocaleString()}`);
                    console.log(`   Updated: ${new Date(payload.updatedAt).toLocaleString()}`);
                    console.log(`   Config: ${JSON.stringify(payload.config, null, 2)}`);
                    console.log('');
                });
            } else {
                console.log('No payloads found. Create your first payload!\n');
            }
        } catch (error) {
            console.log(`❌ Error: ${error.message}\n`);
        }
        
        await this.showMainMenu();
    }

    async createPayload() {
        console.log('\n🆕 Create New Payload\n');
        
        try {
            const name = await this.ask('Payload name: ');
            if (!name.trim()) {
                console.log('❌ Name is required\n');
                await this.showMainMenu();
                return;
            }

            const type = await this.ask('Payload type (beaconism/red-shell/hot-patch/stub-generator/irc-bot/http-bot/crypto/network/generic): ');
            if (!type.trim()) {
                console.log('❌ Type is required\n');
                await this.showMainMenu();
                return;
            }

            const description = await this.ask('Description (optional): ');
            
            console.log('\nConfiguration (JSON format, or press Enter for empty):');
            const configText = await this.ask('Config: ');
            
            let config = {};
            if (configText.trim()) {
                try {
                    config = JSON.parse(configText);
                } catch (error) {
                    console.log('❌ Invalid JSON format\n');
                    await this.showMainMenu();
                    return;
                }
            }

            const payloadData = {
                name: name.trim(),
                type: type.trim(),
                description: description.trim(),
                config
            };

            console.log('\n⏳ Creating payload...');
            const data = await this.makeRequest('POST', '/payload-manager/create', payloadData);
            
            if (data.success) {
                console.log(`✅ Payload "${data.payload.name}" created successfully!`);
                console.log(`   ID: ${data.payload.id}\n`);
            } else {
                console.log(`❌ Error: ${data.error}\n`);
            }
        } catch (error) {
            console.log(`❌ Error: ${error.message}\n`);
        }
        
        await this.showMainMenu();
    }

    async editPayload() {
        console.log('\n✏️ Edit Payload\n');
        
        try {
            const payloads = await this.makeRequest('GET', '/payload-manager/payloads');
            
            if (!payloads.success || payloads.payloads.length === 0) {
                console.log('❌ No payloads found to edit\n');
                await this.showMainMenu();
                return;
            }

            console.log('Available payloads:');
            payloads.payloads.forEach((payload, index) => {
                console.log(`${index + 1}. ${payload.name} (${payload.type})`);
            });

            const choice = await this.ask('\nEnter payload number to edit: ');
            const index = parseInt(choice) - 1;
            
            if (index < 0 || index >= payloads.payloads.length) {
                console.log('❌ Invalid payload number\n');
                await this.showMainMenu();
                return;
            }

            const payload = payloads.payloads[index];
            
            const newName = await this.ask(`New name (current: ${payload.name}): `);
            const newDescription = await this.ask(`New description (current: ${payload.description || 'None'}): `);
            
            const updates = {};
            if (newName.trim()) updates.name = newName.trim();
            if (newDescription.trim()) updates.description = newDescription.trim();
            
            if (Object.keys(updates).length === 0) {
                console.log('❌ No changes provided\n');
                await this.showMainMenu();
                return;
            }

            console.log('\n⏳ Updating payload...');
            const data = await this.makeRequest('PUT', `/payload-manager/update/${payload.id}`, updates);
            
            if (data.success) {
                console.log(`✅ Payload updated successfully!\n`);
            } else {
                console.log(`❌ Error: ${data.error}\n`);
            }
        } catch (error) {
            console.log(`❌ Error: ${error.message}\n`);
        }
        
        await this.showMainMenu();
    }

    async deletePayload() {
        console.log('\n🗑️ Delete Payload\n');
        
        try {
            const payloads = await this.makeRequest('GET', '/payload-manager/payloads');
            
            if (!payloads.success || payloads.payloads.length === 0) {
                console.log('❌ No payloads found to delete\n');
                await this.showMainMenu();
                return;
            }

            console.log('Available payloads:');
            payloads.payloads.forEach((payload, index) => {
                console.log(`${index + 1}. ${payload.name} (${payload.type})`);
            });

            const choice = await this.ask('\nEnter payload number to delete: ');
            const index = parseInt(choice) - 1;
            
            if (index < 0 || index >= payloads.payloads.length) {
                console.log('❌ Invalid payload number\n');
                await this.showMainMenu();
                return;
            }

            const payload = payloads.payloads[index];
            const confirm = await this.ask(`Are you sure you want to delete "${payload.name}"? (yes/no): `);
            
            if (confirm.toLowerCase() !== 'yes') {
                console.log('❌ Deletion cancelled\n');
                await this.showMainMenu();
                return;
            }

            console.log('\n⏳ Deleting payload...');
            const data = await this.makeRequest('DELETE', `/payload-manager/delete/${payload.id}`);
            
            if (data.success) {
                console.log(`✅ Payload deleted successfully!\n`);
            } else {
                console.log(`❌ Error: ${data.error}\n`);
            }
        } catch (error) {
            console.log(`❌ Error: ${error.message}\n`);
        }
        
        await this.showMainMenu();
    }

    async duplicatePayload() {
        console.log('\n📋 Duplicate Payload\n');
        
        try {
            const payloads = await this.makeRequest('GET', '/payload-manager/payloads');
            
            if (!payloads.success || payloads.payloads.length === 0) {
                console.log('❌ No payloads found to duplicate\n');
                await this.showMainMenu();
                return;
            }

            console.log('Available payloads:');
            payloads.payloads.forEach((payload, index) => {
                console.log(`${index + 1}. ${payload.name} (${payload.type})`);
            });

            const choice = await this.ask('\nEnter payload number to duplicate: ');
            const index = parseInt(choice) - 1;
            
            if (index < 0 || index >= payloads.payloads.length) {
                console.log('❌ Invalid payload number\n');
                await this.showMainMenu();
                return;
            }

            const payload = payloads.payloads[index];
            const newName = await this.ask(`Enter name for duplicated payload: `);
            
            if (!newName.trim()) {
                console.log('❌ Name is required\n');
                await this.showMainMenu();
                return;
            }

            console.log('\n⏳ Duplicating payload...');
            const data = await this.makeRequest('POST', `/payload-manager/duplicate/${payload.id}`, { newName: newName.trim() });
            
            if (data.success) {
                console.log(`✅ Payload duplicated successfully!`);
                console.log(`   New ID: ${data.payload.id}\n`);
            } else {
                console.log(`❌ Error: ${data.error}\n`);
            }
        } catch (error) {
            console.log(`❌ Error: ${error.message}\n`);
        }
        
        await this.showMainMenu();
    }

    async usePayload() {
        console.log('\n🎯 Use Payload\n');
        
        try {
            const payloads = await this.makeRequest('GET', '/payload-manager/payloads');
            
            if (!payloads.success || payloads.payloads.length === 0) {
                console.log('❌ No payloads found to use\n');
                await this.showMainMenu();
                return;
            }

            console.log('Available payloads:');
            payloads.payloads.forEach((payload, index) => {
                console.log(`${index + 1}. ${payload.name} (${payload.type})`);
            });

            const choice = await this.ask('\nEnter payload number to use: ');
            const index = parseInt(choice) - 1;
            
            if (index < 0 || index >= payloads.payloads.length) {
                console.log('❌ Invalid payload number\n');
                await this.showMainMenu();
                return;
            }

            const payload = payloads.payloads[index];
            
            console.log('\n⏳ Activating payload...');
            const data = await this.makeRequest('POST', `/payload-manager/use/${payload.id}`);
            
            if (data.success) {
                this.currentPayload = payload;
                console.log(`✅ Payload "${payload.name}" is now active!\n`);
            } else {
                console.log(`❌ Error: ${data.error}\n`);
            }
        } catch (error) {
            console.log(`❌ Error: ${error.message}\n`);
        }
        
        await this.showMainMenu();
    }

    async exportPayloads() {
        console.log('\n📤 Export Payloads\n');
        
        try {
            const format = await this.ask('Export format (json/csv): ');
            
            if (!['json', 'csv'].includes(format.toLowerCase())) {
                console.log('❌ Invalid format. Use "json" or "csv"\n');
                await this.showMainMenu();
                return;
            }

            console.log('\n⏳ Exporting payloads...');
            const data = await this.makeRequest('GET', `/payload-manager/export?format=${format}`);
            
            if (data.success) {
                const filename = `payloads_${new Date().toISOString().split('T')[0]}.${format}`;
                const filepath = path.join(process.cwd(), filename);
                
                fs.writeFileSync(filepath, data.data);
                console.log(`✅ Payloads exported to: ${filepath}\n`);
            } else {
                console.log(`❌ Error: ${data.error}\n`);
            }
        } catch (error) {
            console.log(`❌ Error: ${error.message}\n`);
        }
        
        await this.showMainMenu();
    }

    async initializeDefaults() {
        console.log('\n🔧 Initialize Default Payloads\n');
        
        const confirm = await this.ask('This will create default payloads. Continue? (yes/no): ');
        
        if (confirm.toLowerCase() !== 'yes') {
            console.log('❌ Operation cancelled\n');
            await this.showMainMenu();
            return;
        }

        try {
            console.log('\n⏳ Initializing default payloads...');
            const data = await this.makeRequest('POST', '/payload-manager/initialize-defaults');
            
            if (data.success) {
                console.log('✅ Default payloads initialized successfully!\n');
            } else {
                console.log(`❌ Error: ${data.error}\n`);
            }
        } catch (error) {
            console.log(`❌ Error: ${error.message}\n`);
        }
        
        await this.showMainMenu();
    }

    async clearAllPayloads() {
        console.log('\n🗑️ Clear All Payloads\n');
        
        const confirm = await this.ask('This will delete ALL payloads. This action cannot be undone. Continue? (yes/no): ');
        
        if (confirm.toLowerCase() !== 'yes') {
            console.log('❌ Operation cancelled\n');
            await this.showMainMenu();
            return;
        }

        try {
            console.log('\n⏳ Clearing all payloads...');
            const data = await this.makeRequest('DELETE', '/payload-manager/clear-all');
            
            if (data.success) {
                console.log('✅ All payloads cleared successfully!\n');
            } else {
                console.log(`❌ Error: ${data.error}\n`);
            }
        } catch (error) {
            console.log(`❌ Error: ${error.message}\n`);
        }
        
        await this.showMainMenu();
    }

    async showStatus() {
        console.log('\n📊 Payload Manager Status\n');
        
        try {
            const data = await this.makeRequest('GET', '/payload-manager/status');
            
            if (data.success) {
                const status = data.status;
                console.log(`Status: ${status.status}`);
                console.log(`Initialized: ${status.initialized ? 'Yes' : 'No'}`);
                console.log(`Total Payloads: ${status.payloadCount}`);
                console.log(`Payload Types: ${status.payloadTypes.join(', ')}`);
                console.log(`Last Updated: ${status.lastUpdated ? new Date(status.lastUpdated).toLocaleString() : 'Never'}`);
                
                if (this.currentPayload) {
                    console.log(`\nCurrent Active Payload: ${this.currentPayload.name} (${this.currentPayload.type})`);
                } else {
                    console.log('\nNo active payload');
                }
            } else {
                console.log(`❌ Error: ${data.error}\n`);
            }
        } catch (error) {
            console.log(`❌ Error: ${error.message}\n`);
        }
        
        await this.showMainMenu();
    }
}

// Start the CLI if this file is run directly
if (require.main === module) {
    const cli = new PayloadCLI();
    cli.start().catch(console.error);
}

module.exports = PayloadCLI;
