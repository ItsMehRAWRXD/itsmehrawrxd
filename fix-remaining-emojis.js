const fs = require('fs').promises;
const path = require('path');

async function fixRemainingEmojis() {
    const files = [
        'examples/irc-bot-builder-usage-examples.js',
        'examples/complete-cli-examples.js',
        'IMPLEMENTATION_SUMMARY.md',
        'ENHANCEMENT_OPPORTUNITIES.md',
        'PROJECT_COMPLETION_REPORT.md',
        'simple-file-analysis.js',
        'EMOJI-REMOVAL-SYSTEM.md'
    ];

    let totalFixed = 0;

    for (const file of files) {
        try {
            const content = await fs.readFile(file, 'utf8');
            // Replace emojis with [INFO] using Unicode ranges
            const newContent = content.replace(/[\u{1F300}-\u{1F9FF}]|[\u{2600}-\u{26FF}]|[\u{2700}-\u{27BF}]/gu, '[INFO]');
            
            if (content !== newContent) {
                await fs.writeFile(file, newContent, 'utf8');
                const count = (content.match(/[\u{1F300}-\u{1F9FF}]|[\u{2600}-\u{26FF}]|[\u{2700}-\u{27BF}]/gu) || []).length;
                totalFixed += count;
                console.log(`Fixed ${count} emojis in ${file}`);
            }
        } catch (error) {
            console.log(`Error processing ${file}: ${error.message}`);
        }
    }

    console.log(`\nTotal emojis fixed: ${totalFixed}`);
}

fixRemainingEmojis().catch(console.error);
