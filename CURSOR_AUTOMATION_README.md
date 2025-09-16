# Cursor Automation Bot

A powerful automation script that automatically clicks "Keep all" when Cursor IDE source is updated, eliminating the need for manual intervention during development.

## 🚀 Features

- **Automatic Detection**: Monitors Cursor IDE for source update dialogs
- **Auto-Click**: Automatically clicks "Keep all" button when updates are detected
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **Configurable**: Customizable delays, retry mechanisms, and behavior
- **Integration Ready**: Integrates with existing bot infrastructure (HTTP, IRC, Discord)
- **Error Handling**: Robust error handling with retry mechanisms
- **Screenshot Capture**: Debug screenshots for troubleshooting
- **Notification System**: Sends notifications when updates are handled

## 📋 Requirements

### Windows
- PowerShell (included with Windows)
- Cursor IDE installed

### macOS
- AppleScript support (included with macOS)
- Cursor IDE installed

### Linux
- `xdotool` package: `sudo apt-get install xdotool` (Ubuntu/Debian)
- `import` command (ImageMagick): `sudo apt-get install imagemagick`
- Cursor IDE installed

## 🛠️ Installation

1. **Clone or download the files**:
   ```bash
   # The following files should be in your project:
   # - src/engines/cursor-automation-bot.js
   # - cursor-automation-runner.js
   # - cursor-automation-config.json
   # - examples/cursor-automation-examples.js
   # - test-cursor-automation.js
   ```

2. **Install dependencies** (if any):
   ```bash
   npm install
   ```

3. **Make the runner executable** (Linux/macOS):
   ```bash
   chmod +x cursor-automation-runner.js
   ```

## 🎯 Quick Start

### Basic Usage

```bash
# Start the automation bot
node cursor-automation-runner.js

# Run in daemon mode (background)
node cursor-automation-runner.js --daemon

# Use custom configuration
node cursor-automation-runner.js --config my-config.json
```

### Programmatic Usage

```javascript
const CursorAutomationBot = require('./src/engines/cursor-automation-bot');

const bot = new CursorAutomationBot({
    autoClickDelay: 1000,
    maxRetries: 3,
    enableLogging: true
});

// Set up event handlers
bot.on('started', () => {
    console.log('Bot started!');
});

bot.on('updateHandled', (data) => {
    if (data.success) {
        console.log('Update handled successfully!');
    } else {
        console.log('Failed to handle update');
    }
});

// Start the bot
await bot.start();
```

## ⚙️ Configuration

The bot can be configured through the `cursor-automation-config.json` file:

```json
{
  "cursorAutomation": {
    "enabled": true,
    "autoClickDelay": 1000,
    "maxRetries": 3,
    "retryDelay": 2000,
    "checkInterval": 5000,
    "enableLogging": true,
    "enableNotifications": true,
    
    "uiSettings": {
      "buttonText": "Keep all",
      "dialogTitle": "Source updated",
      "timeout": 10000,
      "confidence": 0.8
    },
    
    "integration": {
      "enableHTTPBot": true,
      "enableIRCBot": false,
      "enableDiscordBot": false,
      "webhookUrl": "https://your-webhook-url.com",
      "ircChannel": "#cursor-automation"
    }
  }
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable/disable the automation bot |
| `autoClickDelay` | number | `1000` | Delay in milliseconds before clicking |
| `maxRetries` | number | `3` | Maximum number of retry attempts |
| `retryDelay` | number | `2000` | Delay between retry attempts |
| `checkInterval` | number | `5000` | How often to check for updates |
| `enableLogging` | boolean | `true` | Enable console logging |
| `enableNotifications` | boolean | `true` | Enable notification system |

## 🔧 Advanced Usage

### Custom Configuration

```javascript
const customConfig = {
    autoClickDelay: 2000,        // Wait 2 seconds before clicking
    maxRetries: 5,               // Try up to 5 times
    retryDelay: 3000,            // Wait 3 seconds between retries
    checkInterval: 3000,         // Check every 3 seconds
    enableLogging: true,
    enableNotifications: true,
    
    uiSettings: {
        buttonText: 'Keep all',
        dialogTitle: 'Source updated',
        timeout: 15000,          // Wait up to 15 seconds for dialog
        confidence: 0.9          // Higher confidence for button detection
    },
    
    integration: {
        enableHTTPBot: true,
        webhookUrl: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK',
        enableIRCBot: false,
        enableDiscordBot: false
    }
};

const bot = new CursorAutomationBot(customConfig);
```

### Integration with Existing Systems

```javascript
const bot = new CursorAutomationBot({
    integration: {
        enableHTTPBot: true,
        enableIRCBot: true,
        enableDiscordBot: true,
        webhookUrl: 'https://your-webhook-url.com/notifications',
        ircChannel: '#cursor-updates'
    }
});

// Handle IRC messages
bot.on('ircMessage', (data) => {
    console.log(`IRC Message to ${data.channel}: ${data.message}`);
    // Send to your IRC bot system
});

// Handle Discord messages
bot.on('discordMessage', (data) => {
    console.log(`Discord Message to ${data.channel}: ${data.message}`);
    // Send to your Discord bot system
});
```

### Monitoring and Statistics

```javascript
let updateCount = 0;
let successCount = 0;
let failureCount = 0;

bot.on('updateHandled', (data) => {
    updateCount++;
    if (data.success) {
        successCount++;
    } else {
        failureCount++;
    }
    
    console.log(`📊 Statistics:`);
    console.log(`   Total updates: ${updateCount}`);
    console.log(`   Successful: ${successCount}`);
    console.log(`   Failed: ${failureCount}`);
    console.log(`   Success rate: ${((successCount / updateCount) * 100).toFixed(1)}%`);
});

// Periodic status reporting
setInterval(() => {
    const status = bot.getStatus();
    console.log('📈 Bot Status:', status);
}, 30000); // Every 30 seconds
```

## 🧪 Testing

Run the test suite to verify everything is working correctly:

```bash
node test-cursor-automation.js
```

The test suite will verify:
- Bot initialization
- Configuration management
- Platform detection
- Event handling
- Status methods
- Error handling

## 📚 Examples

See the `examples/cursor-automation-examples.js` file for comprehensive usage examples:

- Basic usage
- Custom configuration
- Integration examples
- Platform-specific configuration
- Error handling and recovery
- Monitoring and statistics
- Dynamic configuration updates
- Batch processing
- Testing and validation
- Production deployment

## 🚨 Troubleshooting

### Common Issues

1. **Bot not detecting updates**:
   - Ensure Cursor IDE is running
   - Check that the dialog title matches your Cursor version
   - Verify the button text is correct for your language

2. **Permission errors** (Linux/macOS):
   - Grant accessibility permissions to your terminal/script
   - On macOS: System Preferences > Security & Privacy > Privacy > Accessibility

3. **Button not found**:
   - Check the `buttonText` configuration
   - Verify the dialog is fully loaded before clicking
   - Increase the `autoClickDelay` if needed

4. **High CPU usage**:
   - Increase the `checkInterval` to check less frequently
   - Disable logging if not needed

### Debug Mode

Enable debug logging by setting `enableLogging: true` in your configuration. The bot will:
- Log all automation attempts
- Capture screenshots when dialogs are detected
- Provide detailed error messages

### Screenshots

When debugging is enabled, screenshots are saved to the `temp/` directory:
- `cursor_screenshot.png` - Latest screenshot when dialog is detected

## 🔒 Security Considerations

- The bot only interacts with Cursor IDE windows
- No sensitive data is collected or transmitted
- All automation is local to your machine
- Webhook URLs should use HTTPS
- Consider using environment variables for sensitive configuration

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is part of the RawrZ Security Platform. Please refer to the main project license.

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section
2. Run the test suite to verify setup
3. Check the examples for usage patterns
4. Review the configuration options

## 🔄 Updates

The bot automatically handles Cursor IDE updates. When Cursor updates itself:
1. The bot detects the update dialog
2. Waits for the configured delay
3. Clicks "Keep all" automatically
4. Sends notifications if enabled
5. Continues monitoring for future updates

---

**Note**: This automation bot is designed to work with Cursor IDE's update dialogs. The exact dialog text and behavior may vary between Cursor versions. If you encounter issues, please check the configuration and adjust the `buttonText` and `dialogTitle` settings accordingly.
