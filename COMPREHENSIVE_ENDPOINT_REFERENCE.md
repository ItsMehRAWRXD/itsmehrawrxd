# RawrZ Comprehensive Endpoint Reference

## All 294 Endpoints Organized by Category

### 1. Health & Status (5 endpoints)
- `GET /health` - System health check
- `GET /` - Main panel (serves panel.html)
- `GET /health-monitor/status` - Health monitor status
- `POST /health-monitor/toggle` - Toggle health monitoring
- `POST /health-monitor/interval` - Set monitoring interval

### 2. API Endpoints (38 endpoints)

#### Core API
- `GET /api/health` - API health check
- `GET /api/status` - API status
- `GET /api/algorithms` - Available algorithms
- `GET /api/engines` - Available engines
- `GET /api/features` - Available features
- `POST /api/rebuild` - Rebuild system

#### IRC API
- `GET /api/irc/channels` - IRC channels
- `POST /api/irc/connect` - Connect to IRC
- `POST /api/irc/disconnect` - Disconnect from IRC
- `POST /api/irc/join` - Join IRC channel
- `POST /api/irc/leave` - Leave IRC channel
- `POST /api/irc/message` - Send IRC message

#### Crypto API
- `GET /api/crypto/algorithms` - Crypto algorithms
- `GET /api/crypto/modes` - Crypto modes
- `GET /api/crypto/key-sizes` - Key sizes
- `POST /api/crypto/test-algorithm` - Test algorithm
- `POST /api/crypto/generate-report` - Generate crypto report

#### Bot API
- `GET /api/bots/languages` - Bot languages
- `GET /api/bots/features` - Bot features
- `GET /api/bots/templates` - Bot templates

#### Analysis API
- `GET /api/analysis/tools` - Analysis tools
- `GET /api/analysis/engines` - Analysis engines
- `POST /api/analysis/malware` - Malware analysis
- `POST /api/analysis/digital-forensics` - Digital forensics
- `POST /api/analysis/network` - Network analysis
- `POST /api/analysis/reverse-engineering` - Reverse engineering

#### Compile API
- `GET /api/compile/languages` - Compile languages
- `GET /api/compile/targets` - Compile targets

#### Dashboard API
- `GET /api/dashboard/stats` - Dashboard statistics

#### Security API
- `POST /api/security/scan` - Security scan
- `POST /api/security/fud-analysis` - FUD analysis
- `POST /api/security/vulnerability-check` - Vulnerability check
- `POST /api/security/threat-detection` - Threat detection
- `POST /api/security/stealth-mode` - Stealth mode
- `POST /api/security/anti-detection` - Anti-detection

### 3. Panel Routes (5 endpoints)
- `GET /panel` - Main panel
- `GET /irc-bot-builder` - IRC bot builder panel
- `GET /http-bot-panel` - HTTP bot panel
- `GET /stub-generator-panel` - Stub generator panel
- `GET /health-dashboard` - Health dashboard
- `GET /health-monitor/dashboard` - Health monitor dashboard

### 4. Bot Generation (54 endpoints)

#### Bot Management
- `GET /bot-manager` - Bot manager panel
- `GET /api/bots/status` - Bot status
- `GET /bot/heartbeat` - Bot heartbeat
- `GET /bot/commands/:botId` - Bot commands
- `GET /bot/status` - Bot status

#### HTTP Bot
- `GET /http-bot/templates` - HTTP bot templates
- `GET /http-bot/features` - HTTP bot features
- `GET /http-bot/status` - HTTP bot status
- `GET /http-bot/logs/:botId` - HTTP bot logs
- `GET /http-bot/data/:botId` - HTTP bot data
- `GET /http-bot/browser-data/:botId` - Browser data
- `GET /http-bot/crypto-wallets/:botId` - Crypto wallets
- `GET /http-bot/processes/:botId` - Processes
- `GET /http-bot/files/:botId` - Files
- `GET /http-bot/system-info/:botId` - System info
- `POST /http-bot/generate` - Generate HTTP bot
- `POST /http-bot/test` - Test HTTP bot
- `POST /http-bot/compile` - Compile HTTP bot
- `POST /http-bot/connect` - Connect HTTP bot
- `POST /http-bot/disconnect` - Disconnect HTTP bot
- `POST /http-bot/command` - Send command
- `POST /http-bot/heartbeat` - Heartbeat
- `POST /http-bot/exfiltrate` - Exfiltrate data
- `POST /http-bot/stop-exfiltration` - Stop exfiltration
- `POST /http-bot/download/:botId` - Download from bot
- `POST /http-bot/upload/:botId` - Upload to bot
- `POST /http-bot/screenshot/:botId` - Take screenshot
- `POST /http-bot/keylog/:botId` - Keylog
- `POST /http-bot/webcam/:botId` - Webcam capture
- `POST /http-bot/audio/:botId` - Audio capture

#### IRC Bot
- `GET /irc-bot/burner-status` - Burner status
- `GET /irc-bot/fud-score` - FUD score
- `GET /irc-bot/templates` - IRC bot templates
- `GET /irc-bot/features` - IRC bot features
- `GET /irc-bot/custom-features/:featureName` - Custom features
- `GET /irc-bot/custom-features` - All custom features
- `GET /irc-bot/feature-templates/:templateName` - Feature templates
- `GET /irc-bot/feature-templates` - All feature templates
- `POST /irc-bot/generate` - Generate IRC bot
- `POST /irc-bot/generate-stub` - Generate stub
- `POST /irc-bot/encrypt-stub` - Encrypt stub
- `POST /irc-bot/save-encrypted-stub` - Save encrypted stub
- `POST /irc-bot/burn-encrypt` - Burn encrypt
- `POST /irc-bot/generate-burner-stub` - Generate burner stub
- `POST /irc-bot/generate-fud-stub` - Generate FUD stub
- `POST /irc-bot/test` - Test IRC bot
- `POST /irc-bot/compile` - Compile IRC bot
- `POST /irc-bot/custom-features/add` - Add custom feature
- `POST /irc-bot/feature-templates/create` - Create feature template
- `PUT /irc-bot/custom-features/update/:featureName` - Update custom feature
- `DELETE /irc-bot/custom-features/remove/:featureName` - Remove custom feature
- `DELETE /irc-bot/feature-templates/:templateName` - Delete feature template

### 5. Analysis (35 endpoints)

#### Jotti Scanner
- `GET /jotti/info` - Jotti info
- `GET /jotti/test-connection` - Test connection
- `GET /jotti/active-scans` - Active scans
- `GET /jotti/scan-history` - Scan history
- `GET /jotti/scan-status/:jobId` - Scan status
- `POST /jotti/scan` - Scan file
- `POST /jotti/scan-multiple` - Scan multiple files
- `POST /jotti/cancel-scan` - Cancel scan

#### Private Scanner
- `GET /private-scanner/queue-status` - Queue status
- `GET /private-scanner/engines` - Scanner engines
- `GET /private-scanner/stats` - Scanner stats
- `GET /private-scanner/result/:scanId` - Scan result
- `GET /private-scanner/history` - Scan history
- `POST /private-scanner/scan` - Scan file
- `POST /private-scanner/queue` - Queue scan
- `POST /private-scanner/cancel/:scanId` - Cancel scan
- `POST /private-scanner/clear-queue` - Clear queue
- `POST /private-scanner/queue-settings` - Queue settings

#### Analysis Tools
- `POST /analyze` - General analysis
- `POST /portscan` - Port scan
- `POST /mobile-scan` - Mobile scan
- `POST /forensics-scan` - Forensics scan
- `POST /network-scan` - Network scan
- `POST /vulnerability-scan` - Vulnerability scan
- `POST /security-scan` - Security scan
- `POST /malware-scan` - Malware scan
- `POST /app-analysis` - App analysis
- `POST /device-forensics` - Device forensics
- `POST /behavior-analysis` - Behavior analysis
- `POST /signature-check` - Signature check
- `POST /data-recovery` - Data recovery
- `POST /disassembly` - Disassembly
- `POST /decompilation` - Decompilation
- `POST /string-extraction` - String extraction
- `POST /memory-analysis` - Memory analysis
- `POST /process-dump` - Process dump
- `POST /heap-analysis` - Heap analysis

### 6. Security (2 endpoints)
- `POST /threat-detection` - Threat detection
- `POST /vulnerability-check` - Vulnerability check

### 7. Crypto (9 endpoints)
- `GET /stub-generator/encryption-methods` - Encryption methods
- `POST /hash` - Hash data
- `POST /encrypt` - Encrypt data
- `POST /encrypt-file` - Encrypt file
- `POST /decrypt-file` - Decrypt file
- `POST /decrypt` - Decrypt data
- `POST /advancedcrypto` - Advanced crypto
- `POST /file-hash` - File hash
- `POST /ev-cert/encrypt-stub` - EV cert encrypt stub

### 8. Network (4 endpoints)
- `GET /api/network/ports` - Network ports
- `GET /api/network/protocols` - Network protocols
- `GET /dns` - DNS resolution
- `GET /ping` - Ping test
- `POST /traceroute` - Traceroute
- `POST /whois` - WHOIS lookup

### 9. Utility (5 endpoints)
- `GET /uuid` - Generate UUID
- `GET /time` - Get time
- `POST /random` - Random data
- `POST /password` - Generate password
- `POST /math` - Math operations
- `POST /timeline-analysis` - Timeline analysis
- `POST /random-math` - Random math

### 10. Other (137 endpoints)

#### System Information
- `GET /unified` - Unified interface
- `GET /files` - File listing
- `GET /download` - Download files
- `GET /sysinfo` - System info
- `GET /processes` - Process listing
- `GET /api-status` - API status
- `GET /performance-monitor` - Performance monitor
- `GET /memory-info` - Memory info
- `GET /cpu-usage` - CPU usage
- `GET /disk-usage` - Disk usage
- `GET /network-stats` - Network stats

#### Mutex & UPX
- `GET /mutex/options` - Mutex options
- `GET /upx/methods` - UPX methods
- `POST /mutex/generate` - Generate mutex
- `POST /mutex/apply` - Apply mutex
- `POST /upx/pack` - UPX pack
- `POST /upx/status` - UPX status

#### OpenSSL Management
- `GET /openssl/config` - OpenSSL config
- `GET /openssl/algorithms` - OpenSSL algorithms
- `GET /openssl/openssl-algorithms` - OpenSSL algorithms
- `GET /openssl/custom-algorithms` - Custom algorithms
- `GET /openssl-management/status` - Management status
- `GET /openssl-management/report` - Management report
- `POST /openssl/toggle-openssl` - Toggle OpenSSL
- `POST /openssl/toggle-custom` - Toggle custom
- `POST /openssl-management/toggle` - Toggle management
- `POST /openssl-management/test` - Test management
- `POST /openssl-management/preset` - Management preset

#### Implementation Check
- `GET /implementation-check/status` - Check status
- `GET /implementation-check/results` - Check results
- `GET /implementation-check/modules` - Check modules
- `POST /implementation-check/run` - Run check
- `POST /implementation-check/force` - Force check

#### Red Killer
- `GET /red-killer/status` - Red killer status
- `GET /red-killer/loot` - Red killer loot
- `GET /red-killer/loot/:id` - Specific loot
- `GET /red-killer/kills` - Red killer kills
- `POST /red-killer/detect` - Detect targets
- `POST /red-killer/execute` - Execute red killer
- `POST /red-killer/extract` - Extract data
- `POST /red-killer/wifi-dump` - WiFi dump

#### EV Cert
- `GET /ev-cert/status` - EV cert status
- `GET /ev-cert/certificates` - EV certificates
- `GET /ev-cert/stubs` - EV cert stubs
- `GET /ev-cert/templates` - EV cert templates
- `GET /ev-cert/languages` - EV cert languages
- `GET /ev-cert/algorithms` - EV cert algorithms
- `POST /ev-cert/generate` - Generate EV cert

#### Beaconism
- `GET /beaconism/status` - Beaconism status
- `GET /beaconism/payloads` - Beaconism payloads
- `GET /beaconism/targets` - Beaconism targets
- `POST /beaconism/generate-payload` - Generate payload
- `POST /beaconism/deploy` - Deploy payload
- `POST /beaconism/scan-target` - Scan target

#### Red Shells
- `GET /red-shells/status` - Red shells status
- `GET /red-shells` - Red shells list
- `GET /red-shells/:id/history` - Shell history
- `GET /red-shells/stats` - Red shells stats
- `POST /red-shells/create` - Create red shell
- `POST /red-shells/:id/execute` - Execute command
- `DELETE /red-shells/:id` - Delete red shell

#### Stub Generator
- `GET /stub-generator/status` - Stub generator status
- `GET /stub-generator/templates` - Stub templates
- `GET /stub-generator/active` - Active stubs
- `GET /stub-generator/packing-methods` - Packing methods
- `GET /stub-generator/fud-techniques` - FUD techniques
- `GET /stub-generator/auto-regeneration/status` - Auto regeneration status
- `GET /stub-generator/unpacked` - Unpacked stubs
- `GET /stub-generator/repack-history` - Repack history
- `GET /stub-generator/comprehensive-stats` - Comprehensive stats
- `GET /stub-generator/export-stats/:format` - Export stats
- `POST /stub-generator/generate` - Generate stub
- `POST /stub-generator/regenerate` - Regenerate stub
- `POST /stub-generator/analyze` - Analyze stub
- `POST /stub-generator/trigger-regeneration` - Trigger regeneration
- `POST /stub-generator/unpack` - Unpack stub
- `POST /stub-generator/repack` - Repack stub
- `POST /stub-generator/auto-regeneration/enable` - Enable auto regeneration
- `POST /stub-generator/auto-regeneration/disable` - Disable auto regeneration
- `POST /stub-generator/process-scheduled` - Process scheduled
- `POST /stub-generator/reset-stats` - Reset stats
- `DELETE /stub-generator/:botId` - Delete stub
- `DELETE /stub-generator/clear/all` - Clear all stubs
- `DELETE /stub-generator/unpacked/:unpackId` - Delete unpacked
- `DELETE /stub-generator/unpacked/clear/all` - Clear all unpacked

#### Native Compiler
- `GET /native-compiler/stats` - Compiler stats
- `GET /native-compiler/supported-languages` - Supported languages
- `GET /native-compiler/available-compilers` - Available compilers
- `POST /native-compiler/regenerate` - Regenerate
- `POST /native-compiler/compile` - Compile

#### Advanced Features
- `GET /advanced-features` - Advanced features panel
- `POST /upload` - Upload file
- `POST /cli` - CLI command
- `POST /stub` - Generate stub
- `POST /compile-asm` - Compile assembly
- `POST /compile-js` - Compile JavaScript
- `POST /keygen` - Generate key
- `POST /sign` - Sign data
- `POST /verify` - Verify signature
- `POST /base64encode` - Base64 encode
- `POST /base64decode` - Base64 decode
- `POST /hexencode` - Hex encode
- `POST /hexdecode` - Hex decode
- `POST /urlencode` - URL encode
- `POST /urldecode` - URL decode
- `POST /fileops` - File operations
- `POST /textops` - Text operations
- `POST /validate` - Validate data
- `POST /download-file` - Download file
- `POST /read-file` - Read file
- `POST /read-local-file` - Read local file
- `POST /stealth-mode` - Stealth mode
- `POST /anti-detection` - Anti-detection
- `POST /polymorphic` - Polymorphic
- `POST /hot-patch` - Hot patch
- `POST /patch-rollback` - Patch rollback
- `POST /garbage-collect` - Garbage collect
- `POST /memory-cleanup` - Memory cleanup
- `POST /file-signature` - File signature
- `POST /backup` - Backup
- `POST /restore` - Restore
- `POST /data-conversion` - Data conversion
- `POST /compress` - Compress
- `POST /decompress` - Decompress
- `POST /service-detection` - Service detection
- `POST /packet-capture` - Packet capture
- `POST /traffic-analysis` - Traffic analysis
- `POST /protocol-analysis` - Protocol analysis
- `POST /file-analysis` - File analysis

#### QR & Barcode
- `POST /qr-generate` - Generate QR code
- `POST /barcode-generate` - Generate barcode

#### Backup
- `GET /backup-list` - Backup list

## Usage Notes

1. **Authentication**: Most endpoints require Bearer token authentication
2. **Content-Type**: POST requests should use `application/json`
3. **Parameters**: Many endpoints accept optional parameters with sensible defaults
4. **Error Handling**: All endpoints return consistent error responses
5. **Rate Limiting**: Consider implementing rate limiting for production use

## Testing

Use the comprehensive test script `test-all-294-endpoints.js` to verify all endpoints are working correctly.
