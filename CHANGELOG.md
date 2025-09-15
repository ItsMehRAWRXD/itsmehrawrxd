# RawrZ Security Platform - Changelog

## Version 2.1.1 - September 15, 2025

### Fixed
- **Certificate Popup Dialogs**: Fixed EV Certificate Encryptor showing popup dialogs during server startup
  - Modified `loadTrustedCAs()` method to use completely hidden PowerShell commands
  - Added `-WindowStyle Hidden` parameter to prevent GUI popups
  - Added `windowsHide: true` option to exec call
  - Added `2>$null` to suppress error output
  - Added timeout to prevent hanging processes
  - Certificate store now loads silently without user interaction

### Technical Details
- **File Modified**: `src/engines/ev-cert-encryptor.js`
- **Method**: `loadTrustedCAs()`
- **Impact**: Improved user experience during server startup
- **Backward Compatibility**: Fully maintained

### Documentation Updates
- Updated `PROJECT_COMPLETION_REPORT.md` with certificate management status
- Updated `DEPLOYMENT.md` with troubleshooting information for certificate popups
- Updated `TESTING.md` with certificate popup fix documentation
- Added this changelog file for version tracking

## Version 2.1.0 - September 15, 2025

### Initial Release
- Complete RawrZ Security Platform with 150+ features
- 27+ security engines
- Comprehensive CLI and web interfaces
- Full testing suite
- Production deployment ready

### Features
- **Core Platform**: RawrZ Standalone CLI with 102+ commands
- **Security Engines**: Anti-analysis, hot patchers, network tools, health monitoring
- **Bot Generation**: HTTP bot generator, IRC bot generator, stub generators
- **Web Interfaces**: Multiple control panels and dashboards
- **API Endpoints**: 50+ REST API endpoints
- **Security Features**: Authentication, CORS, security headers, input validation
- **Testing Suite**: Unit tests, performance tests, comprehensive tests
- **Deployment**: Docker, Kubernetes, production configurations

### Technical Implementation
- **Real Implementations**: All engines use actual implementations, no simulated code
- **Native Integration**: FFI, ref, winreg, ps, netstat modules
- **System Operations**: Real OS interactions, file I/O, network calls
- **Performance Optimized**: Caching, connection pooling, concurrent operations
- **Error Handling**: Comprehensive error handling and graceful degradation

---

*For detailed information about each version, see the respective documentation files.*
