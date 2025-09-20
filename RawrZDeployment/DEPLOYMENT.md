# RawrZ Security Platform - Deployment Package

## Overview
This deployment package contains the complete RawrZ Security Platform with all advanced evasion tools and real functionality.

## Components

### Core Application
- api-server-real.js - Main API server with all 47+ engines
- package.json - Node.js dependencies
- Dockerfile - Docker container configuration
- README.md - Platform documentation

### Advanced Evasion Tools
- EvAdrKiller.ps1 - EV/ADR certificate killer
- B.ps1 - Beaconism-dropper
- CppEncExe.ps1 - C++ compiler with Camellia encryption
- FHp.ps1 - File-less hot-patch one-liner
- TripleCrypto.ps1 - Triple encryption (Camellia + AES + ChaCha20)
- HotDrop.ps1 - Hot-patch dropper

### Polymorphic Loaders
- polymorph.asm - MASM64 polymorphic loader
- polymorph_ssl.asm - MASM64 SSL polymorphic loader with OpenSSL
- loader.c - C polymorphic loader
- poly_key.h - Generated polymorphic key header
- poly_ssl.inc - Generated SSL polymorphic configuration
- stealth_poly.h - Generated stealth polymorphic configuration

### Ring-0 Hybrid Dropper
- stealthdrv.c - Kernel driver for process/file/registry hiding
- stealthinst.c - User-mode installer
- stealthinj.asm - Registry-based injector

### Build Scripts
- polymorph_build.ps1 - MASM polymorphic loader builder
- polymorph_ssl_build.ps1 - MASM SSL polymorphic loader builder
- generate_poly_key.ps1 - Polymorphic key generator
- setup-native-compilation.sh - Native compilation setup

### Native Compilation System
- native-compile.Dockerfile - Docker configuration for native compilation
- native-compile.sh - Native compilation script
- native-compile-server.js - Native compilation server
- camellia-hotpatch.Dockerfile - Camellia hot-patch Docker configuration
- stub_patch.c - Camellia hot-patch stub
- camellia_hotpatch.h - Camellia hot-patch header
- spoof_descriptors.c - Hardware ID spoofing

### Engines (47+ modules)
All engine modules are located in src/engines/ directory:
- Real encryption engine
- Black hat capabilities engine
- Advanced evasion engine
- IRC bot generator
- And 43+ additional engines

## Installation

### Prerequisites
- Node.js 16+
- Visual Studio 2022 with MASM
- Windows Driver Kit (WDK) for kernel components
- OpenSSL 3.x static libraries
- Docker (for native compilation)

### Quick Start
1. Install Node.js dependencies:
   npm install

2. Start the API server:
   node api-server-real.js

3. Access the web interface:
   http://localhost:3000

### Advanced Features
1. Build polymorphic loaders:
   .\build-scripts\polymorph_build.ps1

2. Setup native compilation:
   .\build-scripts\setup-native-compilation.sh

3. Test all features:
   .\tests\test_advanced_evasion.ps1

## Security Notice
This platform is designed for legitimate security research, penetration testing, and red team operations. All tools use only documented APIs and are provided as-is for educational and research purposes.

## License
All components are released into the public domain. See individual files for full license information.

## Support
For technical support and documentation, refer to the main README.md file.

Generated: 2025-09-20 05:53:46
