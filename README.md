# RawrZ Security Platform

Advanced cybersecurity toolkit with 51+ engines for penetration testing, malware analysis, and security research.

## 🚀 Features

- **51 Security Engines**: Comprehensive toolkit for cybersecurity professionals
- **Interactive Web Panel**: Full-featured web interface
- **CLI Interface**: Command-line tools for automation
- **Real-time Monitoring**: Health dashboard and system monitoring
- **Encryption Suite**: Advanced cryptographic capabilities
- **Malware Analysis**: Comprehensive analysis tools
- **Network Tools**: Port scanning, network analysis
- **FUD Generation**: Fully Undetectable payload generation

## 🛠️ Quick Start

### Local Development
```bash
# Install dependencies
npm install

# Start the server
npm start

# Access the web panel
open http://localhost:8080/panel.html
```

### Docker Deployment
```bash
# Build the image
docker build -t rawrzapp .

# Run the container
docker run -p 8080:8080 rawrzapp
```

## 🌐 DigitalOcean App Platform Deployment

1. **Connect GitHub Repository**:
   - Go to [DigitalOcean App Platform](https://cloud.digitalocean.com/apps)
   - Click "Create App"
   - Connect your GitHub account
   - Select repository: `ItsMehRAWRXD/itsmehrawrxd`

2. **Configure App**:
   - App will auto-detect Node.js
   - Use the included `.do/app.yaml` configuration
   - Estimated cost: $5/month for basic plan

3. **Deploy**:
   - Click "Create Resources"
   - Wait for deployment to complete
   - Access your app via the provided URL

## 📋 API Endpoints

- `GET /health` - System health check
- `GET /api/engines/status` - Engine status
- `GET /panel.html` - Main web interface
- `GET /health-dashboard.html` - Health monitoring
- `GET /enhanced-payload-panel.html` - Payload management

## 🔧 Configuration

Set environment variables:
- `PORT`: Server port (default: 8080)
- `NODE_ENV`: Environment (production/development)
- `AUTH_TOKEN`: Optional authentication token

## 📁 Project Structure

```
RawrZApp/
├── src/engines/          # 51 security engines
├── public/               # Web interface files
├── server.js            # Main server
├── package.json         # Dependencies
├── .do/app.yaml         # DigitalOcean config
└── Dockerfile           # Container config
```

## 🛡️ Security Notice

This tool is designed for authorized security testing and research only. Users are responsible for complying with applicable laws and regulations.

## 📄 License

MIT License - See LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📞 Support

For issues and questions, please open an issue on GitHub.
