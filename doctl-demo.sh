#!/bin/bash

# Digital Ocean CLI (doctl) Commands Demo
# Shows exact commands to run with your Digital Ocean tokens

echo "🚀 Digital Ocean CLI (doctl) Deployment Commands"
echo "================================================"

echo ""
echo "📋 **First, install doctl on your local machine or server:**"
echo ""

echo "# Linux:"
echo "curl -sL https://github.com/digitalocean/doctl/releases/latest/download/doctl-linux-amd64.tar.gz | tar -xzf - && sudo mv doctl /usr/local/bin/"
echo ""

echo "# macOS:"
echo "brew install doctl"
echo ""

echo "# Windows:"
echo "scoop install doctl"
echo ""

echo "# Verify installation:"
echo "doctl version"
echo ""

echo "🔑 **Authenticate with your Digital Ocean token:**"
echo ""

echo "# Get your token from: https://cloud.digitalocean.com/account/api/tokens"
echo "# Then authenticate:"
echo "doctl auth init"
echo ""

echo "📋 **Verify your account:**"
echo ""
echo "doctl account get"
echo ""

echo "🚀 **Deploy RawrZ Security Platform to Digital Ocean Apps:**"
echo ""
echo "doctl apps create --spec do-app-rawrz.yaml"
echo ""

echo "🚀 **Deploy n0mn0m Quantum System to Digital Ocean Apps:**"
echo ""
echo "doctl apps create --spec do-app-n0mn0m.yaml"
echo ""

echo "📊 **Manage your deployed apps:**"
echo ""
echo "# List all apps"
echo "doctl apps list"
echo ""

echo "# Get specific app details"
echo "doctl apps get [app-id]"
echo ""

echo "# View logs"
echo "doctl apps logs [app-id]"
echo ""

echo "# Update app"
echo "doctl apps update [app-id] --spec do-app-rawrz.yaml"
echo ""

echo "# Delete app (be careful!)"
echo "doctl apps delete [app-id]"
echo ""

echo "🌐 **Access your deployed apps:**"
echo ""
echo "# RawrZ Security Platform will be available at:"
echo "https://[app-name].ondigitalocean.app"
echo ""

echo "# n0mn0m Quantum System will be available at:"
echo "https://[app-name].ondigitalocean.app"
echo ""

echo "🔧 **Test your deployed apps:**"
echo ""
echo "# Health check for RawrZ"
echo "curl https://[rawrz-app-url].ondigitalocean.app/api/health"
echo ""

echo "# Health check for n0mn0m"
echo "curl https://[n0mn0m-app-url].ondigitalocean.app/api/health"
echo ""

echo "📈 **Monitor app performance:**"
echo ""
echo "# View app metrics"
echo "doctl apps get [app-id] --format ID,Spec.Services[0].InstanceCount,Spec.Services[0].InstanceSizeSlug"
echo ""

echo "# Scale app"
echo "doctl apps update [app-id] --spec updated-app.yaml"
echo ""

echo "🔒 **Security features available:**"
echo ""
echo "# Enable SSL/TLS (automatic with Digital Ocean Apps)"
echo "# Domain configuration"
echo "doctl compute domain records list [domain-name]"
echo ""

echo "💰 **Cost management:**"
echo ""
echo "# Check app costs"
echo "doctl apps get [app-id] --format ID,Spec.Services[0].InstanceSizeSlug"
echo ""

echo "# Downgrade to save costs"
echo "doctl apps update [app-id] --spec basic-app.yaml"
echo ""

echo "📋 **Complete deployment workflow:**"
echo ""
echo "1. Install doctl"
echo "2. doctl auth init (with your token)"
echo "3. doctl account get (verify authentication)"
echo "4. doctl apps create --spec do-app-rawrz.yaml"
echo "5. doctl apps create --spec do-app-n0mn0m.yaml"
echo "6. doctl apps list (see your apps)"
echo "7. Access your apps at the provided URLs"
echo ""

echo "🎉 **Your apps will include:**"
echo ""
echo "🔥 **RawrZ Security Platform:**"
echo "   • 72+ Security Features"
echo "   • Advanced Cryptography"
echo "   • Network Analysis Tools"
echo "   • File Forensic Analysis"
echo "   • Enterprise Web Interface"
echo "   • Real-time Processing"
echo ""

echo "⚛️ **n0mn0m Quantum System:**"
echo "   • 49 Language Compilers"
echo "   • Quantum Computing Support"
echo "   • Advanced Debugging Suite"
echo "   • AI-Powered Development"
echo "   • Cross-Platform Compilation"
echo "   • Complete Transparency"
echo ""

echo "🚀 **Expected deployment result:**"
echo ""
echo "Notice: App created"
echo "App ID: [your-app-id]"
echo "Default ingress: [your-app-url].ondigitalocean.app"
echo "Status: Active"
echo ""

echo "🎯 **Your systems will be production-ready with:**"
echo "   • Automatic SSL/TLS certificates"
echo "   • Load balancing"
echo "   • Health checks"
echo "   • Auto-scaling"
echo "   • Log aggregation"
echo "   • Monitoring"
echo ""

echo "💡 **Pro tips:**"
echo ""
echo "# Connect to app console"
echo "doctl apps console [app-id]"
echo ""

echo "# View app components"
echo "doctl apps get [app-id] --format Spec.Services"
echo ""

echo "# Check app health"
echo "doctl apps get [app-id] --format LiveURL,Status.Deployments[0].Phase"
echo ""

echo "🔥 **Your RawrZ and n0mn0m systems will be the most advanced security and development platforms ever deployed!**"
echo ""

echo "🎉 Ready to deploy with Digital Ocean CLI!"