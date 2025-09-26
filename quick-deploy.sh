#!/bin/bash

echo "🌐 Creating DigitalOcean Droplet..."

# Create droplet using DigitalOcean API
curl -X POST https://api.digitalocean.com/v2/droplets \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer dop_v1_31e52e2e6e6cd0b837e35d79d5c1b68304962e66ed1549352f1dae152c488994" \
  -d '{
    "name": "rawrz-platform",
    "region": "nyc1",
    "size": "s-1vcpu-1gb",
    "image": "ubuntu-22-04-x64",
    "ssh_keys": [],
    "backups": false,
    "ipv6": false,
    "user_data": "#!/bin/bash\napt-get update\napt-get install -y git curl\ncurl -fsSL https://deb.nodesource.com/setup_18.x | bash -\napt-get install -y nodejs\ncd /root\ngit clone https://github.com/ItsMehRAWRXD/itsmehrawrxd.git\ncd itsmehrawrxd\ngit checkout cursor/refactor-paneling-for-endpoint-generation-and-customization-5167\nnpm install\nexport NODE_ENV=production\nexport PORT=8080\nexport MAX_FILE_SIZE=500MB\nexport LOG_LEVEL=warn\nexport NODE_OPTIONS=\"--max-old-space-size=768\"\nexport AUTH_TOKEN=\"dop_v1_31e52e2e6e6cd0b837e35d79d5c1b68304962e66ed1549352f1dae152c488994\"\nmkdir -p uploads downloads generated-stubs\nnohup node server.js > app.log 2>&1 &\necho \"RawrZ Platform started on port 8080\""
  }' | jq -r '.droplet.id'

echo "✅ Droplet creation initiated"
echo "⏳ Please wait 2-3 minutes for droplet to be ready"
echo ""
echo "🔍 To check status:"
echo "curl -H \"Authorization: Bearer dop_v1_31e52e2e6e6cd0b837e35d79d5c1b68304962e66ed1549352f1dae152c488994\" https://api.digitalocean.com/v2/droplets"
echo ""
echo "🌐 Once ready, your platform will be available at:"
echo "http://DROPLET_IP:8080/unified"
