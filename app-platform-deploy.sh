#!/bin/bash

echo "🚀 Deploying to DigitalOcean App Platform..."

# Create app using DigitalOcean API
curl -X POST https://api.digitalocean.com/v2/apps \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer dop_v1_31e52e2e6e6cd0b837e35d79d5c1b68304962e66ed1549352f1dae152c488994" \
  -d '{
    "spec": {
      "name": "rawrz-platform",
      "services": [
        {
          "name": "rawrz-app",
          "source_dir": "/",
          "github": {
            "repo": "ItsMehRAWRXD/itsmehrawrxd",
            "branch": "cursor/refactor-paneling-for-endpoint-generation-and-customization-5167"
          },
          "run_command": "npm start",
          "environment_slug": "node-js",
          "instance_count": 1,
          "instance_size_slug": "basic-xxs",
          "http_port": 8080,
          "envs": [
            {"key": "NODE_ENV", "value": "production"},
            {"key": "PORT", "value": "8080"},
            {"key": "MAX_FILE_SIZE", "value": "500MB"},
            {"key": "LOG_LEVEL", "value": "warn"},
            {"key": "NODE_OPTIONS", "value": "--max-old-space-size=768"},
            {"key": "AUTH_TOKEN", "value": "dop_v1_31e52e2e6e6cd0b837e35d79d5c1b68304962e66ed1549352f1dae152c488994"}
          ],
          "routes": [{"path": "/"}],
          "health_check": {
            "http_path": "/health",
            "initial_delay_seconds": 10,
            "period_seconds": 10,
            "timeout_seconds": 5,
            "success_threshold": 1,
            "failure_threshold": 3
          },
          "build_command": "npm install && npm audit fix --force || true"
        }
      ]
    }
  }' | jq -r '.app.id'

echo "✅ App Platform deployment initiated"
echo "⏳ Please wait 5-10 minutes for deployment to complete"
echo ""
echo "🔍 To check status:"
echo "curl -H \"Authorization: Bearer dop_v1_31e52e2e6e6cd0b837e35d79d5c1b68304962e66ed1549352f1dae152c488994\" https://api.digitalocean.com/v2/apps"
