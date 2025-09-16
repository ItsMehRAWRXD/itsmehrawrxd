#!/usr/bin/env node

// Digital Ocean App Platform Deployment Script
// Deploys RawrZ Security Platform with cost-effective configuration

const https = require('https');
const fs = require('fs');
const path = require('path');

// Configuration
const DO_API_TOKEN = 'dop_v1_ccce0b4c48181e9ef566a7b2a5105194256b8302af99761a57a7cad6d3007c4e';
const GITHUB_TOKEN = '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';
const GITHUB_REPO = 'ItsMehRAWRXD/itsmehrawrxd';
const APP_NAME = 'rawr-security-platform';

// Cost-effective configuration (no droplets, just App Platform)
const appSpec = {
  "spec": {
    "name": APP_NAME,
    "region": "nyc",
    "services": [
      {
        "name": "rawr-backend",
        "run_command": "npm start",
        "http_port": 8080,
        "source_dir": "/",
        "dockerfile_path": "Dockerfile",
        "instance_count": 1,
        "instance_size_slug": "basic-xxs", // $4-6/month
        "github": {
          "repo": GITHUB_REPO,
          "branch": "main"
        },
        "envs": [
          {
            "key": "NODE_ENV",
            "value": "production",
            "scope": "RUN_AND_BUILD_TIME"
          },
          {
            "key": "PORT",
            "value": "8080",
            "scope": "RUN_AND_BUILD_TIME"
          },
          {
            "key": "NPM_CONFIG_PRODUCTION",
            "value": "false",
            "scope": "BUILD_TIME"
          }
        ]
      }
    ],
    "ingress": {
      "rules": [
        {
          "match": {
            "path": {
              "prefix": "/"
            }
          },
          "component": {
            "name": "rawr-backend"
          }
        }
      ]
    }
  }
};

function makeRequest(options, postData = null) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const jsonData = JSON.parse(data);
          resolve({ status: res.statusCode, data: jsonData });
        } catch (e) {
          resolve({ status: res.statusCode, data: data });
        }
      });
    });

    req.on('error', reject);
    
    if (postData) {
      req.write(JSON.stringify(postData));
    }
    
    req.end();
  });
}

async function deployToDigitalOcean() {
  console.log('🚀 Starting Digital Ocean App Platform Deployment...\n');

  try {
    // Step 1: Create the app
    console.log('📦 Creating Digital Ocean App...');
    const createOptions = {
      hostname: 'api.digitalocean.com',
      port: 443,
      path: '/v2/apps',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${DO_API_TOKEN}`,
        'Content-Type': 'application/json'
      }
    };

    const createResponse = await makeRequest(createOptions, appSpec);
    
    if (createResponse.status === 201) {
      console.log('✅ App created successfully!');
      console.log(`📱 App ID: ${createResponse.data.app.id}`);
      console.log(`🌐 App URL: ${createResponse.data.app.live_url || 'Deploying...'}`);
      
      // Step 2: Deploy the app
      console.log('\n🚀 Starting deployment...');
      const deployOptions = {
        hostname: 'api.digitalocean.com',
        port: 443,
        path: `/v2/apps/${createResponse.data.app.id}/deployments`,
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${DO_API_TOKEN}`,
          'Content-Type': 'application/json'
        }
      };

      const deployResponse = await makeRequest(deployOptions, {
        "force_build": true
      });

      if (deployResponse.status === 201) {
        console.log('✅ Deployment started successfully!');
        console.log(`🔄 Deployment ID: ${deployResponse.data.deployment.id}`);
        console.log(`📊 Status: ${deployResponse.data.deployment.phase}`);
        
        // Monitor deployment
        console.log('\n⏳ Monitoring deployment progress...');
        await monitorDeployment(createResponse.data.app.id, deployResponse.data.deployment.id);
        
      } else {
        console.error('❌ Deployment failed:', deployResponse.data);
      }
      
    } else {
      console.error('❌ App creation failed:', createResponse.data);
    }

  } catch (error) {
    console.error('❌ Deployment error:', error.message);
  }
}

async function monitorDeployment(appId, deploymentId) {
  const maxAttempts = 30; // 5 minutes max
  let attempts = 0;

  while (attempts < maxAttempts) {
    try {
      const statusOptions = {
        hostname: 'api.digitalocean.com',
        port: 443,
        path: `/v2/apps/${appId}/deployments/${deploymentId}`,
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${DO_API_TOKEN}`
        }
      };

      const response = await makeRequest(statusOptions);
      
      if (response.status === 200) {
        const deployment = response.data.deployment;
        console.log(`📊 Status: ${deployment.phase} (${deployment.progress}%)`);
        
        if (deployment.phase === 'ACTIVE') {
          console.log('🎉 Deployment completed successfully!');
          console.log(`🌐 Your RawrZ Security Platform is now live!`);
          break;
        } else if (deployment.phase === 'ERROR') {
          console.error('❌ Deployment failed with error');
          break;
        }
      }
      
      attempts++;
      await new Promise(resolve => setTimeout(resolve, 10000)); // Wait 10 seconds
      
    } catch (error) {
      console.error('❌ Error monitoring deployment:', error.message);
      break;
    }
  }
  
  if (attempts >= maxAttempts) {
    console.log('⏰ Deployment monitoring timeout. Check Digital Ocean dashboard for status.');
  }
}

// Run deployment
if (require.main === module) {
  deployToDigitalOcean().catch(console.error);
}

module.exports = { deployToDigitalOcean };
