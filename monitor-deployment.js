#!/usr/bin/env node

// Monitor Digital Ocean App Deployment
const https = require('https');

const DO_API_TOKEN = 'dop_v1_ccce0b4c48181e9ef566a7b2a5105194256b8302af99761a57a7cad6d3007c4e';
const APP_ID = '5a7b948b-884a-4570-b674-e49b6d4bb405';

function makeRequest(options) {
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
    req.end();
  });
}

async function monitorDeployment() {
  console.log('🔍 Monitoring RawrZ Security Platform Deployment...\n');
  console.log(`📱 App ID: ${APP_ID}\n`);

  const maxAttempts = 30; // 5 minutes max
  let attempts = 0;

  while (attempts < maxAttempts) {
    try {
      const options = {
        hostname: 'api.digitalocean.com',
        port: 443,
        path: `/v2/apps/${APP_ID}`,
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${DO_API_TOKEN}`
        }
      };

      const response = await makeRequest(options);
      
      if (response.status === 200) {
        const app = response.data.app;
        const deployment = app.pending_deployment || app.last_deployment_active_at;
        
        console.log(`📊 App Status: ${app.spec.name}`);
        console.log(`🌐 Live URL: ${app.live_url || 'Not yet available'}`);
        console.log(`📅 Created: ${app.created_at}`);
        
        if (app.pending_deployment) {
          console.log(`🔄 Deployment Phase: ${app.pending_deployment.phase}`);
          console.log(`📈 Progress: ${app.pending_deployment.progress?.steps_completed || 0}/${app.pending_deployment.progress?.total_steps || 0}`);
          
          if (app.pending_deployment.phase === 'ACTIVE') {
            console.log('\n🎉 Deployment completed successfully!');
            console.log(`🌐 Your RawrZ Security Platform is now live at: ${app.live_url}`);
            console.log(`🔗 Health Check: ${app.live_url}/health`);
            console.log(`🎛️  Web Panel: ${app.live_url}/panel`);
            break;
          } else if (app.pending_deployment.phase === 'ERROR') {
            console.error('\n❌ Deployment failed with error');
            break;
          }
        } else {
          console.log('✅ App is active and running!');
          console.log(`🌐 Live URL: ${app.live_url}`);
          break;
        }
      }
      
      attempts++;
      console.log(`\n⏳ Waiting 10 seconds... (${attempts}/${maxAttempts})`);
      await new Promise(resolve => setTimeout(resolve, 10000));
      
    } catch (error) {
      console.error('❌ Error monitoring deployment:', error.message);
      break;
    }
  }
  
  if (attempts >= maxAttempts) {
    console.log('\n⏰ Monitoring timeout. Check Digital Ocean dashboard for status.');
    console.log('🔗 Dashboard: https://cloud.digitalocean.com/apps');
  }
}

// Run monitoring
if (require.main === module) {
  monitorDeployment().catch(console.error);
}

module.exports = { monitorDeployment };
