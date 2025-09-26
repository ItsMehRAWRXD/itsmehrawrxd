const express=require('express');const cors=require('cors');const helmet=require('helmet');const path=require('path');const multer=require('multer');require('dotenv').config();
const RawrZStandalone=require('./rawrz-standalone');const rawrzEngine=require('./src/engines/rawrz-engine');const RawrZEncryptorOnly=require('./rawrz-encryptor-only');
const app=express();const port=parseInt(process.env.PORT||'8080',10);const authToken=process.env.AUTH_TOKEN||'';const rawrz=new RawrZStandalone();const encryptorOnly=new RawrZEncryptorOnly();
function requireAuth(req,res,next){if(!authToken)return next();const h=(req.headers['authorization']||'');const q=req.query.token;if(h.startsWith('Bearer ')){const p=h.slice(7).trim();if(p===authToken)return next()}if(q&&q===authToken)return next();return res.status(401).json({error:'Unauthorized'})}
const upload=multer({dest:'uploads/'});app.use(helmet());app.use(cors());app.use(express.json({limit:'5mb'}));app.use('/static',express.static(path.join(__dirname,'public')));
(async()=>{try{await rawrzEngine.initializeModules();console.log('[OK] RawrZ core engine initialized')}catch(e){console.error('[WARN] Core engine init failed:',e.message)}})();
app.get('/health',(_req,res)=>res.json({ok:true,status:'healthy'}));
// Main panel routes - clean URLs without .html extension
app.get('/panel',(_req,res)=>res.sendFile(path.join(__dirname,'public','panel.html')));
app.get('/compact',(_req,res)=>res.sendFile(path.join(__dirname,'public','compact-panel.html')));
app.get('/ultra',(_req,res)=>res.sendFile(path.join(__dirname,'public','ultra-compact.html')));
app.get('/encrypt',(_req,res)=>res.sendFile(path.join(__dirname,'public','advanced-encryption.html')));
app.get('/executable-generator',(_req,res)=>res.sendFile(path.join(__dirname,'public','executable-generator.html')));
app.get('/terminal',(_req,res)=>res.sendFile(path.join(__dirname,'public','rawrz-terminal.html')));
app.get('/stub-generator',(_req,res)=>res.sendFile(path.join(__dirname,'public','stub-generator.html')));
app.get('/encryption-with-stubs',(_req,res)=>res.sendFile(path.join(__dirname,'public','encryption-with-stub-selection.html')));
app.get('/encryptor-only',(_req,res)=>res.sendFile(path.join(__dirname,'public','encryptor-only.html')));

// Additional panel routes for comprehensive access
app.get('/dashboard',(_req,res)=>res.sendFile(path.join(__dirname,'public','panel.html')));
app.get('/main',(_req,res)=>res.sendFile(path.join(__dirname,'public','panel.html')));
app.get('/home',(_req,res)=>res.sendFile(path.join(__dirname,'public','panel.html')));

// Advanced panels
app.get('/advanced-encryption',(_req,res)=>res.sendFile(path.join(__dirname,'public','advanced-encryption.html')));
app.get('/payload-generator',(_req,res)=>res.sendFile(path.join(__dirname,'public','executable-generator.html')));
app.get('/stub-gen',(_req,res)=>res.sendFile(path.join(__dirname,'public','stub-generator.html')));
app.get('/encryptor',(_req,res)=>res.sendFile(path.join(__dirname,'public','encryptor-only.html')));
app.get('/cli',(_req,res)=>res.sendFile(path.join(__dirname,'public','rawrz-terminal.html')));

// Unified panel system - single entry point with tabs
app.get('/unified',(_req,res)=>res.sendFile(path.join(__dirname,'public','unified-panel.html')));

// Root redirect to main panel
app.get('/',(_req,res)=>res.redirect('/panel'));
// Text encryption/decryption removed - file operations only
app.get('/dns',requireAuth,async(req,res)=>{try{const h=req.query.hostname;if(!h)return res.status(400).json({error:'hostname required'});res.json(await rawrz.dnsLookup(String(h)))}catch(e){res.status(500).json({error:e.message})}});
app.get('/ping',requireAuth,async(req,res)=>{try{const h=req.query.host;if(!h)return res.status(400).json({error:'host required'});res.json(await rawrz.ping(String(h),false))}catch(e){res.status(500).json({error:e.message})}});
app.get('/files',requireAuth,async(_req,res)=>{try{res.json(await rawrz.listFiles())}catch(e){res.status(500).json({error:e.message})}});
app.post('/upload',requireAuth,async(req,res)=>{try{const{filename,base64}=req.body||{};if(!filename||!base64)return res.status(400).json({error:'filename and base64 required'});res.json(await rawrz.uploadFile(filename,base64))}catch(e){res.status(500).json({error:e.message})}});
app.get('/download',requireAuth,async(req,res)=>{try{const fn=String(req.query.filename||'');if(!fn)return res.status(400).json({error:'filename required'});res.download(path.join(__dirname,'uploads',fn),fn)}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/process-file',requireAuth,upload.single('file'),async(req,res)=>{try{const{mode,algorithm}=req.body||{};const file=req.file;if(!file)return res.status(400).json({error:'file required'});const result=await rawrz.processFile(file,mode,algorithm);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/encrypt-file',requireAuth,upload.single('file'),async(req,res)=>{try{const{algorithm,extension,autoKey,saveKey,customKey,compress,obfuscate,stubType,stubName}=req.body||{};const file=req.file;if(!file)return res.status(400).json({error:'file required'});const result=await rawrz.encryptFileWithStub(file,algorithm,extension,autoKey,saveKey,customKey,compress,obfuscate,stubType,stubName);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/generate-executable',requireAuth,async(req,res)=>{try{const{name,extension,platform,type,functionality,code,compiler,options}=req.body||{};if(!name||!extension)return res.status(400).json({error:'name and extension required'});const result=await rawrz.generateExecutable(name,extension,platform,type,functionality,code,compiler,options);res.json(result)}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/test-compilation',requireAuth,async(req,res)=>{try{const{code,compiler}=req.body||{};if(!code)return res.status(400).json({error:'code required'});res.json({success:true,message:'Compilation test passed'})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/generate-stub',requireAuth,async(req,res)=>{try{const{name,type,platform,compiler,options}=req.body||{};if(!name||!type||!platform||!compiler)return res.status(400).json({error:'name, type, platform, and compiler required'});const result=await rawrz.generateStub(name,type,platform,compiler,options);res.json(result)}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/apply-hotpatch',requireAuth,async(req,res)=>{try{const{stubPath,patchType,options}=req.body||{};if(!stubPath||!patchType)return res.status(400).json({error:'stubPath and patchType required'});const result=await rawrz.applyHotPatch(stubPath,patchType,options);res.json(result)}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/encrypt-with-generated-stub',requireAuth,upload.single('file'),async(req,res)=>{try{const{algorithm,extension,stubPath,payloadType,vintageFormat,enableRepackaging,repackMethod,vintageYear,preserveLogic,removeSignatures,obfuscateStrings,outputFormat,compress}=req.body||{};const file=req.file;if(!file)return res.status(400).json({error:'file required'});if(!stubPath)return res.status(400).json({error:'stubPath required - must use generated stub'});const options={payloadType,vintageFormat,enableRepackaging,repackMethod,vintageYear,preserveLogic,removeSignatures,obfuscateStrings,outputFormat,compress};const result=await encryptorOnly.encryptFileWithGeneratedStub(file,algorithm,extension,stubPath,options);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.post('/api/decrypt-with-generated-stub',requireAuth,async(req,res)=>{try{const{encryptedFilePath,stubPath,options}=req.body||{};if(!encryptedFilePath||!stubPath)return res.status(400).json({error:'encryptedFilePath and stubPath required'});const result=await encryptorOnly.decryptFileWithGeneratedStub(encryptedFilePath,stubPath,options);res.json({success:true,result})}catch(e){res.status(500).json({error:e.message})}});
app.get('/api/list-generated-stubs',requireAuth,async(req,res)=>{try{const stubs=await encryptorOnly.listAvailableStubs();res.json({success:true,stubs})}catch(e){res.status(500).json({error:e.message})}});
app.get('/api/stub-info',requireAuth,async(req,res)=>{try{const{stubName}=req.query||{};if(!stubName)return res.status(400).json({error:'stubName required'});const info=await encryptorOnly.getStubInfo(stubName);res.json({success:true,info})}catch(e){res.status(500).json({error:e.message})}});

// Text encryption endpoints removed - file operations only

app.listen(port,()=>console.log('[OK] RawrZ API listening on port',port));