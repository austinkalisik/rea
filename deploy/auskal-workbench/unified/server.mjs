import http from 'node:http';
import {promises as fs,createReadStream} from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
const ROOT='/data';
const ID=/^[a-f0-9-]{36}$/;
const MAX_RAW=48*1024*1024,MAX_BODY=68*1024*1024;
const TYPES=['auto','web','source','git','binary','android','ios','script','image'];
await fs.mkdir(ROOT,{recursive:true});
async function metadata(id){return JSON.parse(await fs.readFile(path.join(ROOT,id,'job.json'),'utf8'));}
async function save(job){const p=path.join(ROOT,job.id,'job.json');await fs.writeFile(p+'.tmp-web',JSON.stringify(job));await fs.rename(p+'.tmp-web',p);}
async function jobs(){const out=[];for(const id of await fs.readdir(ROOT))if(ID.test(id))try{out.push(await metadata(id));}catch{}return out.sort((a,b)=>b.created.localeCompare(a.created));}
function send(res,code,data,type='application/json'){
 res.writeHead(code,{'Content-Type':type,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"});res.end(type==='application/json'?JSON.stringify(data):data);
}
function fail(code,message){return Object.assign(new Error(message),{code});}
async function readJson(req,limit=MAX_BODY){
 if(req.headers['content-type']!=='application/json')throw fail(415,'Send application/json.');
 if(Number(req.headers['content-length'])>limit)throw fail(413,'Request exceeds the upload limit.');
 let size=0;const chunks=[];for await(const chunk of req){size+=chunk.length;if(size>limit)throw fail(413,'Upload limit is 48 MB.');chunks.push(chunk);}
 try{return JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{throw fail(400,'Invalid JSON.');}
}
function relativeName(name){
 if(typeof name!=='string'||name.length>500||/[\x00-\x1f\\]/.test(name)||path.posix.isAbsolute(name)||name.split('/').some(x=>!x||x==='.'||x==='..'))throw fail(400,'Invalid upload path.');return name;
}
const SESSION_FILE = path.join(ROOT,'.rea-sessions.json');
const sessions = new Map(), attempts = new Map();
try {
  for (const [key,value] of JSON.parse(await fs.readFile(SESSION_FILE,'utf8')))
    if (/^[a-f0-9]{64}$/.test(key) && value.expires > Date.now()) sessions.set(key,value);
} catch {}
let sessionWrite=Promise.resolve();
function persistSessions() {
  const data=JSON.stringify([...sessions]);
  sessionWrite=sessionWrite.catch(()=>{}).then(async()=>{
    await fs.writeFile(SESSION_FILE+'.tmp',data,{mode:0o600});
    await fs.rename(SESSION_FILE+'.tmp',SESSION_FILE);
  });
  return sessionWrite;
}
function sessionKey(req) {
  const token=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('__Host-rea_session='))?.slice(19);
  return token && /^[a-f0-9]{64}$/.test(token) ? crypto.createHash('sha256').update(token).digest('hex') : '';
}
function signedIn(req) {
  const key=sessionKey(req), session=sessions.get(key);
  if (!session || session.expires<=Date.now()) { sessions.delete(key); return false; }
  return true;
}
function checkOrigin(req) {
  if (req.headers.origin!=='https://dev.auskal.tech' || req.headers['x-rea-request']!=='workbench')
    throw fail(403,'Request origin rejected.');
}
async function signIn(req,res) {
  checkOrigin(req);
  const ip=req.headers['x-rea-client-ip'] || req.socket.remoteAddress;
  const now=Date.now();
  for(const [key,v] of attempts) if(v.until<now) attempts.delete(key);
  const attempt=attempts.get(ip)||{count:0,until:now+600000};
  if(attempt.count>=10 || attempts.size>=10000) throw fail(429,'Too many sign-in attempts. Try again in 10 minutes.');
  attempt.count++;attempts.set(ip,attempt);
  const body=await readJson(req,4096);
  if(typeof body.username!=='string' || typeof body.password!=='string' ||
      !body.username.length || body.username.length>128 || body.username.includes(':') || !body.password.length || body.password.length>512)
    throw fail(400,'Enter your username and password.');
  let verified;
  try {
    verified=await fetch(process.env.REA_AUTH_VERIFY_URL || 'http://172.16.4.1:3181/verify',{
      headers:{Authorization:'Basic '+Buffer.from(body.username+':'+body.password).toString('base64')},
      redirect:'error',signal:AbortSignal.timeout(5000)
    });
  } catch { throw fail(503,'Account verification is unavailable. Try again shortly.'); }
  const status=verified.status;await verified.body?.cancel();
  if(status===401 || status===403) throw fail(401,'Username or password is incorrect. Use your existing GodsEye account.');
  if(status!==200) throw fail(503,'Account verification is unavailable. Try again shortly.');
  const token=crypto.randomBytes(32).toString('hex'), key=crypto.createHash('sha256').update(token).digest('hex');
  for(const [k,v] of sessions) if(v.expires<=now) sessions.delete(k);
  if(sessions.size>=32) sessions.delete(sessions.keys().next().value);
  sessions.set(key,{expires:now+28800000,username:body.username});
  await persistSessions();attempts.delete(ip);
  res.setHeader('Set-Cookie','__Host-rea_session='+token+'; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800');
  return send(res,200,{ok:true});
}

const acknowledged=new Map();
const ACK_FILE=path.join(ROOT,'.acknowledgments.json');
try{for(const [k,v] of JSON.parse(await fs.readFile(ACK_FILE,'utf8')))acknowledged.set(k,v);}catch{}
let ackWrite=Promise.resolve();
function account(req){return sessions.get(sessionKey(req))?.username;}
function sniff(name,data){
 const ext=name.toLowerCase();
 if(/\.(apk|aab)$/.test(ext))return 'android';if(ext.endsWith('.ipa'))return 'ios';
 if(data.subarray(0,4).equals(Buffer.from([0x7f,69,76,70]))||data.subarray(0,2).toString()==='MZ'||['feedface','feedfacf','cefaedfe','cffaedfe','cafebabe','bebafeca'].includes(data.subarray(0,4).toString('hex')))return 'binary';
 if(data.subarray(0,8).toString('hex')==='89504e470d0a1a0a'||data.subarray(0,2).toString('hex')==='ffd8')return 'image';
 if(/\.(zip|tar|tar\.gz|tgz)$/.test(ext)||data.subarray(0,2).toString()==='PK')return 'source';
 return 'script';
}
let accepting=false;
async function enqueue(body,user){
 const kind=body.kind||'auto';if(!TYPES.includes(kind))throw fail(400,'Choose a supported target type.');
 const url=typeof body.url==='string'?body.url.trim():'';
 if(url&&(body.files?.length))throw fail(400,'Choose either a URL or uploaded files for this run.');
 let targetType=kind,parsed;
 if(url){
  try{parsed=new URL(url);}catch{throw fail(400,'Enter a complete http:// or https:// URL.');}
  if(!['https:','http:'].includes(parsed.protocol)||parsed.username||parsed.password||!['','80','443'].includes(parsed.port)||url.length>2048)throw fail(400,'Use a public HTTP(S) URL without credentials or custom ports.');
  if(kind==='auto')targetType=/\.(zip|tgz|tar|tar\.gz)$/i.test(parsed.pathname)?'source':/\.git\/?$/.test(parsed.pathname)||parsed.hostname==='github.com'&&/^\/[^/]+\/[^/]+\/?$/.test(parsed.pathname)?'git':'web';
  if(!['web','git','source'].includes(targetType))throw fail(400,'This type requires a file upload.');
  if(targetType==='git'&&parsed.protocol!=='https:')throw fail(400,'Git acquisition requires an HTTPS URL.');
 }else if(!Array.isArray(body.files)||!body.files.length||body.files.length>300)throw fail(400,'Upload 1–300 files or enter a public URL.');
 try{const health=JSON.parse(await fs.readFile(path.join(ROOT,'.worker-health.json'),'utf8'));if(health.diskBytes>8*1024**3)throw fail(507,'Workspace reached its disk budget. Older runs expire after 24 hours.');}catch(e){if(Number.isInteger(e.code))throw e;}
 const prior=await jobs();if(prior.filter(j=>['queued','running'].includes(j.status)).length>=8)throw fail(429,'The queue is full. Please wait for a run to finish.');
 if(prior.length>=60||prior.reduce((s,j)=>s+(j.bytes||0),0)>2*1024**3)throw fail(507,'Workspace is full. Uploads and reports expire after 24 hours.');
 const names=new Set();let total=0;
 const files=(body.files||[]).map(f=>{
  const name=relativeName(f.name);if(names.has(name))throw fail(400,'Duplicate upload path.');names.add(name);
  if(typeof f.data!=='string'||f.data.length>MAX_BODY)throw fail(400,'Invalid file encoding.');
  const data=Buffer.from(f.data,'base64');if(data.toString('base64')!==f.data)throw fail(400,'Invalid file encoding.');
  total+=data.length;if(total>MAX_RAW)throw fail(413,'Upload limit is 48 MB total.');
  return{name,data,sha256:crypto.createHash('sha256').update(data).digest('hex')};
 });
 for(const n of names)for(const peer of names)if(n!==peer&&peer.startsWith(n+'/'))throw fail(400,'File and folder paths conflict.');
 if(!url&&kind==='auto')targetType=files.length>1?'source':sniff(files[0].name,files[0].data);
 if(['web','git'].includes(targetType)&&!url)throw fail(400,'This type requires a URL.');
 if(body.ai&&!process.env.REA_AI_ENABLED?.match(/^(1|true)$/i))throw fail(400,'Optional AI is not configured.');
 const id=crypto.randomUUID(),dir=path.join(ROOT,id),input=path.join(dir,'input');await fs.mkdir(input,{recursive:true});
 try{
  for(const f of files){const p=path.join(input,f.name);await fs.mkdir(path.dirname(p),{recursive:true});await fs.writeFile(p,f.data,{flag:'wx',mode:0o600});}
  const title=url?parsed.hostname:files[0].name;
  const job={id,schemaVersion:2,kind:targetType,requestedKind:kind,label:targetType.toUpperCase()+' analysis',title,created:new Date().toISOString(),status:'queued',stage:'Waiting for an available worker',progress:0,bytes:total,files:files.map(({name,data,sha256})=>({name,bytes:data.length,sha256})),version:'6.9.0'};
  await fs.writeFile(path.join(dir,'request.json'),JSON.stringify({id,kind:targetType,requestedKind:kind,url,ai:!!body.ai,files:job.files}),{mode:0o600});
  await save(job);return job;
 }catch(e){await fs.rm(dir,{recursive:true,force:true});throw e;}
}
async function streamFile(res,p,mime,name){
 const st=await fs.lstat(p);if(!st.isFile()||st.isSymbolicLink())throw fail(404,'Report not found.');
 res.writeHead(200,{'Content-Type':mime,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...(name?{'Content-Disposition':'attachment; filename="'+name+'"'}:{})});
 const stream=createReadStream(p);stream.on('error',()=>res.destroy());stream.pipe(res);
}
const app=http.createServer(async(req,res)=>{
 try{
  if(!['dev.auskal.tech','127.0.0.1:3180','localhost:3180'].includes(req.headers.host))throw fail(403,'Host rejected.');
  const u=new URL(req.url,'http://localhost'),get=['GET','HEAD'].includes(req.method);
  if(req.method==='POST'&&u.pathname==='/api/login')return await signIn(req,res);
  if(get&&u.pathname==='/login.js')return send(res,200,await fs.readFile('/app/login.js'),'text/javascript; charset=utf-8');
  if(get&&u.pathname==='/login'){
   if(signedIn(req)){res.writeHead(302,{Location:'/', 'Cache-Control':'no-store'});return res.end();}
   return send(res,200,await fs.readFile('/app/login.html'),'text/html; charset=utf-8');
  }
  if(!signedIn(req)){if(u.pathname.startsWith('/api/'))return send(res,401,{error:'Sign in to your REA workspace.'});res.writeHead(302,{Location:'/login','Cache-Control':'no-store'});return res.end();}
  if(req.method==='POST')checkOrigin(req);
  if(req.method==='POST'&&u.pathname==='/api/logout'){
   sessions.delete(sessionKey(req));await persistSessions();res.setHeader('Set-Cookie','__Host-rea_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0');return send(res,200,{ok:true});
  }
  if(get&&u.pathname==='/')return send(res,200,await fs.readFile('/app/unified/index.html'),'text/html; charset=utf-8');
  if(get&&u.pathname==='/app.js')return send(res,200,await fs.readFile('/app/unified/app.js'),'text/javascript; charset=utf-8');
  if(get&&u.pathname==='/api/status'){let worker=null;try{worker=JSON.parse(await fs.readFile(path.join(ROOT,'.worker-health.json'),'utf8'));}catch{}return send(res,200,{version:'2.0',reaVersion:'6.9.0',types:TYPES,maxBytes:MAX_RAW,retentionHours:24,timeoutSeconds:600,workerReady:!!worker&&Date.now()-Date.parse(worker.at)<600000,acknowledged:!!acknowledged.get(account(req)),aiEnabled:/^(1|true)$/i.test(process.env.REA_AI_ENABLED||'')});}
  if(req.method==='POST'&&u.pathname==='/api/acknowledge'){
   const b=await readJson(req,4096);if(b.accepted!==true)throw fail(400,'Acknowledge authorized use to continue.');
   acknowledged.set(account(req),{version:1,at:new Date().toISOString()});
   ackWrite=ackWrite.catch(()=>{}).then(()=>fs.writeFile(ACK_FILE,JSON.stringify([...acknowledged]),{mode:0o600}));await ackWrite;return send(res,200,{ok:true});
  }
  if(get&&u.pathname==='/api/jobs')return send(res,200,await jobs());
  const m=u.pathname.match(/^\/api\/jobs\/([a-f0-9-]{36})(\/report|\/artifacts\/([a-zA-Z0-9_.-]{1,100}))?$/);
  if(get&&m){
   const job=await metadata(m[1]);if(!m[2])return send(res,200,job);
   if(['running','queued'].includes(job.status))throw fail(409,'The analysis is still running.');
   const out=path.join(ROOT,m[1],job.schemaVersion===2?'output':'');
   if(m[3]){
    if(m[3].startsWith('.')||['progress.json','worker.log'].includes(m[3]))throw fail(404,'Artifact not found.');
    return await streamFile(res,path.join(out,m[3]),m[3].endsWith('.png')?'image/png':'application/octet-stream',m[3].endsWith('.png')&&u.searchParams.get('view')==='1'?null:m[3]);
   }
   const format=u.searchParams.get('format')||'json';if(!['json','html','pdf'].includes(format))throw fail(400,'Choose JSON, HTML, or PDF.');
   return await streamFile(res,path.join(out,'report.'+format),{json:'application/json',html:'text/html; charset=utf-8',pdf:'application/pdf'}[format],u.searchParams.has('download')||format!=='json'?'rea-'+job.id+'.'+format:null);
  }
  if(req.method==='POST'&&u.pathname==='/api/jobs'){
   if(!acknowledged.get(account(req)))throw fail(403,'Please acknowledge authorized use before starting an analysis.');
   if(accepting)throw fail(429,'Another upload is being saved. Retry shortly.');accepting=true;
   try{return send(res,202,await enqueue(await readJson(req),account(req)));}finally{accepting=false;}
  }
  send(res,404,{error:'Not found.'});
 }catch(e){console.error('request failed',e.code||500,e.message);if(!res.headersSent)send(res,e.code==='ENOENT'?404:Number.isInteger(e.code)?e.code:500,{error:e.code==='ENOENT'?'File not found or expired.':Number.isInteger(e.code)?e.message:'Request failed. Try again or check the service logs.'});}
});
app.requestTimeout=60000;
app.listen(3180,'0.0.0.0',()=>console.log('Unified REA dashboard listening on 3180'));
