import http from 'node:http';
import { promises as fs, createReadStream } from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';

const ROOT = '/data';
const MODES = {
  artifact: { label: 'Artifact overview', command: 'inspect-artifact', hint: 'Identify a file, inspect its structure, and discover available observations.' },
  javascript: { label: 'JavaScript / Electron', command: 'analyze-javascript-application', folder: true, hint: 'Upload a JavaScript project folder or ASAR. Inspect modules, imports, and Electron boundaries.' },
  hardening: { label: 'Binary security', command: 'inspect-binary-hardening', hint: 'Inspect ELF, PE, or Mach-O security flags without executing the file.' },
  layout: { label: 'Binary layout', command: 'inspect-binary-layout', hint: 'Inspect native binary sections, segments, and linked layout.' },
  entropy: { label: 'Byte entropy', command: 'inspect-byte-entropy', hint: 'Measure file-wide and block entropy.' },
  managed: { label: '.NET assembly', command: 'inspect-managed-artifact', hint: 'Inspect PE/CLI identity and metadata without loading the target.' },
  members: { label: '.NET members', command: 'inspect-managed-members', hint: 'Inspect types, methods, signatures, and CIL anchors.' },
  apk: { label: 'APK signatures', command: 'inspect-apk-signature', hint: 'Inspect declared Android signing schemes, certificates, and digests.' },
  flutter: { label: 'Flutter build', command: 'identify-flutter-build', hint: 'Identify Dart snapshot hashes and Flutter engine facts from an APK.' },
  elf: { label: 'ELF notes', command: 'inspect-elf-notes', hint: 'Read ELF note identities and GNU build metadata.' },
  api: { label: 'API specification', command: 'inspect-api-contract', hint: 'Inspect a local OpenAPI JSON or GraphQL SDL specification offline.' },
  crash: { label: 'Apple crash report', command: 'inspect-apple-ips', hint: 'Inspect an Apple .ips crash report.' }
};
const MAX_RAW = 48 * 1024 * 1024, MAX_BODY = 68 * 1024 * 1024;
const ID = /^[a-f0-9-]{36}$/;
let busy = false;
await fs.mkdir(ROOT, { recursive: true });
async function metadata(id) { return JSON.parse(await fs.readFile(path.join(ROOT, id, 'job.json'), 'utf8')); }
async function save(job) {
  const p = path.join(ROOT, job.id, 'job.json');
  await fs.writeFile(p + '.tmp', JSON.stringify(job)); await fs.rename(p + '.tmp', p);
}
async function jobs() {
  const out = [];
  for (const name of await fs.readdir(ROOT)) {
    if (ID.test(name)) try { out.push(await metadata(name)); } catch {}
  }
  return out.sort((a,b) => b.created.localeCompare(a.created));
}
for (const job of await jobs()) if (job.status === 'running') {
  job.status = 'interrupted'; job.error = 'Service restarted before this analysis finished.'; await save(job);
}
async function cleanup() {
  for (const job of await jobs()) if (job.status !== 'running' && Date.now() - Date.parse(job.created) > 86400000)
    await fs.rm(path.join(ROOT, job.id), { recursive: true, force: true });
}
await cleanup();
const cleanupTimer = setInterval(() => cleanup().catch(console.error), 3600000);
cleanupTimer.unref();
function send(res, code, data, type = 'application/json') {
  res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin', 'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'" });
  res.end(type === 'application/json' ? JSON.stringify(data) : data);
}
function fail(code, message) { return Object.assign(new Error(message), { code }); }
async function readJson(req, limit=MAX_BODY) {
  if (req.headers['content-type'] !== 'application/json') throw fail(415, 'Send application/json.');
  if (Number(req.headers['content-length']) > limit) throw fail(413, 'Upload limit is 48 MB.');
  let size = 0; const chunks = [];
  for await (const chunk of req) { size += chunk.length; if (size > limit) throw fail(413, 'Upload limit is 48 MB.'); chunks.push(chunk); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw fail(400, 'Invalid JSON request.'); }
}
function relativeName(name) {
  if (typeof name !== 'string' || name.length > 500 || /[\x00-\x1f\\]/.test(name) || path.posix.isAbsolute(name) ||
      name.split('/').some(x => !x || x === '.' || x === '..')) throw fail(400, 'Invalid upload path.');
  return name;
}
async function launch(body) {
  const mode = MODES[body.mode];
  if (!mode) throw fail(400, 'Choose a supported analysis.');
  if (!Array.isArray(body.files) || !body.files.length || body.files.length > 300) throw fail(400, 'Choose 1 to 300 files.');
  if (!mode.folder && body.files.length !== 1) throw fail(400, 'This analysis takes one file. Choose JavaScript / Electron for a project folder.');
  const names = new Set(); let total = 0;
  const decoded = body.files.map(file => {
    const name = relativeName(file.name);
    if (names.has(name)) throw fail(400, 'Duplicate file path.'); names.add(name);
    if (typeof file.data !== 'string' || file.data.length > MAX_BODY || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(file.data))
      throw fail(400, 'Invalid file encoding.');
    const data = Buffer.from(file.data, 'base64'); total += data.length;
    if (total > MAX_RAW) throw fail(413, 'Upload limit is 48 MB total.');
    return { name, data, sha256: crypto.createHash('sha256').update(data).digest('hex') };
  });
  for (const name of names) for (const peer of names) if (name !== peer && peer.startsWith(name + '/')) throw fail(400, 'File and directory paths conflict.');
  const prior = await jobs();
  if (prior.length >= 50 || prior.reduce((sum,j) => sum + (j.bytes || 0), 0) + total > 768 * 1024 * 1024)
    throw fail(507, 'Workspace is full. Reports and uploads expire after 24 hours.');
  const id = crypto.randomUUID(), dir = path.join(ROOT, id), input = path.join(dir, 'input');
  await fs.mkdir(input, { recursive: true });
  try {
    for (const f of decoded) {
      const dest = path.join(input, f.name); await fs.mkdir(path.dirname(dest), { recursive: true }); await fs.writeFile(dest, f.data, { flag: 'wx', mode: 0o600 });
    }
    const target = mode.folder && !(decoded.length === 1 && decoded[0].name.endsWith('.asar')) ? input : path.join(input, decoded[0].name);
    const job = { id, mode: body.mode, label: mode.label, command: mode.command, created: new Date().toISOString(), status: 'running',
      bytes: total, files: decoded.map(({name,data,sha256}) => ({name,bytes:data.length,sha256})), version: '6.9.0' };
    await save(job);
    execute(job, [mode.command, target, '--format', 'json']).catch(async err => {
      job.status = 'failed'; job.error = err.message; await save(job).catch(console.error); busy = false;
    });
    return job;
  } catch (err) { await fs.rm(dir, {recursive:true,force:true}); throw err; }
}
async function execute(job, args) {
  const start = Date.now(), chunks = [], errors = []; let bytes = 0, errBytes = 0, reason;
  const child = spawn('rea', args, { cwd: path.join(ROOT,job.id), detached:true, stdio:['ignore','pipe','pipe'],
    env: { PATH: process.env.PATH, HOME: '/tmp', TMPDIR:'/tmp', LANG:'C.UTF-8', NO_COLOR:'1' } });
  const kill = why => { reason ||= why; try { process.kill(-child.pid, 'SIGKILL'); } catch {} };
  const timer = setTimeout(() => kill('Analysis exceeded the 120 second limit.'), 120000);
  child.stdout.on('data', chunk => { bytes += chunk.length; if (bytes > 12 * 1024 * 1024) kill('Report exceeded the 12 MB display limit.'); else chunks.push(chunk); });
  child.stderr.on('data', chunk => { errBytes += chunk.length; if (errBytes < 128*1024) errors.push(chunk); });
  const outcome = await new Promise(resolve => {
    child.once('error', e => resolve({error:e.message,code:null}));
    child.once('close', (code,signal) => resolve({code,signal}));
  });
  clearTimeout(timer);
  // Close any children retained by a provider after its parent exits.
  try { process.kill(-child.pid, 'SIGKILL'); } catch {}
  const stdout = Buffer.concat(chunks).toString('utf8'), stderr = Buffer.concat(errors).toString('utf8');
  let result;
  try { result = JSON.parse(stdout); } catch { result = { output: stdout }; }
  job.finished = new Date().toISOString(); job.durationMs = Date.now()-start; job.exitCode = outcome.code;
  job.status = !reason && !outcome.error && outcome.code === 0 ? 'complete' : 'failed';
  if (reason || outcome.error) job.error = reason || outcome.error;
  const report = { analysis: job, result, diagnostics: stderr };
  await fs.writeFile(path.join(ROOT,job.id,'report.json'), JSON.stringify(report,null,2), {mode:0o600});
  await save(job); busy = false;
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

const app = http.createServer(async (req,res) => {
  try {
    if (!['dev.auskal.tech','127.0.0.1:3180','localhost:3180'].includes(req.headers.host)) throw fail(403, 'Host rejected.');
    const url = new URL(req.url, 'http://localhost');
    if(req.method==='POST' && url.pathname==='/api/login') return await signIn(req,res);
    if((req.method==='GET' || req.method==='HEAD') && url.pathname==='/login.js') return send(res,200,await fs.readFile('/app/login.js'),'text/javascript; charset=utf-8');
    if((req.method==='GET' || req.method==='HEAD') && url.pathname==='/login') {
      if(signedIn(req)) { res.writeHead(302,{Location:'/', 'Cache-Control':'no-store'});return res.end(); }
      return send(res,200,await fs.readFile('/app/login.html'),'text/html; charset=utf-8');
    }
    if(!signedIn(req)) {
      if(url.pathname.startsWith('/api/')) return send(res,401,{error:'Sign in to your REA workspace.'});
      res.writeHead(302,{Location:'/login','Cache-Control':'no-store'});return res.end();
    }
    if(req.method==='POST' && url.pathname==='/api/logout') {
      checkOrigin(req);sessions.delete(sessionKey(req));await persistSessions();
      res.setHeader('Set-Cookie','__Host-rea_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0');
      return send(res,200,{ok:true});
    }
    if ((req.method === 'GET' || req.method === 'HEAD') && url.pathname === '/') return send(res,200,await fs.readFile('/app/index.html'),'text/html; charset=utf-8');
    if ((req.method === 'GET' || req.method === 'HEAD') && url.pathname === '/app.js') return send(res,200,await fs.readFile('/app/app.js'),'text/javascript; charset=utf-8');
    if ((req.method === 'GET' || req.method === 'HEAD') && url.pathname === '/api/status') return send(res,200,{version:'6.9.0',busy,modes:MODES,maxBytes:MAX_RAW,retentionHours:24});
    if ((req.method === 'GET' || req.method === 'HEAD') && url.pathname === '/api/jobs') return send(res,200,await jobs());
    const match = url.pathname.match(/^\/api\/jobs\/([a-f0-9-]{36})(\/report)?$/);
    if ((req.method === 'GET' || req.method === 'HEAD') && match) {
      const job = await metadata(match[1]);
      if (!match[2]) return send(res,200,job);
      if (job.status === 'running') return send(res,409,{error:'Analysis is still running.'});
      const p = path.join(ROOT,match[1],'report.json'); await fs.access(p);
      res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
        'Content-Disposition':'attachment; filename="rea-'+match[1]+'.json"'});
      const stream = createReadStream(p); stream.on('error', () => res.destroy()); return stream.pipe(res);
    }
    if (req.method === 'POST' && url.pathname === '/api/jobs') {
      if (req.headers.origin !== 'https://dev.auskal.tech' || req.headers['x-rea-request'] !== 'workbench') throw fail(403,'Request origin rejected.');
      if (busy) throw fail(409,'Another analysis is running. Please wait.');
      busy = true;
      try { return send(res,202,await launch(await readJson(req))); } catch(err) { busy=false; throw err; }
    }
    send(res,404,{error:'Not found.'});
  } catch(err) { if (!res.headersSent) send(res,err.code === 'ENOENT' ? 404 : Number.isInteger(err.code) ? err.code : 500,{error:Number.isInteger(err.code) ? err.message : err.code === 'ENOENT' ? 'Not found.' : 'Request failed. Check the selected files.'}); }
});
app.requestTimeout=60000;
app.listen(3180,'0.0.0.0',()=>console.log('REA workbench listening on 3180'));
