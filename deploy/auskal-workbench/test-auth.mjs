import http from 'node:http';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
const base='http://127.0.0.1:3180';
const auth=http.createServer((req,res)=>{
  const valid=req.headers.authorization==='Basic '+Buffer.from('fixture-user:fixture-password').toString('base64');
  res.writeHead(valid?200:401);res.end(valid?'ok':'invalid');
});
await new Promise(r=>auth.listen(3181,'127.0.0.1',r));
let app;
function start(){app=spawn('node',['/app/server.mjs'],{env:{...process.env,REA_AUTH_VERIFY_URL:'http://127.0.0.1:3181/verify'},stdio:['ignore','inherit','inherit']});}
async function ready(){for(let i=0;i<50;i++){try{if((await request('/login')).status===200)return;}catch{}await new Promise(r=>setTimeout(r,100));}throw Error('App did not start');}
async function stop(){const p=app;if(!p || p.exitCode!==null)return;await new Promise(r=>{p.once('exit',r);p.kill('SIGTERM');});}
async function request(route,body,cookie,extra={}){
  const headers={'Host':'dev.auskal.tech','Origin':'https://dev.auskal.tech','X-REA-Request':'workbench',...extra};
  if(body!==undefined)headers['Content-Type']='application/json';
  if(cookie)headers.Cookie=cookie;
  return fetch(base+route,{method:body===undefined?'GET':'POST',headers,body:body===undefined?undefined:JSON.stringify(body),redirect:'manual'});
}
try{
  start();await ready();
  assert.equal((await request('/')).status,302);
  assert.equal((await request('/api/jobs')).status,401);
  let r=await request('/api/login',{username:'fixture-user',password:'wrong'});
  assert.equal(r.status,401);assert.equal(r.headers.get('www-authenticate'),null);
  assert.equal((await request('/api/login',{username:'fixture-user',password:'fixture-password'},null,{Origin:'https://untrusted.example'})).status,403);
  r=await request('/api/login',{username:'fixture-user',password:'fixture-password'});
  assert.equal(r.status,200);
  const cookieHeader=r.headers.get('set-cookie');
  assert.match(cookieHeader,/HttpOnly/);assert.match(cookieHeader,/Secure/);assert.match(cookieHeader,/SameSite=Strict/);
  const cookie=cookieHeader.split(';')[0];
  assert.equal((await request('/api/status',undefined,cookie)).status,200);
  assert.equal((await request('/',undefined,cookie)).status,200);
  assert.equal((await request('/login',undefined,cookie)).status,302);
  await stop();start();await ready();
  assert.equal((await request('/api/status',undefined,cookie)).status,200);
  console.log('PASS: login page, unauthenticated protection, invalid login, CSRF, secure cookie, session persistence');
  for(const body of [
    {mode:'artifact',files:[{name:'../escape',data:'YWJj'}]},
    {mode:'shell',files:[]}
  ])assert.equal((await request('/api/jobs',body,cookie)).status,400);
  const body={mode:'javascript',files:[
    {name:'package.json',data:Buffer.from('{"type":"module","name":"rea-auth-fixture"}').toString('base64')},
    {name:'sample.js',data:Buffer.from('export const greeting = "Hello AusKal";').toString('base64')}
  ]};
  r=await request('/api/jobs',body,cookie);assert.equal(r.status,202);
  let job=await r.json();
  for(let i=0;i<65;i++){await new Promise(r=>setTimeout(r,1000));job=await (await request('/api/jobs/'+job.id,undefined,cookie)).json();if(job.status!=='running')break;}
  assert.equal(job.status,'complete',JSON.stringify(job));
  r=await request('/api/jobs/'+job.id+'/report',undefined,cookie);assert.equal(r.status,200);
  const report=await r.json();assert.ok(report.result.evidence_id);
  console.log('PASS: authenticated REA analysis, report download, traversal and command rejection');
  assert.equal((await request('/api/logout',{},cookie)).status,200);
  assert.equal((await request('/api/jobs',undefined,cookie)).status,401);
  console.log('PASS: sign-out revokes session');
}finally{await stop();auth.close();}
