// Isolated test-only account verifier; never used by production.
import http from 'node:http';
import {spawn} from 'node:child_process';
const fake=http.createServer((req,res)=>{const valid=req.headers.authorization==='Basic '+Buffer.from('fixture-user:fixture-password').toString('base64');res.writeHead(valid?200:401);res.end(valid?'ok':'invalid');});
await new Promise(r=>fake.listen(3181,'127.0.0.1',r));
const app=spawn('node',['/app/unified/server.mjs'],{env:{...process.env,REA_AUTH_VERIFY_URL:'http://127.0.0.1:3181/verify'},stdio:'inherit'});
process.on('SIGTERM',()=>{app.kill();fake.close();});app.on('exit',code=>process.exit(code||0));
