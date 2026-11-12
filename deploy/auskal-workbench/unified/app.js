const $=id=>document.getElementById(id);
const HINTS={auto:'Detection uses file content, package structure, extension, and URL.',web:'Passive fetch and headless render, headers, technology indicators, JavaScript and endpoint review.',source:'Safe extraction, file tree, manifest/dependency inventory, gitleaks and Semgrep.',git:'Public HTTPS clone, pinned revision, source inventory and security scanning. No build scripts run.',binary:'LIEF metadata, imports/exports, sections, strings, entropy and REA hardening checks.',android:'Manifest and permissions, network config, JADX decompilation, resources and secret scanning.',ios:'Info.plist, ATS, frameworks, available entitlements and strings. Deep iOS decompilation is limited on Linux.',script:'Source inventory, JavaScript module evidence where applicable, SAST and exposed-secret patterns.',image:'Tesseract OCR, image metadata and a text-based security review. Optional visual AI requires configuration.'};
let files=[],active=null,poll=null,knownJobs=[],acknowledged=false,submitting=false;
const bytes=n=>n>=1048576?(n/1048576).toFixed(1)+' MB':Math.ceil(n/1024)+' KB';
function node(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=String(text);if(cls)e.className=cls;return e;}
function message(text,error=false){$('message').textContent=text;$('message').className='status'+(error?' error':'');}
async function api(url,options){const r=await fetch(url,options);if(r.status===401){location.assign('/login');throw Error('Please sign in again.');}let d;try{d=await r.json();}catch{throw Error('The server could not complete this request.');}if(!r.ok)throw Error(d.error||'Request failed.');return d;}
const post=(url,body)=>api(url,{method:'POST',headers:{'Content-Type':'application/json','X-REA-Request':'workbench'},body:JSON.stringify(body)});
function choose(list){files=Array.from(list);if(files.length)$('url').value='';$('selected').textContent=files.length?files.length+' file(s) · '+bytes(files.reduce((s,f)=>s+f.size,0))+'\n'+files.slice(0,8).map(f=>f.webkitRelativePath||f.name).join('\n'):'No files selected. You can also paste a screenshot.';message('');}
$('choose').onclick=()=>$('files').click();$('folder').onclick=()=>$('directory').click();$('files').onchange=e=>choose(e.target.files);$('directory').onchange=e=>choose(e.target.files);
$('url').oninput=()=>{if($('url').value&&files.length){files=[];$('selected').textContent='Using the URL above for this run.';}};
$('kind').onchange=()=>$('hint').textContent=HINTS[$('kind').value];
for(const event of ['dragenter','dragover'])$('drop').addEventListener(event,e=>{e.preventDefault();$('drop').classList.add('over');});
for(const event of ['dragleave','drop'])$('drop').addEventListener(event,e=>{e.preventDefault();$('drop').classList.remove('over');});
$('drop').addEventListener('drop',e=>{if(e.dataTransfer.files.length)choose(e.dataTransfer.files);else{const text=e.dataTransfer.getData('text/plain');if(/^https?:\/\//i.test(text)){$('url').value=text.trim();choose([]);}}});
document.addEventListener('paste',e=>{const images=Array.from(e.clipboardData?.files||[]).filter(f=>f.type.startsWith('image/'));if(images.length){e.preventDefault();choose(images);}});
$('sample').onclick=()=>{choose([new File(['{"name":"auskal-sample","version":"1.0.0","type":"module"}'],'package.json'),new File(['export function greet(name) { return "Hello " + name; }\nexport const api = "/api/v1/example";'],'sample.js'),new File(['import subprocess\ndef unsafe_demo(user_input):\n    subprocess.run(user_input, shell=True)\n'],'review-example.py')]);$('kind').value='auto';$('kind').onchange();message('Sample loaded. Click Analyze target to begin.');};
function fileData(f){return new Promise((resolve,reject)=>{const r=new FileReader();r.onerror=()=>reject(Error('Could not read '+f.name));r.onload=()=>resolve({name:f.webkitRelativePath||f.name,data:r.result.split(',')[1]});r.readAsDataURL(f);});}
$('analyze').onclick=async()=>{
 if(submitting)return;
 if(!acknowledged){$('ack').showModal();return;}
 const url=$('url').value.trim();if(!url&&!files.length)return message('Paste a public URL or choose your files first.',true);
 if(files.length>300||files.reduce((s,f)=>s+f.size,0)>48*1048576)return message('Limit: 48 MB total and 300 uploaded files.',true);
 submitting=true;$('analyze').disabled=true;
 try{message('Preparing your target…');const uploaded=[];for(const f of files)uploaded.push(await fileData(f));const job=await post('/api/jobs',{kind:$('kind').value,url,files:uploaded,ai:$('ai').checked});message('Added to the queue. Progress appears in the report panel.');await show(job.id);await refreshHistory();}
 catch(e){message(e.message,true);}finally{submitting=false;$('analyze').disabled=false;}
};
$('logout').onclick=async()=>{try{await post('/api/logout',{});location.assign('/login');}catch(e){message(e.message,true);}};
$('ack-check').onchange=()=>$('ack-submit').disabled=!$('ack-check').checked;
$('ack').addEventListener('cancel',e=>e.preventDefault());
$('ack-submit').onclick=async()=>{try{await post('/api/acknowledge',{accepted:$('ack-check').checked});acknowledged=true;$('ack').close();}catch(e){$('ack-error').textContent=e.message;}};
$('refresh').onclick=()=>refreshHistory().catch(e=>message(e.message,true));$('filter').oninput=renderHistory;
async function refreshHistory(){knownJobs=await api('/api/jobs');renderHistory();}
function renderHistory(){const q=$('filter').value.toLowerCase();$('history').replaceChildren();for(const j of knownJobs.filter(j=>(j.title||j.files?.[0]?.name||j.label||'').toLowerCase().includes(q)||String(j.kind||'').includes(q))){const b=node('button');const name=node('span',undefined,'name');name.append(node('span',j.title||j.files?.[0]?.name||j.label),node('small',new Date(j.created).toLocaleString()));b.append(name,node('span',j.status,'badge '+j.status));b.onclick=()=>show(j.id);$('history').append(b);}if(!$('history').children.length)$('history').append(node('p','No matching runs yet.'));}
function stat(value,label,cls){const e=node('div',undefined,'stat');e.append(node('b',value,cls),node('small',label));return e;}
function prettyData(data){const pre=node('pre',JSON.stringify(data,null,2));return pre;}
function reportView(report,job){
 $('findings').replaceChildren();$('sections').replaceChildren();$('stats').replaceChildren();$('artifacts').replaceChildren();$('previews').replaceChildren();$('limitations').replaceChildren();
 if(report.schemaVersion!==2){$('summary').textContent='Report from the previous REA interface.';$('sections').append(prettyData(report.result||report));return;}
 $('summary').textContent=report.summary?.text||'';const counts=report.summary?.counts||{};
 $('stats').append(stat(counts.high||0,'HIGH','high'),stat(counts.medium||0,'MEDIUM','medium'),stat((counts.low||0)+(counts.info||0),'LOW / INFO','low'),stat(report.sections.length,'ANALYZER SECTIONS'));
 if(report.findings?.length){$('findings').append(node('h3','Findings to review'));for(const f of report.findings.slice(0,100)){const e=node('article',undefined,'finding '+f.severity);e.append(node('strong',f.severity.toUpperCase()+' · '+f.title),node('p',f.detail),node('small',f.location),node('p',f.recommendation));$('findings').append(e);}}
 for(const section of report.sections){const details=node('details');const summary=node('summary');summary.append(node('strong',section.title),node('span',section.status.replaceAll('_',' '),'badge '+section.status));const content=node('div',undefined,'section-body');if(section.summary)content.append(node('p',section.summary));if(section.id==='ocr')content.append(node('pre',section.data.text));content.append(prettyData(section.data));for(const note of section.limitations||[])content.append(node('p','Coverage: '+note));details.append(summary,content);if(['ocr','http','binary','android','ios'].includes(section.id))details.open=true;$('sections').append(details);}
 for(const a of report.artifacts||[]){const link=node('a',a.description+' ↓','button');link.href='/api/jobs/'+job.id+'/artifacts/'+encodeURIComponent(a.name);$('artifacts').append(link);if(['website.png','ocr-input.png'].includes(a.name)){const img=node('img');img.className='preview';img.alt=a.description;img.src=link.href+'?view=1';$('previews').append(img);}}
 if(report.limitations?.length){$('limitations').append(node('h3','Coverage & limitations'));const ul=node('ul');for(const text of report.limitations)ul.append(node('li',text));$('limitations').append(ul);}
}
async function show(id){
 clearTimeout(poll);active=id;
 try{
  const job=await api('/api/jobs/'+id);if(active!==id)return;
  $('empty').hidden=true;$('result').hidden=false;$('report-title').textContent=job.title||job.files?.[0]?.name||job.label;
  $('report-meta').textContent=(job.detectedType||job.kind||job.label)+' · '+new Date(job.created).toLocaleString()+(job.durationMs?' · '+(job.durationMs/1000).toFixed(1)+' seconds':'');
  const running=['queued','running'].includes(job.status);$('work').hidden=!running;$('downloads').hidden=running;
  $('stage').textContent=job.stage||job.status;const progress=Math.max(0,Math.min(100,job.progress||0));$('percent').textContent=progress+'%';$('bar').style.width=progress+'%';
  $('report-error').className='status '+(job.error?'error':'');$('report-error').textContent=job.error||'';
  if(running){$('summary').textContent=job.stage||'Waiting for a worker';for(const n of ['findings','sections','stats','artifacts','previews','limitations'])$(n).replaceChildren();poll=setTimeout(async()=>{await show(id);await refreshHistory().catch(()=>{});},1800);}
  else{for(const format of ['json','html','pdf']){$(format).href='/api/jobs/'+id+'/report?format='+format+'&download=1';$(format).hidden=job.schemaVersion!==2&&format!=='json';}try{const report=await api('/api/jobs/'+id+'/report');if(active===id)reportView(report,job);}catch(e){$('report-error').textContent=job.error||e.message;$('downloads').hidden=true;}}
 }catch(e){message(e.message,true);}
}
(async()=>{try{const status=await api('/api/status');acknowledged=status.acknowledged;$('engine').textContent='● QUEUED WORKERS READY';$('ai').disabled=!status.aiEnabled;if(status.aiEnabled)$('ai-label').textContent='Send redacted findings (and this screenshot, if selected) to Anthropic for an optional AI review. API charges may apply.';await refreshHistory();if(!acknowledged)$('ack').showModal();}catch(e){$('engine').textContent='Connection unavailable';message(e.message,true);}})();
