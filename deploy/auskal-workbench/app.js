const $ = id => document.getElementById(id);
let modes = {}, chosen = [], active, timer, submitting = false;
const bytes = n => n >= 1048576 ? (n/1048576).toFixed(1)+' MB' : (n/1024).toFixed(1)+' KB';
async function api(url, options) {
  const r = await fetch(url, options);
  if (r.status === 401) throw Error('Sign in using your existing GodsEye credentials, then reload.');
  const d = await r.json(); if (!r.ok) throw Error(d.error || 'Request failed.'); return d;
}
function message(text, error=false) { $('status').textContent=text; $('status').className='status '+(error?'error':''); }
function modeChange() { $('hint').textContent=modes[$('mode').value]?.hint || ''; }
function choose(files) {
  chosen = Array.from(files);
  $('selected').textContent = chosen.length ? chosen.length+' file(s) · '+bytes(chosen.reduce((s,f)=>s+f.size,0))+'\n'+chosen.slice(0,6).map(f=>f.webkitRelativePath||f.name).join('\n') : 'No files selected';
  $('analyze').disabled=!chosen.length || submitting;
  if (chosen.length > 1) { $('mode').value='javascript'; modeChange(); }
  message('');
}
$('choose').onclick=()=>$('files').click();
$('folder').onclick=()=>$('directory').click();
$('files').onchange=e=>choose(e.target.files);
$('directory').onchange=e=>{choose(e.target.files); $('mode').value='javascript'; modeChange();};
$('mode').onchange=modeChange;
$('demo').onclick=()=>{
  choose([new File(['{"name":"rea-demo","type":"module","version":"1.0.0"}'],'package.json',{type:'application/json'}),
    new File(['export function greet(name) { return "Hello, " + name; }\nexport const version = "1.0.0";'],'sample.js',{type:'text/javascript'})]);
  $('mode').value='javascript';modeChange();$('analyze').click();
};
$('refresh').onclick=()=>history().catch(e=>message(e.message,true));
function fileData(file) { return new Promise((resolve,reject)=>{const reader=new FileReader();reader.onerror=()=>reject(Error('Could not read '+file.name));reader.onload=()=>resolve({name:file.webkitRelativePath||file.name,data:reader.result.split(',')[1]});reader.readAsDataURL(file);}); }
$('analyze').onclick=async()=>{
  if (submitting) return;
  if (!chosen.length) return message('Choose your files first.',true);
  if (chosen.length>300 || chosen.reduce((s,f)=>s+f.size,0)>48*1048576) return message('Choose up to 300 files, 48 MB total.',true);
  if (!modes[$('mode').value].folder && chosen.length!==1) return message('This analysis takes one file. Choose JavaScript / Electron for a folder.',true);
  submitting=true; $('analyze').disabled=true; $('choose').disabled=true; $('folder').disabled=true;
  try {
    message('Preparing files…');
    const files=[]; for (const file of chosen) files.push(await fileData(file));
    message('Uploading and starting analysis…');
    const job=await api('/api/jobs',{method:'POST',headers:{'Content-Type':'application/json','X-REA-Request':'workbench'},body:JSON.stringify({mode:$('mode').value,files})});
    message('Analysis started. You can follow the results here.');
    await show(job.id); await history();
  } catch(e) { message(e.message,true); }
  finally { submitting=false; $('analyze').disabled=!chosen.length; $('choose').disabled=false; $('folder').disabled=false; }
};
function fact(label,value,hash=false) {
  const div=document.createElement('div'); div.className='fact'+(hash?' hash':'');
  const small=document.createElement('small');small.textContent=label;
  const text=document.createElement('div');text.textContent=value;
  div.append(small,text);$('facts').append(div);
}
async function show(id) {
  clearTimeout(timer);active=id;
  try {
    const job=await api('/api/jobs/'+id);
    if (active!==id) return;
    $('empty').hidden=true;$('result').hidden=false;$('facts').replaceChildren();
    fact('Analysis',job.label);fact('Status',job.status);
    fact('Files',job.files.length+' · '+bytes(job.bytes));fact('Time',job.durationMs!=null?(job.durationMs/1000).toFixed(1)+' seconds':new Date(job.created).toLocaleString());
    fact('Input',job.files.map(f=>f.name).join(', '));
    if(job.files.length===1) fact('SHA-256',job.files[0].sha256,true);
    $('download').hidden=job.status==='running'||job.status==='interrupted';
    $('download').href='/api/jobs/'+id+'/report';
    $('report-status').textContent=job.error || (job.status==='running'?'Inspecting your files. This can take up to two minutes.':job.status==='complete'?'Analysis complete. Review the evidence and its stated limitations.':'Analysis could not complete. See the diagnostic details below.');
    $('report-status').className='status '+(job.status==='failed'?'error':job.status==='complete'?'success':'running');
    if(job.status==='running') {
      $('output').textContent='Waiting for REA…';
      timer=setTimeout(async()=>{await show(id);await history().catch(()=>{});},2000);
    } else if(job.status==='interrupted') $('output').textContent=job.error;
    else {
      const report=await api('/api/jobs/'+id+'/report');
      if(active===id) $('output').textContent=JSON.stringify(report.result,null,2)+(report.diagnostics?'\n\nDiagnostics\n'+report.diagnostics:'');
    }
  }catch(e){message(e.message,true);}
}
async function history() {
  const jobs=await api('/api/jobs');$('history').replaceChildren();
  if(!jobs.length){const p=document.createElement('p');p.textContent='No analyses yet.';$('history').append(p);}
  for(const job of jobs) {
    const b=document.createElement('button');b.type='button';
    const name=document.createElement('span');name.className='name';name.textContent=job.files[0]?.name||job.label;
    const badge=document.createElement('span');badge.className='badge '+job.status;badge.textContent=job.status;
    b.append(name,badge);b.onclick=()=>show(job.id);$('history').append(b);
  }
}
(async()=>{try{
  const status=await api('/api/status');modes=status.modes;
  $('runtime').textContent='● REA '+status.version+' ready';$('mode').replaceChildren();
  for(const [value,m] of Object.entries(modes)){const option=document.createElement('option');option.value=value;option.textContent=m.label;$('mode').append(option);}
  $('mode').disabled=false;modeChange();await history();
}catch(e){$('runtime').textContent='Connection unavailable';message(e.message,true);}})();
