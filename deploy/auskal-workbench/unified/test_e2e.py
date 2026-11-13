"""Authenticated submission → durable queue → real engines → report downloads."""
import base64,datetime,json,os,pathlib,time,urllib.error,urllib.request
BASE=os.environ['REA_TEST_BASE'];FIX=pathlib.Path('/opt/rea-workbench/unified/fixtures');COOKIE=None
RESULTS=json.loads(pathlib.Path('/opt/rea-workbench/unified/e2e-results.json').read_text()) if os.environ.get('REA_TEST_START') else []
def request(route,body=None):
 headers={'Host':'dev.auskal.tech','Origin':'https://dev.auskal.tech','X-REA-Request':'workbench'}
 if COOKIE:headers['Cookie']=COOKIE
 if body is not None:headers['Content-Type']='application/json'
 req=urllib.request.Request(BASE+route,data=json.dumps(body).encode() if body is not None else None,headers=headers)
 return urllib.request.urlopen(req,timeout=30)
def api(route,body=None):
 with request(route,body) as r:return json.load(r)
def wait(job):
 for _ in range(330):
  state=api('/api/jobs/'+job['id'])
  if state['status'] not in ('queued','running'):return state
  time.sleep(2)
 raise AssertionError('Queue did not finish within test timeout')
def run(label,name=None,url=None,kind='auto',expect=None):
 start=time.monotonic();data={'kind':kind,'files':[],'url':url or ''}
 if name:
  p=FIX/name;data['files']=[{'name':p.name,'data':base64.b64encode(p.read_bytes()).decode()}]
 job=api('/api/jobs',data);print('START',label,job['id'],flush=True)
 state=wait(job);report=api('/api/jobs/'+job['id']+'/report')
 assert state['status']=='complete',(label,state.get('error'),report.get('error'))
 assert report['status']=='complete'
 sections={s['id']:s for s in report['sections']}
 if expect:expect(report,sections)
 for fmt,magic in [('json',b'{'),('html',b'<!doctype html'),('pdf',b'%PDF')]:
  with request('/api/jobs/'+job['id']+'/report?format='+fmt+'&download=1') as r:
   content=r.read();assert content.startswith(magic),(label,fmt,content[:80]);assert len(content)>100
 for key in ['secrets','sast']:
  if key in sections:assert sections[key]['status']=='complete',(label,key,sections[key])
 RESULTS[:]=[x for x in RESULTS if x['sample']!=label]
 RESULTS.append({'sample':label,'runId':job['id'],'type':report['targetType'],'seconds':round(time.monotonic()-start,1),'sections':[{k:s[k] for k in ['id','status']} for s in report['sections']],'findings':len(report['findings']),'downloads':['json','html','pdf'],'status':'passed'})
 print('PASS',label,round(time.monotonic()-start,1),'seconds',flush=True)
 pathlib.Path('/opt/rea-workbench/unified/e2e-results.json').write_text(json.dumps(RESULTS,indent=2))
def has_source(r,s):
 assert s['inventory']['data']['manifests'];assert s['sast']['data']['matches']>=1,(s['sast'])
def has_binary(r,s):assert not s['binary']['data'].get('parseError'),s['binary']['data'];assert s['binary']['data']['file']
def has_android(r,s):assert s['android']['data']['package'];assert s['jadx']['data'].get('classes',0)>0,s['jadx']
def has_ios(r,s):assert s['ios']['data']['bundle']['CFBundleIdentifier']=='tech.auskal.fixture';assert s['ios']['data']['entitlements']
def has_ocr(r,s):assert 'AUSKAL' in s['ocr']['data']['text'],s['ocr']['data']
def has_web(r,s):assert s['render']['status']=='complete',s['render'];assert 'AUSKAL PASSIVE RENDER VERIFIED' in s['render']['data']['visibleText'];assert s['client-scripts']['data']['scripts'];assert '/api/v1/fixture' in s['endpoints']['data']['endpoints']
for _ in range(30):
 try:
  with request('/login') as r:assert r.status==200
  break
 except Exception:time.sleep(1)
with request('/api/login',{'username':'fixture-user','password':'fixture-password'}) as response:
 COOKIE=response.headers['Set-Cookie'].split(';')[0]
if not api('/api/status')['acknowledged']:
 try:api('/api/jobs',{'kind':'script','files':[]});raise AssertionError('Authorization acknowledgment not enforced')
 except urllib.error.HTTPError as error:assert error.code==403
api('/api/acknowledge',{'accepted':True});assert api('/api/status')['acknowledged'] is True
print('PASS session login and one-time acknowledgment',flush=True)
started=not bool(os.environ.get('REA_TEST_START'))
for label,name,check in [('ZIP source','source.zip',has_source),('TAR.GZ source','source.tar.gz',has_source),('ELF binary','sample-elf',has_binary),('PE executable','sample.exe',has_binary),('Mach-O library','sample.dylib',has_binary),('Android APK','sample.apk',has_android),('Android AAB','sample.aab',has_android),('iOS IPA','sample.ipa',has_ios),('PNG screenshot','screenshot.png',has_ocr),('JPEG screenshot','screenshot.jpg',has_ocr),('JavaScript source','app.js',None),('Python source','unsafe.py',None)]:
 if label==os.environ.get('REA_TEST_START'):started=True
 if started:run(label,name=name,expect=check)
if os.environ.get('REA_TEST_START') not in ('Archive URL','Git URL'):run('Passive website',url='http://dev.auskal.tech/.well-known/acme-challenge/rea-fixture.html',kind='auto',expect=has_web)
if os.environ.get('REA_TEST_START')!='Git URL':run('Archive URL',url='http://dev.auskal.tech/.well-known/acme-challenge/rea-source.tar.gz',kind='auto',expect=has_source)
run('Git URL',url='https://github.com/octocat/Hello-World.git',kind='auto')
# Private network URLs must fail before any successful response can be captured.
job=api('/api/jobs',{'kind':'web','url':'http://127.0.0.1/','files':[]});state=wait(job)
assert state['status']=='failed',state
print('PASS private-address URL refused',flush=True)
print('ALL INPUT TYPES PASSED',len(RESULTS),flush=True)
api('/api/logout',{})
try:api('/api/jobs');raise AssertionError('Sign-out failed')
except urllib.error.HTTPError as error:assert error.code==401
print('PASS sign-out revokes session',flush=True)
