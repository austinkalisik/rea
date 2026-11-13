import base64,json,os,time,urllib.request
BASE=os.environ['REA_TEST_BASE'];cookie=None
def api(route,body=None):
 h={'Host':'dev.auskal.tech','Origin':'https://dev.auskal.tech','X-REA-Request':'workbench'}
 if cookie:h['Cookie']=cookie
 if body is not None:h['Content-Type']='application/json'
 req=urllib.request.Request(BASE+route,data=json.dumps(body).encode() if body is not None else None,headers=h)
 return urllib.request.urlopen(req,timeout=20)
for _ in range(30):
 try:
  with api('/login') as r:r.read()
  break
 except Exception:time.sleep(1)
with api('/api/login',{'username':'fixture-user','password':'fixture-password'}) as r:cookie=r.headers['Set-Cookie'].split(';')[0]
with api('/api/acknowledge',{'accepted':True}) as r:r.read()
# Deterministic, nonfunctional detector fixtures, never used to authenticate anywhere.
fixture_aws='AK'+'IA'+'QWERTYASDFGHJKLZ'
fixture_stripe='sk_'+'live_'+'51e9429c76c62c534879815a03df59b681'
files={'fixture.py':'import subprocess\ndef demo(value):\n subprocess.run(value, shell=True)\n','fixture.js':'const endpoint = atob("aHR0cHM6Ly9leGFtcGxlLmNvbS9hcGkvdjEvZml4dHVyZQ==");\n','fixture.env':'AWS_ACCESS_KEY_ID="'+fixture_aws+'"\nSTRIPE_SECRET="'+fixture_stripe+'"\n'}
with api('/api/jobs',{'kind':'auto','files':[{'name':n,'data':base64.b64encode(v.encode()).decode()} for n,v in files.items()]}) as r:job=json.load(r)
for _ in range(100):
 time.sleep(1)
 with api('/api/jobs/'+job['id']) as r:state=json.load(r)
 if state['status'] not in ('queued','running'):break
assert state['status']=='complete',state
with api('/api/jobs/'+job['id']+'/report') as r:report=json.load(r)
s={x['id']:x for x in report['sections']}
assert s['secrets']['data']['matches']>0,s['secrets']
assert s['sast']['data']['matches']>0,s['sast']
assert 'https://example.com/api/v1/fixture' in s['endpoints']['data']['endpoints'],s['endpoints']
assert any(x['name'].endswith('.deobfuscated.js') for x in report['artifacts'])
print('PASS seeded secret detector, SAST finding, constant decoding, decoded endpoint inventory and deobfuscated artifact',flush=True)
# Two requests can enter the durable queue; the web process continues responding.
def enqueue(name,text):
 with api('/api/jobs',{'kind':'script','files':[{'name':name,'data':base64.b64encode(text.encode()).decode()}]}) as r:return json.load(r)
a=enqueue('one.py','value = 1');b=enqueue('two.py','value = 2')
with api('/api/jobs') as r:jobs=json.load(r)
assert sum(x['status']=='running' for x in jobs)<=1
assert any(x['id']==b['id'] and x['status']=='queued' for x in jobs),jobs
for j in [a,b]:
 for _ in range(100):
  with api('/api/jobs/'+j['id']) as r:v=json.load(r)
  if v['status'] not in ('queued','running'):break
  time.sleep(1)
 assert v['status']=='complete',v
print('PASS queued concurrency and responsive history while engines run',flush=True)
with api('/api/jobs',{'kind':'web','url':'http://127.0.0.1/','files':[]}) as r:job=json.load(r)
for _ in range(40):
 with api('/api/jobs/'+job['id']) as r:v=json.load(r)
 if v['status'] not in ('queued','running'):break
 time.sleep(1)
assert v['status']=='failed',v
print('PASS private-network target reports a clear failure',flush=True)
