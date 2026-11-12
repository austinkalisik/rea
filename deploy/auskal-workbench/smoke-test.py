import base64,json,time,urllib.request,urllib.error
BASE='http://172.16.4.2:3180'
def request(route,data=None,origin='https://dev.auskal.tech',host='dev.auskal.tech'):
    h={'Host':host,'Content-Type':'application/json','Origin':origin,'X-REA-Request':'workbench'}
    r=urllib.request.Request(BASE+route,data=json.dumps(data).encode() if data is not None else None,headers=h)
    with urllib.request.urlopen(r,timeout=15) as response: return response.status,json.load(response)
def rejects(body,code,**kw):
    try: request('/api/jobs',body,**kw); raise AssertionError('request accepted unexpectedly')
    except urllib.error.HTTPError as err: assert err.code==code,(err.code,err.read())
request('/api/status')
rejects({'mode':'artifact','files':[{'name':'../escape','data':'YWJj'}]},400)
rejects({'mode':'shell','files':[]},400)
rejects({'mode':'artifact','files':[]},403,origin='https://untrusted.example')
rejects({'mode':'artifact','files':[]},403,host='untrusted.example')
print('PASS: health, traversal, command whitelist, origin and host validation',flush=True)
for mode,files in [
    ('javascript',[('package.json',b'{"name":"demo","type":"module","version":"1.0.0"}'),('sample.js',b'export function greet(name) { return "Hello, " + name; }')]),
    ('hardening',[('sample-elf',open('/bin/true','rb').read())]),
    ('entropy',[('sample.txt',b'AusKal analysis sample '*300)])]:
    code,job=request('/api/jobs',{'mode':mode,'files':[{'name':name,'data':base64.b64encode(data).decode()} for name,data in files]})
    assert code==202
    for _ in range(70):
        time.sleep(2)
        _,job=request('/api/jobs/'+job['id'])
        if job['status']!='running': break
    _,report=request('/api/jobs/'+job['id']+'/report')
    print(mode,job['status'],'exit',job.get('exitCode'),'report keys',list(report['result'])[:6],flush=True)
    if job['status']!='complete':
        print(json.dumps(report)[:3500],flush=True)
        raise AssertionError('Analysis failed')
print('PASS: JavaScript, real ELF hardening, entropy and JSON report downloads',flush=True)
