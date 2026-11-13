"""Offline static engines; web acquisition is gated by the public egress proxy."""
import argparse,base64,collections,hashlib,html.parser,importlib.metadata,json,math,os,pathlib,plistlib,re,shutil,struct,sys,tempfile,time,urllib.parse,zipfile
import xml.etree.ElementTree as ET
from reporting import OUT,REPORT,artifact,command,export,finding,progress,section
from acquire import extract,fetch,git_acquire,valid_url
from decoding import decode_js
INPUT=pathlib.Path('/input')
SOURCE_SUFFIXES={'.js','.jsx','.ts','.tsx','.py','.java','.kt','.swift','.c','.h','.cpp','.go','.rs','.php','.rb','.cs','.json','.xml','.yaml','.yml','.html','.css','.txt','.env','.sh','.toml','.gradle','.properties','.graphql'}

def text_files(root,limit=300):
    count=0
    for p in sorted(root.rglob('*')):
        if not p.is_file() or p.is_symlink() or p.stat().st_size>2*1024**2:continue
        if p.suffix.lower() not in SOURCE_SUFFIXES and p.name not in {'Dockerfile','requirements.txt','Gemfile','go.mod'} and not p.name.startswith('.env'):continue
        try:text=p.read_text(errors='strict')
        except (UnicodeError,OSError):continue
        count+=1
        if count>limit:break
        yield p,text

def parse_json_result(tool):
    try:return json.loads(tool['stdout'])
    except (json.JSONDecodeError,KeyError):return {}

def scan(root,percent=60):
    decoded_text=[]
    for source,text in text_files(root):
        for token in re.findall(r'''atob\(\s*["']([A-Za-z0-9+/=]{8,1000})["']\s*\)''',text)[:20]:
            try:decoded_text.append(base64.b64decode(token,validate=True).decode('utf8'))
            except Exception:pass
    if decoded_text:(root/'rea-decoded-constants.txt').write_text('\n'.join(json.dumps(x) for x in decoded_text)[:2*1024**2])
    progress('Scanning for exposed secrets',percent)
    report_path=OUT/'gitleaks-internal.json'
    g=command(['gitleaks','dir',str(root),'--no-banner','--redact=100','--report-format','json','--report-path',str(report_path),'--exit-code','0'],timeout=90)
    leaks=[]
    if report_path.exists():
        try:leaks=json.loads(report_path.read_text()) or []
        except ValueError:pass
        report_path.unlink()
    for leak in leaks[:200]:
        finding('Potential secret: '+leak.get('Description',leak.get('RuleID','credential')),'high','A detector matched a possible credential. Value redacted; review whether it is public/test data.',str(leak.get('File','')).replace(str(root)+'/','')+':'+str(leak.get('StartLine','')),'If this is a real secret, rotate it and move it to server-side configuration.')
    section('secrets','Exposed keys & secrets',{'matches':len(leaks),'returned':min(len(leaks),200),'values':'redacted','scanner':'gitleaks'},'complete' if g['ok'] else 'partial','Potential matches require validation.',[] if g['ok'] else [g.get('error') or g['stderr'][-700:]])
    progress('Running static security rules',percent+10)
    s=command(['semgrep','scan','--config','/app/unified/rules.yml','--json','--metrics','off','--disable-version-check','--no-git-ignore','--max-target-bytes','2097152','--timeout','10','--jobs','2',str(root)],timeout=100)
    parsed=parse_json_result(s);matches=parsed.get('results',[])
    for match in matches[:200]:
        extra=match.get('extra',{})
        finding(extra.get('message',match.get('check_id','Static pattern')),{'ERROR':'high','WARNING':'medium','INFO':'info'}.get(extra.get('severity'),'medium'),'Static rule '+match.get('check_id','')+' matched; data flow and exploitability need review.',str(match.get('path','')).replace(str(root)+'/','')+':'+str(match.get('start',{}).get('line','')),'Review the matched code and replace unsafe APIs or validate untrusted input.')
    section('sast','Source security review',{'engine':'Semgrep OSS, local rules only','matches':len(matches),'rules':[r.get('check_id') for r in matches[:100]],'errors':[{k:e.get(k) for k in ('type','message','path')} for e in parsed.get('errors',[])[:20]],'scannedFiles':len(parsed.get('paths',{}).get('scanned',[]))},'complete' if s['ok'] and not parsed.get('errors') else 'partial','Heuristic matches are not a proof of vulnerability.',[] if s['ok'] else [s.get('error') or s['stderr'][-700:]])
    endpoints=set();decoded=[];obfuscation=[]
    for p,text in text_files(root):
        for value in re.findall(r'''["'`](https?://[^\s"'`<>]{3,300}|/(?:api|v[0-9]+|graphql|rest)(?:/[^\s"'`<>]{0,250})?)["'`]''',text):
            value=re.sub(r'(?i)([?&](?:token|key|secret|password|api_key)=)[^&]+',r'\1[REDACTED]',value);endpoints.add(value)
        if p.suffix.lower() in {'.js','.ts','.jsx','.tsx'}:
            for literal in re.findall(r'''atob\(\s*["']([A-Za-z0-9+/=]{8,1000})["']\s*\)''',text)[:20]:
                try:
                    value=base64.b64decode(literal,validate=True).decode('utf8')
                    decoded.append({'file':str(p.relative_to(root)),'operation':'constant atob','decoded':value[:500]})
                except Exception:pass
            if re.search(r'\\x[0-9a-fA-F]{2}',text):obfuscation.append({'file':str(p.relative_to(root)),'indicator':'hex-escaped string literals'})
            if re.search(r'\beval\s*\(|new\s+Function\b|_0x[0-9a-f]{3,}',text):obfuscation.append({'file':str(p.relative_to(root)),'indicator':'dynamic evaluation or obfuscated identifier'})
    section('endpoints','Referenced API endpoints',{'endpoints':sorted(endpoints)[:300],'count':len(endpoints)},summary='References found in client/source text; no endpoints were probed.')
    # Decoded literals can be credentials; scan them first, then expose only their digest/shape.
    section('deobfuscation','Static decoding & obfuscation review',{'decodedConstants':[{'file':x['file'],'operation':x['operation'],'preview':x['decoded'][:12]+'…' if x['decoded'].startswith(('http','/api')) else '[decoded text withheld; SHA-256 '+hashlib.sha256(x['decoded'].encode()).hexdigest()[:16]+']'} for x in decoded[:40]],'indicators':obfuscation[:60]},summary='Safe constant decoding only; no target JavaScript was executed by the decoder.',limitations=['This is not a general-purpose deobfuscator. Runtime-dependent and encrypted code cannot be statically recovered here.'])

def inventory(root):
    files=[p for p in sorted(root.rglob('*')) if p.is_file() and not p.is_symlink()]
    tree=[{'path':str(p.relative_to(root)),'bytes':p.stat().st_size} for p in files[:5000]]
    manifests=[]
    for p in files:
        if p.stat().st_size>2*1024**2:continue
        if p.name not in {'package.json','requirements.txt','pyproject.toml','Cargo.toml','go.mod','composer.json','pom.xml','build.gradle','Gemfile','Dockerfile','Package.swift'}:continue
        text=p.read_text(errors='replace')
        data={'file':str(p.relative_to(root))}
        if p.name in {'package.json','composer.json'}:
            try:
                v=json.loads(text);data.update({k:v[k] for k in ['name','version','dependencies','devDependencies','require','scripts'] if k in v})
            except ValueError:data['parseError']='Invalid JSON'
        else:data['declarations']=text[:12000]
        manifests.append(data)
        if len(manifests)>=80:break
    section('inventory','File tree & dependencies',{'fileCount':len(files),'files':tree,'manifests':manifests},summary='Manifests are parsed as data; dependencies are not installed and build scripts are not run.',limitations=['This does not query vulnerability databases or establish dependency CVE status.'])
    return files

def script_analysis(root):
    inventory(root)
    js=[p for p in root.rglob('*') if p.suffix.lower() in {'.js','.ts','.jsx','.tsx'}]
    if js:
        progress('Building REA source evidence',35)
        rea=command(['rea','analyze-javascript-application',str(root),'--format','json'],timeout=80)
        parsed=parse_json_result(rea)
        section('rea','REA JavaScript evidence',parsed if len(rea['stdout'])<1500000 else {'evidenceId':parsed.get('evidence_id'),'note':'Large evidence omitted from the inline projection.'},'complete' if rea['ok'] else 'partial','Module and import relationships from REA.',[] if rea['ok'] else [rea.get('error') or rea['stderr'][-1000:]])
        import jsbeautifier
        for i,p in enumerate(js[:6]):
            if p.stat().st_size>512*1024:continue
            target=OUT/f'client-{i+1}.beautified.js';target.write_text(jsbeautifier.beautify(p.read_text(errors='replace')));artifact(target.name,'Beautified JavaScript (not executed)')
            decoded,count=decode_js(p.read_text(errors='replace'))
            if count:
                transformed=OUT/f'client-{i+1}.deobfuscated.js';transformed.write_text(jsbeautifier.beautify(decoded));artifact(transformed.name,'Constant-decoded JavaScript (not executed; source may contain sensitive literals)')
    scan(root)

def binary_analysis(p):
    progress('Inspecting binary headers and strings',25)
    data=p.read_bytes();freq=collections.Counter(data);entropy=-sum((n/len(data))*math.log2(n/len(data)) for n in freq.values()) if data else 0
    strings=[]
    for m in re.finditer(rb'[\x20-\x7e]{5,}',data):
        strings.append({'offset':m.start(),'text':m.group().decode()[:400]})
        if len(strings)>=1000:break
    info={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'entropy':round(entropy,4),'file':command(['file','-b',str(p)],10)['stdout'].strip(),'strings':strings,'stringLimit':1000}
    import lief
    try:
        b=lief.parse(str(p))
        if b is None:raise ValueError('LIEF could not recognize a native binary')
        sections=[]
        for s in list(b.sections)[:200]:sections.append({'name':s.name,'size':s.size,'offset':s.offset,'entropy':round(s.entropy,3)})
        def names(values):return [str(getattr(v,'name',v))[:300] for v in list(values)[:1000]]
        info.update({'format':str(b.format),'entrypoint':hex(b.entrypoint),'sections':sections,'imports':names(getattr(b,'imported_functions',[])),'exports':names(getattr(b,'exported_functions',[])),'libraries':names(getattr(b,'libraries',getattr(b,'imports',[])))})
        markers=[s['name'] for s in sections if re.search(r'(?i)upx|aspack|mpress|themida',s['name'])]
        info['packingIndicators']={'highEntropy':entropy>7.2,'sectionMarkers':markers}
        if markers or entropy>7.2:finding('Possible packing or compression indicators','medium','High entropy or a known packer section name was observed. This can also occur in benign compressed/encrypted data.',p.name,'Review sections and imports; treat packing as an indicator, not a verdict.')
    except Exception as exc:info['parseError']=str(exc)[:300];REPORT['limitations'].append('Native metadata parsing was incomplete: '+str(exc)[:200])
    section('binary','Binary structure, strings & entropy',info)
    progress('Checking native security flags',45)
    hard=command(['rea','inspect-binary-hardening',str(p),'--format','json'],timeout=60)
    section('hardening','Binary security flags',parse_json_result(hard),'complete' if hard['ok'] else 'partial',limitations=[] if hard['ok'] else [hard['stderr'][-700:]])
    section('decompile','Optional native decompilation',{'enabled':False},'not_enabled','Ghidra-headless is not enabled on this shared VPS.',limitations=['No native pseudocode was generated. Linux workers cannot reconstruct arbitrary protected or encrypted software.'])
    scanroot=OUT/'scan-text';scanroot.mkdir();(scanroot/'strings.txt').write_text('\n'.join(x['text'] for x in strings));scan(scanroot)

def android_analysis(p,root):
    progress('Extracting Android package',20);expanded=extract(p,root)
    manifest=root/'AndroidManifest.xml'
    is_bundle=p.suffix.lower()=='.aab' or (root/'base/manifest/AndroidManifest.xml').exists()
    if is_bundle:
        tool=command(['java','-Xmx768m','-jar','/opt/engines/bundletool.jar','dump','manifest','--bundle='+str(p),'--module=base'],timeout=45)
        if tool['ok']:xml=tool['stdout']
        else:raise ValueError('AAB manifest decoding failed: '+tool['stderr'][-600:])
    else:
        raw=manifest.read_bytes()
        if raw.lstrip().startswith(b'<'):xml=raw.decode('utf8','replace')
        else:
            from androguard.core.axml import AXMLPrinter
            xml=AXMLPrinter(raw).get_xml().decode('utf8','replace')
    (OUT/'AndroidManifest.xml').write_text(xml);artifact('AndroidManifest.xml','Decoded Android manifest')
    element=ET.fromstring(xml);ns='{http://schemas.android.com/apk/res/android}'
    permissions=[x.get(ns+'name') for x in element.iter() if x.tag in ('uses-permission','uses-permission-sdk-23')]
    application=element.find('application');attrs=dict(application.attrib) if application is not None else {}
    components=[{'type':x.tag,'name':x.get(ns+'name'),'exported':x.get(ns+'exported'),'permission':x.get(ns+'permission')} for x in element.iter() if x.tag in ('activity','service','receiver','provider')]
    details={'package':element.get('package'),'permissions':permissions,'application':attrs,'components':components,'bundle':is_bundle,**expanded}
    for flag in ('debuggable','usesCleartextTraffic'):
        if attrs.get(ns+flag)=='true':finding('Android '+flag+' is enabled','medium','The manifest explicitly enables '+flag+'.','AndroidManifest.xml','Disable this setting in production unless it is an intentional requirement.')
    risky=[x for x in permissions if x and any(s in x for s in ['READ_SMS','READ_CONTACTS','ACCESS_FINE_LOCATION','RECORD_AUDIO','MANAGE_EXTERNAL_STORAGE'])]
    if risky:finding('Sensitive Android permissions','medium',', '.join(risky),'AndroidManifest.xml','Confirm each permission is necessary and documented.')
    section('android','Android manifest & permissions',details)
    configs=[]
    for f in root.rglob('*.xml'):
        if 'network' not in f.name.lower() or f.stat().st_size>1024**2:continue
        raw=f.read_bytes()
        try:
            if not raw.lstrip().startswith(b'<'):
                from androguard.core.axml import AXMLPrinter
                raw=AXMLPrinter(raw).get_xml()
            text=raw.decode('utf8','replace');configs.append({'file':str(f.relative_to(root)),'xml':text[:12000]})
            if re.search(r'cleartextTrafficPermitted\s*=\s*["\']true',text):finding('Cleartext Android network configuration','medium','A network security configuration permits cleartext traffic.',str(f.relative_to(root)),'Use TLS and limit any cleartext exceptions to required domains.')
            if 'src="user"' in text:finding('User-installed CAs trusted','medium','Network security config includes the user certificate store.',str(f.relative_to(root)),'Review whether production builds should trust user-installed CAs.')
            f.write_text(text)
        except Exception as exc:configs.append({'file':f.name,'error':str(exc)[:200]})
    section('android-network','Network security configuration',{'manifestReference':attrs.get(ns+'networkSecurityConfig'),'configs':configs},summary='Manifest and packaged XML review; no device or traffic interception.',limitations=['Resource references not resolved by the decoder remain unknown. Missing explicit flags do not establish the effective platform default.'])
    progress('Decompiling DEX with JADX',35)
    dex=list(root.rglob('*.dex'))[:20]
    if dex:
        code=OUT/'decompiled';tool=command(['jadx','--no-res','--threads-count','2','-d',str(code),*map(str,dex)],timeout=160,ok=(0,1))
        java=list(code.rglob('*.java'));samples=[{'file':str(f.relative_to(code)),'source':f.read_text(errors='replace')[:5000]} for f in java[:12]]
        section('jadx','JADX decompiled source',{'classes':len(java),'samples':samples,'exitCode':tool['code']},'complete' if tool['code']==0 else 'partial',summary='DEX decompilation without executing the app.',limitations=[] if tool['code']==0 else ['Some classes could not be decompiled. '+(tool['stdout']+tool['stderr'])[-1500:]])
        if java:archive=shutil.make_archive(str(OUT/'decompiled-sources'),'zip',code);artifact('decompiled-sources.zip','JADX Java source archive');scan(code,60)
        else:scan(root,60)
    else:section('jadx','JADX decompiled source',{},'not_applicable','No DEX files are present in this package.');scan(root,60)
    resources=[str(f.relative_to(root)) for f in root.rglob('*') if f.is_file() and (str(f.relative_to(root)).startswith(('res/','base/res/','assets/','base/assets/')))][:500]
    resource_strings=[]
    arsc=root/'resources.arsc'
    if arsc.exists():
        try:
            from androguard.core.axml import ARSCParser
            text=ARSCParser(arsc.read_bytes()).get_strings_resources().decode('utf8','replace');(OUT/'android-strings.xml').write_text(text[:2*1024**2]);artifact('android-strings.xml','Decoded Android resource strings');resource_strings=re.findall(r'<string[^>]*>(.*?)</string>',text,re.S)[:300]
        except Exception as exc:REPORT['limitations'].append('Resource string decoding incomplete: '+str(exc)[:200])
    section('resources','Android resources & strings',{'resources':resources,'strings':resource_strings})

def ios_analysis(p,root):
    progress('Reading iOS package metadata',25);expanded=extract(p,root)
    apps=list((root/'Payload').glob('*.app')) if (root/'Payload').exists() else []
    if not apps:raise ValueError('IPA must contain Payload/<app>.app')
    app=apps[0];info=plistlib.loads((app/'Info.plist').read_bytes());frameworks=[str(x.relative_to(app)) for x in app.rglob('*.framework')]
    entitlements=[]
    for f in app.rglob('*.xcent'):
        try:entitlements.append({'file':str(f.relative_to(app)),'values':plistlib.loads(f.read_bytes())})
        except Exception:pass
    executable_name=str(info.get('CFBundleExecutable',''))
    if '/' in executable_name or chr(92) in executable_name or executable_name in ('.','..'):raise ValueError('Invalid CFBundleExecutable path')
    executable=app/executable_name
    if executable.is_file():
        data=executable.read_bytes()
        # Embedded XML entitlement blobs in a code-signature superblob.
        for m in re.finditer(b'\xfa\xde\x71\x71',data):
            try:
                length=struct.unpack('>I',data[m.start()+4:m.start()+8])[0]
                if 8<length<2*1024**2:entitlements.append({'file':executable.name,'values':plistlib.loads(data[m.start()+8:m.start()+length])})
            except Exception:pass
        strs=[m.group().decode('ascii')[:400] for m in list(re.finditer(rb'[\x20-\x7e]{6,}',data))[:1000]]
        (root/'executable-strings.txt').write_text('\n'.join(strs))
    ats=info.get('NSAppTransportSecurity',{})
    if ats.get('NSAllowsArbitraryLoads'):finding('iOS arbitrary network loads enabled','medium','NSAllowsArbitraryLoads is true in ATS configuration.','Info.plist','Prefer HTTPS and narrow, documented ATS exceptions.')
    section('ios','iOS metadata, frameworks & entitlements',{'bundle':info,'frameworks':frameworks,'entitlements':entitlements,'ATS':ats,**expanded},summary='Static IPA review on Linux.',limitations=['No iOS runtime or deep Objective-C/Swift decompilation. Encrypted App Store executables and DER-only entitlements cannot be fully recovered. Entitlements are declared XML data, not a verified code-signature claim.'])
    scan(root)

def image_analysis(p,root):
    from PIL import Image,ImageOps
    Image.MAX_IMAGE_PIXELS=20_000_000
    progress('Reading image and extracting text',25)
    with Image.open(p) as image:
        image.load();info={'format':image.format,'width':image.width,'height':image.height,'mode':image.mode}
        normal=ImageOps.exif_transpose(image).convert('RGB');normal.thumbnail((2600,2600));normal.save(OUT/'ocr-input.png')
        if REQUEST.get('ai'):normal.thumbnail((1400,1400));normal.save(OUT/'ai-image.jpg',quality=85)
    ocr=command(['tesseract',str(OUT/'ocr-input.png'),'stdout','-l','eng','--psm','3'],timeout=60)
    if not ocr['ok']:raise ValueError('OCR failed: '+ocr['stderr'][-500:])
    text=ocr['stdout'];(OUT/'ocr.txt').write_text(text);artifact('ocr.txt','OCR text');artifact('ocr-input.png','Normalized screenshot')
    section('ocr','Screenshot & image text',{'image':info,'text':text,'characters':len(text),'language':'English'},summary='Tesseract OCR; recognition may be imperfect.',limitations=['No AI visual description or generated UI scaffold unless the optional AI pass is explicitly enabled.'])
    root.mkdir(exist_ok=True);(root/'ocr.txt').write_text(text);scan(root)

class PageParser(html.parser.HTMLParser):
    def __init__(self):super().__init__();self.scripts=[];self.inline=[];self.title='';self.in_title=False;self.in_script=False
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='script':
            self.in_script=True
            if a.get('src'):self.scripts.append(a['src'])
        if tag=='title':self.in_title=True
    def handle_endtag(self,tag):
        if tag=='script':self.in_script=False
        if tag=='title':self.in_title=False
    def handle_data(self,data):
        if self.in_script and data.strip():self.inline.append(data)
        if self.in_title:self.title+=data

def web_analysis(url,root):
    progress('Fetching public page and response metadata',15);root.mkdir(exist_ok=True)
    response=fetch(url);body=response['data'];text=body.decode('utf8','replace');(root/'page.html').write_text(text)
    parser=PageParser();parser.feed(text);headers={k.lower():v for k,v in response['headers'] if k.lower()!='set-cookie'}
    cookies=[]
    for k,v in response['headers']:
        if k.lower()=='set-cookie':cookies.append({'name':v.split('=',1)[0],'attributes':v.split(';')[1:],'value':'[REDACTED]'})
    fingerprints=[]
    for name,pattern in [('React',r'__REACT|react-dom|_reactRoot'),('Next.js',r'__NEXT_DATA__|/_next/'),('Vue',r'__VUE|vue\.runtime|data-v-'),('Angular',r'ng-version|angular\.js'),('WordPress',r'wp-content/|wp-includes/'),('jQuery',r'jquery[.-]')]:
        if re.search(pattern,text,re.I):fingerprints.append({'technology':name,'basis':'response HTML marker','confidence':'indicator'})
    for k in ['server','x-powered-by','x-generator']:
        if k in headers:fingerprints.append({'technology':headers[k],'basis':'response header '+k,'confidence':'self-reported'})
    for name in ['content-security-policy','x-content-type-options','strict-transport-security']:
        if name not in headers:finding('Response does not declare '+name,'low','This header was absent from the selected response; application and transport context must be considered.',response['url'],'Review whether this security header is appropriate for the application.')
    section('http','Website response & technology indicators',{'requestedUrl':url,'finalUrl':response['url'],'status':response['status'],'title':parser.title,'headers':headers,'cookies':cookies,'fingerprints':fingerprints},summary='Passive public GET requests. Cookie values are withheld.')
    progress('Collecting client-side JavaScript',30)
    scripts=[]
    for i,src in enumerate(parser.scripts[:16]):
        target=urllib.parse.urljoin(response['url'],src)
        try:
            data=fetch(target,2*1024**2);name=f'bundle-{i+1}.js';(root/name).write_bytes(data['data']);scripts.append({'url':target,'file':name,'bytes':len(data['data'])})
        except Exception as exc:scripts.append({'url':target,'error':str(exc)[:300]})
    for i,src in enumerate(parser.inline[:20]):(root/f'inline-{i+1}.js').write_text(src[:2*1024**2])
    section('client-scripts','Client JavaScript acquisition',{'scripts':scripts,'inlineScripts':min(len(parser.inline),20)},summary='Up to 16 external bundles, 2 MB each. No source server files are accessed.')
    progress('Rendering in isolated headless Chromium',40)
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser=pw.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox','--disable-dev-shm-usage','--proxy-server='+ 'http://172.30.44.1:3182','--proxy-bypass-list=<-loopback>'])
            context=browser.new_context(viewport={'width':1366,'height':900},service_workers='block',accept_downloads=False)
            count=[0]
            def route(r):
                count[0]+=1
                if count[0]>100 or r.request.method not in ('GET','HEAD') or not r.request.url.startswith(('http://','https://')):return r.abort()
                if r.request.resource_type in ('media','font','eventsource'):return r.abort()
                try:valid_url(r.request.url)
                except Exception:return r.abort()
                r.continue_()
            context.route('**/*',route)
            context.route_web_socket('**/*',lambda ws:ws.close())
            page=context.new_page();page.goto(response['url'],wait_until='domcontentloaded',timeout=25000);page.wait_for_timeout(1800)
            rendered=page.locator('body').inner_text(timeout=4000)[:20000];page.screenshot(path=str(OUT/'website.png'),full_page=False,timeout=10000)
            section('render','Headless page render',{'title':page.title(),'visibleText':rendered,'requestsObserved':count[0],'cookies':[{k:v for k,v in c.items() if k!='value'} for c in context.cookies()]},summary='GET/HEAD only; forms, POST, WebSockets, service workers, downloads, and media are blocked.',limitations=['Page scripts execute only inside the disposable renderer. Some applications cannot render with passive requests alone.'])
            browser.close();artifact('website.png','Headless website screenshot')
    except Exception as exc:section('render','Headless page render',{},'partial',limitations=[str(exc)[:500]])
    script_analysis(root)

def detect(p):
    raw=p.read_bytes()[:8];name=p.name.lower()
    if name.endswith(('.apk','.aab')):return 'android'
    if name.endswith('.ipa'):return 'ios'
    if raw.startswith(b'\x7fELF') or raw.startswith(b'MZ') or raw[:4].hex() in ['feedface','feedfacf','cefaedfe','cffaedfe','cafebabe','bebafeca']:return 'binary'
    if raw.startswith(b'\x89PNG') or raw.startswith(b'\xff\xd8'):return 'image'
    if zipfile.is_zipfile(p):
        with zipfile.ZipFile(p) as z:
            names=z.namelist()
            if 'AndroidManifest.xml' in names or 'base/manifest/AndroidManifest.xml' in names:return 'android'
            if any(n.startswith('Payload/') and n.endswith('/Info.plist') for n in names):return 'ios'
        return 'source'
    if name.endswith(('.tar','.tgz','.tar.gz')):return 'source'
    return 'script'

REQUEST={}
def main():
    global REQUEST
    OUT.mkdir(exist_ok=True)
    try:
        from loguru import logger
        logger.remove()
    except ImportError:pass
    if '--render' in sys.argv:
        REPORT.update(json.loads((OUT/'report.json').read_text()));export();return
    REQUEST=json.loads(pathlib.Path('/request.json').read_text())
    kind=REQUEST['kind'];files=[INPUT/f['name'] for f in REQUEST.get('files',[])];p=files[0] if files else None
    if p and len(files)==1 and REQUEST.get('requestedKind','auto')=='auto':kind=detect(p)
    REPORT.update({'targetType':kind,'title':REQUEST.get('url') or (p.name if p else 'Static target'),'inputs':REQUEST.get('files',[]),'runId':REQUEST.get('id'),'passive':True})
    for package in ['lief','semgrep','androguard','playwright','Pillow','reportlab','jsbeautifier']:
        try:REPORT['engines'][package]=importlib.metadata.version(package)
        except Exception:pass
    REPORT['engines'].update({'REA':'6.9.0','JADX':'1.5.6','gitleaks':'8.30.1','bundletool':'1.18.3'})
    root=OUT/'analysis-source'
    try:
        progress('Identifying target',5)
        if kind=='web':web_analysis(REQUEST['url'],root)
        elif kind=='git':
            progress('Acquiring public source repository',10);section('acquisition','Git source acquisition',git_acquire(REQUEST['url'],root));script_analysis(root)
        elif kind=='source':
            if REQUEST.get('url'):
                progress('Downloading source archive',10);r=fetch(REQUEST['url'],48*1024**2);p=pathlib.Path('/tmp/source-download');p.write_bytes(r['data']);section('acquisition','Archive download',{'url':r['url'],'bytes':len(r['data'])})
            if len(files)>1:
                shutil.copytree(INPUT,root);section('acquisition','Uploaded source files',{'files':len(files)})
            else:section('extraction','Safe archive extraction',extract(p,root))
            script_analysis(root)
        elif kind=='script':shutil.copytree(INPUT,root);script_analysis(root)
        elif kind=='binary':binary_analysis(p)
        elif kind=='android':android_analysis(p,root)
        elif kind=='ios':ios_analysis(p,root)
        elif kind=='image':image_analysis(p,root)
        else:raise ValueError('Unsupported target type')
        REPORT['status']='complete'
    except Exception as exc:
        REPORT['status']='failed';REPORT['error']=str(exc)[:1500];REPORT['limitations'].append('Analysis stopped: '+str(exc)[:1000]);section('failure','Analysis failure',{'message':str(exc)[:1500]},'failed')
        print('Analysis failed:',str(exc),file=sys.stderr,flush=True)
    REPORT['limitations'].append('Static analysis can be incomplete and can produce false positives. No clean-bill-of-health or exploitability guarantee is implied.')
    progress('Preparing readable reports',94);export();progress('Reports ready',100)
    if REPORT['status']=='failed':sys.exit(2)
if __name__=='__main__':main()
