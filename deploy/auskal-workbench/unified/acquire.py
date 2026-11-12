import http.client,json,os,pathlib,socket,subprocess,tarfile,tempfile,urllib.request,urllib.parse,zipfile,stat
from reporting import command
PROXY='http://172.30.44.1:3182'
MAX_EXPANDED=256*1024**2
MAX_FILES=5000
class Redirects(urllib.request.HTTPRedirectHandler):
    max_redirections=5
    max_repeats=2

def valid_url(url):
    p=urllib.parse.urlsplit(url)
    if p.scheme not in ('http','https') or not p.hostname or p.username or p.password or p.port not in (None,80,443):raise ValueError('Use a public HTTP(S) URL without credentials/custom ports')
    return p

def fetch(url,limit=8*1024**2):
    valid_url(url)
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({'http':PROXY,'https':PROXY}),Redirects())
    req=urllib.request.Request(url,headers={'User-Agent':'AusKal-REA-Static-Analysis/2.0','Accept-Encoding':'identity'})
    try:response=opener.open(req,timeout=25)
    except urllib.error.HTTPError as error:
        if error.code in (401,403,404,500,502,503):response=error
        else:raise
    with response:
        data=response.read(limit+1)
        if len(data)>limit:raise ValueError('Remote response exceeded the size limit')
        final=response.geturl();valid_url(final)
        return {'url':final,'status':response.status,'headers':list(response.headers.items()),'data':data}

def safe_member(name,root):
    if '\\' in name or '\x00' in name:raise ValueError('Unsafe archive path')
    parts=pathlib.PurePosixPath(name).parts
    if not parts or any(x in ('..','') for x in parts) or name.startswith('/'):raise ValueError('Archive traversal blocked')
    dest=root.joinpath(*parts)
    if root.resolve() not in dest.resolve().parents:raise ValueError('Archive traversal blocked')
    return dest

def extract(archive,root):
    root.mkdir(parents=True,exist_ok=True);total=0;count=0;seen=set()
    def admit(name,size):
        nonlocal total,count
        count+=1;total+=size
        if count>MAX_FILES or total>MAX_EXPANDED or size>64*1024**2:raise ValueError('Archive expansion limit exceeded (5000 files / 256 MB / 64 MB per file)')
        dest=safe_member(name,root)
        if dest in seen:raise ValueError('Duplicate archive member blocked')
        seen.add(dest);return dest
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as z:
            for info in z.infolist():
                if info.is_dir():continue
                if stat.S_ISLNK(info.external_attr>>16) or info.flag_bits&1:raise ValueError('Archive symlinks and encrypted members are not supported')
                dest=admit(info.filename,info.file_size);dest.parent.mkdir(parents=True,exist_ok=True)
                with z.open(info) as src,open(dest,'xb') as out:
                    remaining=info.file_size
                    while True:
                        chunk=src.read(min(65536,remaining+1))
                        if not chunk:break
                        remaining-=len(chunk)
                        if remaining<0:raise ValueError('Archive size mismatch')
                        out.write(chunk)
    else:
        with tarfile.open(archive,'r:*') as tar:
            for item in tar:
                if item.isdir():continue
                if not item.isfile():raise ValueError('Archive links/devices are not allowed')
                dest=admit(item.name,item.size);dest.parent.mkdir(parents=True,exist_ok=True)
                with tar.extractfile(item) as src,open(dest,'xb') as out:
                    remaining=item.size
                    while True:
                        chunk=src.read(min(65536,remaining+1))
                        if not chunk:break
                        remaining-=len(chunk)
                        if remaining<0:raise ValueError('Archive size mismatch')
                        out.write(chunk)
    return {'files':count,'expandedBytes':total}

def git_acquire(url,root):
    p=valid_url(url)
    if p.scheme!='https':raise ValueError('Git acquisition requires HTTPS')
    os.environ.update({'HTTPS_PROXY':PROXY,'HTTP_PROXY':PROXY,'https_proxy':PROXY,'http_proxy':PROXY,'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0','GIT_LFS_SKIP_SMUDGE':'1'})
    bare=pathlib.Path(tempfile.mkdtemp(prefix='rea-git-'))/'repo.git'
    args=['git','-c','protocol.file.allow=never','-c','protocol.ext.allow=never','-c','protocol.ssh.allow=never','-c','core.hooksPath=/dev/null','clone','--bare','--depth=1','--single-branch','--no-tags','--filter=blob:limit=2m','--',url,str(bare)]
    clone=command(args,timeout=120)
    if not clone['ok']:raise ValueError('Public git acquisition failed: '+clone['stderr'][-700:])
    archive=bare.parent/'source.tar'
    packed=command(['git','-C',str(bare),'archive','--format=tar','--output='+str(archive),'HEAD'],timeout=90)
    if not packed['ok']:raise ValueError('Git archive export failed')
    result=extract(archive,root)
    rev=command(['git','-C',str(bare),'rev-parse','HEAD'],timeout=10)
    return {**result,'revision':rev['stdout'].strip(),'url':url}
