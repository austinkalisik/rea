import collections, datetime, html, json, os, pathlib, re, signal, subprocess, tempfile, time

OUT=pathlib.Path('/output')
REPORT={'schemaVersion':2,'title':'Static analysis report','created':datetime.datetime.now(datetime.timezone.utc).isoformat(),'sections':[],'findings':[],'limitations':[],'artifacts':[],'engines':{}}

def progress(stage,percent):
    p=OUT/'progress.json';tmp=OUT/'progress.tmp'
    tmp.write_text(json.dumps({'stage':stage,'progress':percent}));tmp.replace(p)

def finding(title,severity='info',detail='',location='',recommendation=''):
    item={'title':title,'severity':severity,'detail':str(detail)[:3000],'location':str(location)[:700],'recommendation':recommendation}
    REPORT['findings'].append(item);return item

def section(key,title,data=None,status='complete',summary='',limitations=None):
    item={'id':key,'title':title,'status':status,'summary':summary,'data':data or {},'limitations':limitations or []}
    REPORT['sections'].append(item);return item

def command(args,timeout=90,ok=(0,)):
    start=time.monotonic()
    with tempfile.TemporaryFile() as stdout,tempfile.TemporaryFile() as stderr:
        env={**os.environ,'HOME':'/tmp','XDG_CONFIG_HOME':'/tmp/.config','XDG_CACHE_HOME':'/tmp/.cache','JAVA_TOOL_OPTIONS':'-Duser.home=/tmp','SEMGREP_SEND_METRICS':'off','SEMGREP_ENABLE_VERSION_CHECK':'0','NO_COLOR':'1'}
        p=subprocess.Popen(args,stdout=stdout,stderr=stderr,start_new_session=True,env=env)
        reason=None
        while p.poll() is None:
            if time.monotonic()-start>timeout:reason='Tool timed out'
            if stdout.tell()>16*1024**2 or stderr.tell()>2*1024**2:reason='Tool output limit exceeded'
            if reason:
                try:os.killpg(p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                break
            time.sleep(.15)
        p.wait()
        # Descendants may outlive a provider process; they belong to this command group.
        try:os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        stdout.seek(0);stderr.seek(0)
        result={'code':p.returncode,'stdout':stdout.read(16*1024**2).decode('utf8','replace'),'stderr':stderr.read(8000).decode('utf8','replace'),'seconds':round(time.monotonic()-start,2)}
        if reason:result['error']=reason
        result['ok']=not reason and p.returncode in ok
        return result

def artifact(name,description):
    p=OUT/name
    if p.is_file():REPORT['artifacts'].append({'name':name,'description':description,'bytes':p.stat().st_size})

def clean(value):
    if isinstance(value,str):return re.sub('[\x00-\x08\x0b\x0c\x0e-\x1f]','',value)
    if isinstance(value,list):return [clean(v) for v in value]
    if isinstance(value,dict):return {str(k):clean(v) for k,v in value.items()}
    return value

def export():
    counts=collections.Counter(x['severity'] for x in REPORT['findings'])
    REPORT['summary']={'text':f"{REPORT.get('targetType','Target').title()} analysis finished with {len(REPORT['findings'])} findings across {len(REPORT['sections'])} sections.",'counts':dict(counts),'sectionCount':len(REPORT['sections']),'coverage':[{'analyzer':s['title'],'status':s['status']} for s in REPORT['sections']]}
    report=clean(REPORT)
    (OUT/'report.json').write_text(json.dumps(report,indent=2,ensure_ascii=False))
    esc=lambda v:html.escape(str(v))
    parts=['<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>REA analysis report</title><style>body{background:#0b0f16;color:#eef3fb;font:15px/1.7 system-ui;max-width:1100px;margin:auto;padding:32px}h1,h2{color:#b9ff66}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#121924;border:1px solid #29364b;padding:20px;border-radius:10px;font-size:12px}.finding{border-left:3px solid #8aabff;padding:12px 20px;margin:14px 0;background:#121924}small{color:#9aa9bd}</style>','<h1>AUSKAL / REA</h1><h2>'+esc(report['title'])+'</h2><p>'+esc(report['summary']['text'])+'</p><small>'+esc(report['created'])+' · Static analysis only · Findings require review</small>']
    for f in report['findings']:
        parts.append('<div class="finding"><b>'+esc(f['severity'].upper()+': '+f['title'])+'</b><p>'+esc(f['detail'])+'</p><small>'+esc(f['location'])+'</small><p>'+esc(f['recommendation'])+'</p></div>')
    for s in report['sections']:
        parts.append('<h2>'+esc(s['title'])+'</h2><p>'+esc(s['status']+' · '+s['summary'])+'</p><pre>'+esc(json.dumps(s['data'],indent=2,ensure_ascii=False))+'</pre>')
        for text in s['limitations']:parts.append('<p>Coverage note: '+esc(text)+'</p>')
    parts.append('<h2>Limitations</h2><pre>'+esc(json.dumps(report['limitations'],indent=2))+'</pre>')
    (OUT/'report.html').write_text('\n'.join(parts))
    try:
        from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Preformatted
        from reportlab.lib.styles import getSampleStyleSheet,ParagraphStyle
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.utils import simpleSplit
        styles=getSampleStyleSheet();styles.add(ParagraphStyle(name='CodeSmall',fontName='Courier',fontSize=7,leading=9,textColor=colors.HexColor('#263142')))
        story=[Paragraph('AUSKAL / REA',styles['Title']),Paragraph(esc(report['title']),styles['Heading1']),Paragraph(esc(report['summary']['text']),styles['BodyText']),Spacer(1,14)]
        for f in report['findings'][:150]:
            story.extend([Paragraph(esc(f['severity'].upper()+': '+f['title']),styles['Heading3']),Paragraph(esc(f['detail']),styles['BodyText']),Paragraph(esc(f['location']),styles['CodeSmall'])])
        for s in report['sections']:
            story.extend([Paragraph(esc(s['title']),styles['Heading2']),Paragraph(esc(s['status']+' · '+s['summary']),styles['BodyText'])])
            value=json.dumps(s['data'],indent=2,ensure_ascii=True)
            if len(value)>18000:value=value[:18000]+'\n[PDF section abbreviated. Download JSON/HTML for full evidence.]'
            lines=[]
            for line in value.splitlines():lines.extend(line[i:i+100] for i in range(0,max(1,len(line)),100))
            story.extend([Preformatted('\n'.join(lines),styles['CodeSmall']),Spacer(1,10)])
        story.append(Paragraph(esc('Limitations: '+'; '.join(report['limitations'])),styles['BodyText']))
        SimpleDocTemplate(str(OUT/'report.pdf'),title=report['title'],author='Tidalwave Softweb Solutions',leftMargin=36,rightMargin=36,topMargin=36,bottomMargin=36).build(story)
    except Exception as exc:
        REPORT['limitations'].append('PDF rendering failed: '+str(exc)[:200]);(OUT/'report.json').write_text(json.dumps(REPORT,indent=2))
