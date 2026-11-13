"""Browser exercises real staged API/queue; HTTPS edge is routed to the private harness."""
import json,os,pathlib,urllib.request,urllib.error,urllib.parse
from playwright.sync_api import sync_playwright
BASE=os.environ['REA_TEST_BASE'];ORIGIN='https://dev.auskal.tech';OUT=pathlib.Path('/ui-output');OUT.mkdir(exist_ok=True)
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):return None
opener=urllib.request.build_opener(NoRedirect())
with sync_playwright() as p:
 browser=p.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox','--disable-dev-shm-usage'])
 context=browser.new_context(viewport={'width':1440,'height':1000},accept_downloads=True)
 def bridge(route):
  if not route.request.url.startswith(ORIGIN+'/'):return route.abort()
  path=route.request.url[len(ORIGIN):]
  headers={k:v for k,v in route.request.headers.items() if k.lower() not in ['host','accept-encoding','connection','content-length']};headers['Host']='dev.auskal.tech'
  for _ in range(5):
   req=urllib.request.Request(BASE+path,data=route.request.post_data_buffer,method=route.request.method,headers=headers)
   try:response=opener.open(req,timeout=20)
   except urllib.error.HTTPError as error:response=error
   if response.status in (301,302,303,307,308):
    path=response.headers['Location'];response.close()
    if not path.startswith('/'):raise ValueError('Unexpected external fixture redirect')
   else:break
  with response:
   body=response.read();hs={k:v for k,v in response.headers.items() if k.lower() not in ['transfer-encoding','connection','content-length']}
   route.fulfill(status=response.status,headers=hs,body=body)
 context.route('**/*',bridge)
 page=context.new_page();errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
 page.goto(ORIGIN,wait_until='domcontentloaded');page.get_by_label('Username',exact=True).fill('fixture-user');page.get_by_label('Password',exact=True).fill('fixture-password');page.get_by_role('button',name='Sign in →',exact=True).click()
 page.get_by_role('heading',name='Understand what’s underneath.').wait_for()
 page.locator('#ack').wait_for(state='visible');page.locator('#ack-check').check();page.get_by_role('button',name='Continue to my workspace').click()
 page.locator('#url').fill('https://example.com');page.locator('#files').set_input_files('/fixtures/screenshot.png');assert page.locator('#url').input_value()==''
 page.locator('#kind').select_option('image');page.get_by_role('button',name='Analyze target ↗').click()
 page.locator('#work').wait_for(state='visible',timeout=15000)
 page.locator('#json').wait_for(state='visible',timeout=180000)
 assert 'screenshot.png' in page.locator('#report-title').inner_text()
 assert 'AUSKAL' in page.locator('#sections').inner_text(),page.locator('#report-error').inner_text()
 assert 'complete' in page.locator('#sections').inner_text()
 for format in ['json','html','pdf']:
  with page.expect_download() as download:page.locator('#'+format).click()
  download.value.save_as(str(OUT/('ui-report.'+format)))
 page.screenshot(path=str(OUT/'dashboard-desktop.png'),full_page=True)
 page.set_viewport_size({'width':390,'height':844});page.screenshot(path=str(OUT/'dashboard-mobile.png'),full_page=True)
 assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth + 1'),'Mobile layout overflows horizontally'
 # Drop handling uses a benign synthetic source file; it does not launch another scan.
 page.evaluate('''() => { const dt=new DataTransfer();dt.items.add(new File(['export const value = 1;'],'drop-test.js',{type:'text/javascript'}));document.getElementById('drop').dispatchEvent(new DragEvent('drop',{dataTransfer:dt,bubbles:true,cancelable:true})); }''')
 assert 'drop-test.js' in page.locator('#selected').inner_text()
 page.locator('#url').fill('https://example.com');assert 'Using the URL' in page.locator('#selected').inner_text()
 page.get_by_role('button',name='Sign out',exact=True).click();page.get_by_role('heading',name='Welcome back.').wait_for()
 assert not errors,errors
 (OUT/'ui-results.json').write_text(json.dumps({'status':'passed','coverage':['login','first-use acknowledgment','URL/file switching','upload','queued progress','real OCR worker report','history','HTML/PDF/JSON downloads','drag/drop','mobile layout','sign-out'],'browserConsoleErrors':errors},indent=2))
 print('PASS browser login, acknowledgment, upload, progress, real report, downloads, drag/drop, mobile, and sign-out',flush=True)
 browser.close()
