"""Benign fixtures. Android DEX/APK are downloaded separately from JADX's public tests."""
import io,json,os,pathlib,plistlib,shutil,struct,tarfile,zipfile
from PIL import Image,ImageDraw,ImageFont
ROOT=pathlib.Path(os.environ.get('REA_FIXTURES','/fixtures'));ROOT.mkdir(exist_ok=True)
files={'package.json':b'{"name":"rea-fixture","version":"1.0.0","type":"module","dependencies":{"example-lib":"1.0.0"}}','app.js':b'export const endpoint = "/api/v1/example";\nexport function greet(name){return "Hello, "+name;}','unsafe.py':b'import subprocess\ndef demo(user_input):\n    subprocess.run(user_input, shell=True)\n'}
for name,data in files.items():(ROOT/name).write_bytes(data)
with zipfile.ZipFile(ROOT/'source.zip','w',zipfile.ZIP_DEFLATED) as z:
 for name,data in files.items():z.writestr('fixture/'+name,data)
with tarfile.open(ROOT/'source.tar.gz','w:gz') as tar:
 for name,data in files.items():
  item=tarfile.TarInfo('fixture/'+name);item.size=len(data);tar.addfile(item,io.BytesIO(data))
shutil.copyfile('/bin/true',ROOT/'sample-elf')
try:
 import lief
 factory=lief.PE.Factory.create(lief.PE.PE_TYPE.PE32_PLUS)
 text=lief.PE.Section('.text');text.content=[0xc3];factory.add_section(text)
 factory.get().write(str(ROOT/'sample.exe'))
except Exception as exc:print('PE fixture generator:',str(exc))
# Minimal, non-running Mach-O metadata fixture for static parsing.
(ROOT/'sample.dylib').write_bytes(struct.pack('<IiiIIIII',0xfeedfacf,0x0100000c,0,6,0,0,0,0)+b'REA_MACHO_FIXTURE\x00')
info={'CFBundleIdentifier':'tech.auskal.fixture','CFBundleName':'REA Fixture','CFBundleExecutable':'Fixture','CFBundleVersion':'1','NSAppTransportSecurity':{'NSAllowsArbitraryLoads':True}}
with zipfile.ZipFile(ROOT/'sample.ipa','w') as z:
 z.writestr('Payload/Fixture.app/Info.plist',plistlib.dumps(info));z.writestr('Payload/Fixture.app/Fixture',(ROOT/'sample.dylib').read_bytes());z.writestr('Payload/Fixture.app/Fixture.xcent',plistlib.dumps({'application-identifier':'FIXTURE.tech.auskal.fixture','get-task-allow':True}));z.writestr('Payload/Fixture.app/Frameworks/Demo.framework/Info.plist',plistlib.dumps({'CFBundleName':'Demo'}))
image=Image.new('RGB',(1000,360),'white');draw=ImageDraw.Draw(image)
try:font=ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',42)
except OSError:font=ImageFont.load_default()
draw.text((45,55),'AUSKAL REA SAMPLE',font=font,fill='black');draw.text((45,130),'Static analysis dashboard',font=font,fill='black');draw.text((45,210),'OCR verification 12345',font=font,fill='black')
image.save(ROOT/'screenshot.png');image.save(ROOT/'screenshot.jpg',quality=95)
# Android aapt2 XmlNode/XmlElement protobuf encoding (AOSP Resources.proto).
def varint(n):
 b=b''
 while n>127:b+=bytes([(n&127)|128]);n>>=7
 return b+bytes([n])
def field(n,value):
 if isinstance(value,str):value=value.encode()
 return varint((n<<3)|2)+varint(len(value))+value
def attr(name,value,android=False):return (field(1,'http://schemas.android.com/apk/res/android') if android else b'')+field(2,name)+field(3,value)
def element(name,attrs=(),children=(),namespace=False):
 payload=field(3,name)+b''.join(field(4,attr(*a)) for a in attrs)+b''.join(field(5,c) for c in children)
 if namespace:payload=field(1,field(1,'android')+field(2,'http://schemas.android.com/apk/res/android'))+payload
 return field(1,payload)
manifest=element('manifest',[('package','tech.auskal.fixture'),('versionCode','1',True)],[element('uses-permission',[('name','android.permission.INTERNET',True)]),element('uses-sdk',[('minSdkVersion','21',True)]),element('application',[('label','REA Fixture',True),('usesCleartextTraffic','true',True)])],True)
with zipfile.ZipFile(ROOT/'sample.aab','w') as z:
 z.writestr('BundleConfig.pb',b'');z.writestr('base/manifest/AndroidManifest.xml',manifest)
 if (ROOT/'hello.dex').exists():z.write(ROOT/'hello.dex','base/dex/classes.dex')
# Public passive-render fixture. Deliberately includes an endpoint reference and a tiny script.
(ROOT/'rea-fixture.html').write_text('<!doctype html><title>REA fixture</title><h1 id="result">Loading static fixture</h1><script src="rea-fixture.js"></script>')
(ROOT/'rea-fixture.js').write_text('document.getElementById("result").textContent="AUSKAL PASSIVE RENDER VERIFIED"; const endpoint="/api/v1/fixture";')
print('Created fixtures:',','.join(p.name for p in ROOT.iterdir()))
