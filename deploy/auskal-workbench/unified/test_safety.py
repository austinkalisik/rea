import io,json,pathlib,socket,tarfile,tempfile,unittest,unittest.mock,zipfile
from acquire import extract,valid_url
from egress import public_address
class Safety(unittest.TestCase):
 def test_egress_private_and_mapped(self):
  for ip in ['127.0.0.1','10.2.3.4','169.254.169.254','172.16.1.2','192.168.1.1','224.0.0.1','::1','fd00::1','::ffff:8.8.8.8']:
   with self.subTest(ip=ip),unittest.mock.patch('socket.getaddrinfo',return_value=[(None,None,None,None,(ip,443))]):
    with self.assertRaises(ValueError):public_address('example.test',443)
  with unittest.mock.patch('socket.getaddrinfo',return_value=[(None,None,None,None,('93.184.216.34',443))]):self.assertEqual(public_address('example.test',443),'93.184.216.34')
 def test_mixed_dns_answer_rejected(self):
  with unittest.mock.patch('socket.getaddrinfo',return_value=[(0,0,0,0,('8.8.8.8',443)),(0,0,0,0,('10.0.0.1',443))]):
   with self.assertRaises(ValueError):public_address('example.test',443)
 def test_url_scope(self):
  for url in ['file:///etc/passwd','https://user:pass@example.com','http://example.com:9000/']:
   with self.assertRaises(ValueError):valid_url(url)
 def test_zip_paths_and_links(self):
  for name,link in [('../outside',False),('/etc/escape',False),('a/../../escape',False),('a\\escape',False),('link',True)]:
   with tempfile.TemporaryDirectory() as d:
    p=pathlib.Path(d);zpath=p/'input.zip'
    with zipfile.ZipFile(zpath,'w') as z:
     info=zipfile.ZipInfo(name)
     if link:info.external_attr=0o120777<<16
     z.writestr(info,b'payload')
    with self.assertRaises(ValueError):extract(zpath,p/'out')
 def test_tar_links(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);archive=p/'input.tar'
   with tarfile.open(archive,'w') as tar:
    i=tarfile.TarInfo('link');i.type=tarfile.SYMTYPE;i.linkname='/etc/passwd';tar.addfile(i)
   with self.assertRaises(ValueError):extract(archive,p/'out')
 def test_duplicate_and_expansion_budget(self):
  import acquire
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);archive=p/'input.zip'
   with zipfile.ZipFile(archive,'w') as z:z.writestr('first.txt',b'a'*20)
   with unittest.mock.patch.object(acquire,'MAX_EXPANDED',10):
    with self.assertRaises(ValueError):extract(archive,p/'out')
 def test_valid_zip(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d);archive=p/'input.zip'
   with zipfile.ZipFile(archive,'w') as z:z.writestr('project/main.py',b'print("example")')
   self.assertEqual(extract(archive,p/'out')['files'],1)
   self.assertTrue((p/'out/project/main.py').is_file())
if __name__=='__main__':unittest.main()
