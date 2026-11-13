import datetime,json,pathlib,tempfile,unittest,unittest.mock,time
import runner
from reporting import command
class Operations(unittest.TestCase):
 def test_expiry_preserves_sessions_and_recent_runs(self):
  with tempfile.TemporaryDirectory() as temp:
   root=pathlib.Path(temp);(root/'.rea-sessions.json').write_text('[]')
   for id,hours in [('10000000-0000-0000-0000-000000000001',25),('10000000-0000-0000-0000-000000000002',1)]:
    d=root/id;d.mkdir();(d/'job.json').write_text(json.dumps({'created':(datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(hours=hours)).isoformat(),'status':'complete'}));(d/'report.json').write_text('{}')
   with unittest.mock.patch.object(runner,'ROOT',root):runner.cleanup()
   self.assertFalse((root/'10000000-0000-0000-0000-000000000001').exists());self.assertTrue((root/'10000000-0000-0000-0000-000000000002').exists());self.assertTrue((root/'.rea-sessions.json').exists())
 def test_command_timeout(self):
  result=command(['python3','-c','import time;time.sleep(10)'],timeout=.2)
  self.assertFalse(result['ok']);self.assertEqual(result['error'],'Tool timed out');self.assertLess(result['seconds'],3)
 def test_symlink_worker_output_refused(self):
  with tempfile.TemporaryDirectory() as temp:
   p=pathlib.Path(temp);(p/'real').write_text('{}');(p/'link').symlink_to(p/'real')
   with self.assertRaises(ValueError):runner.read(p/'link')
if __name__=='__main__':unittest.main()
