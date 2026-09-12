import json,pathlib,tempfile,unittest,zipfile
from cvevidence_core.integrity import IntegrityError,ingest_package,scan,file_hash,safe_extract
from cvevidence_core.sources import read_excerpt,search_sources,verify_excerpt
class IntakeTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.temp.name)/'package';self.root.mkdir()
  (self.root/'artifact.elf').write_bytes(b'\x7fELF\0test bytes')
  (self.root/'source.c').write_text('one\nint main(void) { return 0; }\nthree\n')
  self.publish()
 def tearDown(self):self.temp.cleanup()
 def publish(self):
  value={'schema_version':'1.0','format':'cmake','package_id':'arbitrary-label','product_id':'test','release_id':'r1','build_id':'b1','primary_artifact':{'path':'artifact.elf','sha256':file_hash(self.root/'artifact.elf')},'files':scan(self.root)}
  (self.root/'manifest.json').write_text(json.dumps(value))
 def test_quote_and_stale_input(self):
  context=ingest_package(self.root);sid=next(k for k,v in context.sources.items() if v['path']=='source.c')
  excerpt=read_excerpt(context,sid,2,2);self.assertEqual(excerpt['text'],'int main(void) { return 0; }');self.assertTrue(verify_excerpt(context,excerpt))
  changed={**excerpt,'text':'int main(void) { return 1; }'};self.assertFalse(verify_excerpt(context,changed))
  (self.root/'source.c').write_text('changed')
  self.assertFalse(verify_excerpt(context,excerpt))
  with self.assertRaises(IntegrityError):context.assert_current()
 def test_unknown_source_and_traversal(self):
  context=ingest_package(self.root)
  for sid in ['../../etc/passwd','/etc/passwd','S-made-up']:
   with self.assertRaises(IntegrityError):read_excerpt(context,sid)
 def test_missing_is_new_delivery_not_tamper(self):
  (self.root/'source.c').unlink()
  with self.assertRaises(IntegrityError):ingest_package(self.root)
  self.publish();context=ingest_package(self.root);self.assertEqual(search_sources(context,'main')['matches'],[])
 def test_escape_symlink_rejected(self):
  (self.root/'outside').symlink_to('/etc/passwd')
  with self.assertRaises(IntegrityError):self.publish()
 def test_zip_slip_rejected_before_extract(self):
  archive=pathlib.Path(self.temp.name)/'bad.zip';dest=pathlib.Path(self.temp.name)/'unpack'
  with zipfile.ZipFile(archive,'w') as z:z.writestr('../escape','bad')
  with self.assertRaises(IntegrityError):safe_extract(archive,dest)
  self.assertFalse(dest.exists());self.assertFalse((dest.parent/'escape').exists())
 def test_zip_duplicate_rejected(self):
  archive=pathlib.Path(self.temp.name)/'duplicate.zip';dest=pathlib.Path(self.temp.name)/'unpack'
  with zipfile.ZipFile(archive,'w') as z:
   z.writestr('same','one');z.writestr('same','two')
  with self.assertRaises(IntegrityError):safe_extract(archive,dest)
 def test_bounded_excerpt(self):
  context=ingest_package(self.root);sid=next(k for k,v in context.sources.items() if v['path']=='source.c')
  for start,end in [(0,1),(1,201),(3,2),(100,100)]:
   with self.assertRaises(ValueError):read_excerpt(context,sid,start,end)
 def test_valid_zip_roundtrip(self):
  archive=pathlib.Path(self.temp.name)/'good.zip';dest=pathlib.Path(self.temp.name)/'unpack'
  with zipfile.ZipFile(archive,'w') as z:
   for p in self.root.iterdir():z.write(p,p.name)
  safe_extract(archive,dest);self.assertEqual(ingest_package(dest).context_hash,ingest_package(self.root).context_hash)
if __name__=='__main__':unittest.main()
