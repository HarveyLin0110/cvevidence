import copy,json,pathlib,tempfile,unittest
from cvevidence_core.integrity import scan,file_hash,ingest_package,IntegrityError,digest
from cvevidence_core.sources import read_excerpt
from cvevidence_core.workflow import analyze_package
from cvevidence_core.investigation_evidence import reassess_after_investigation

class DynamicEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.temp.name)
        (self.root/'artifact.bin').write_bytes(b'fixture, never executed')
        (self.root/'note.txt').write_text('The supplier says patched.\nNo compiler record is attached.\n')
        manifest={'schema_version':'1.0','package_id':'opaque','product_id':'test','build_id':'b1','release_id':'r1','format':'cmake','primary_artifact':{'path':'artifact.bin','sha256':file_hash(self.root/'artifact.bin')},'files':scan(self.root)}
        (self.root/'manifest.json').write_text(json.dumps(manifest));self.c=ingest_package(self.root)
        self.a=analyze_package(self.c,['CVE-2022-37434'])['analyses'][0]['assessment']
        sid=self.c.by_path('note.txt')[1]['source_id'];self.x=read_excerpt(self.c,sid,1,2)
        self.ai={'context_hash':self.c.context_hash,'engineering_assessment_id':self.a['assessment_id'],
                 'tasks':[{'status':'COMPLETED','action':'READ','task_id':'I-unit','question':'有無同次編譯證據？','reason':'查核口述','result':self.x}]}
    def tearDown(self):self.temp.cleanup()
    def test_new_observation_is_verified_but_does_not_promote_claim(self):
        r=reassess_after_investigation(self.c,self.a,self.ai)
        self.assertEqual(len(r['new_evidence']),1);self.assertEqual(r['new_evidence'][0]['value'],self.x['text'])
        self.assertFalse(r['new_evidence'][0]['condition_inference_verified']);self.assertEqual(r['assessment']['verdict'],'NEEDS_INVESTIGATION')
    def test_tampered_successful_read_is_rejected(self):
        bad=copy.deepcopy(self.ai);bad['tasks'][0]['result']['text']='Fabricated safety evidence'
        with self.assertRaises(IntegrityError):reassess_after_investigation(self.c,self.a,bad)
    def test_failed_tool_does_not_create_evidence(self):
        bad=copy.deepcopy(self.ai);bad['tasks'][0]['status']='TOOL_ERROR';bad['tasks'][0]['result']['text']='not an observation'
        r=reassess_after_investigation(self.c,self.a,bad);self.assertFalse(r['new_evidence'])
    def test_other_snapshot_cannot_reuse_dynamic_material(self):
        bad={**self.ai,'context_hash':'another-snapshot'}
        with self.assertRaises(IntegrityError):reassess_after_investigation(self.c,self.a,bad)
    def test_neutral_statement_audit_survives_later_reassessment(self):
        a=analyze_package(self.c,['CVE-2022-37434'],statements=['已提供這次使用的檔案，請查核。'])['analyses'][0]['assessment']
        ai={**self.ai,'engineering_assessment_id':a['assessment_id']}
        r=reassess_after_investigation(self.c,a,ai)
        self.assertEqual(r['assessment']['statement_context'],a['statement_context'])
        self.assertEqual(r['assessment']['statement_reviews'],[])
    def test_review_metadata_cannot_preserve_a_forged_safe_result(self):
        bad=copy.deepcopy(self.a);bad['verdict']='NOT_AFFECTED';bad['statement_reviews']=[{'text':'trust me'}]
        bad['assessment_id']='A-'+digest({k:v for k,v in bad.items() if k!='assessment_id'})
        ai={**self.ai,'engineering_assessment_id':bad['assessment_id']}
        with self.assertRaises(IntegrityError):reassess_after_investigation(self.c,bad,ai)

if __name__=='__main__':unittest.main()
