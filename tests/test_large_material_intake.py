"""Bounded streams and new TEST_ONLY large inputs; not real product impact tests."""
import io
import zipfile
from uuid import uuid4
import pytest
from cvevidence_core import partial_intake as intake
from cvevidence_core.integrity import safe_extract,ingest_package


class ChunkedInput:
    def __init__(self,size,prefix=b'TEST_ONLY'):
        self.size=size;self.prefix=prefix;self.position=0;self.read_sizes=[]
    def seek(self,offset):
        assert offset==0
        self.position=0
    def read(self,size):
        assert 0<size<=1024*1024, 'No whole-file read'
        self.read_sizes.append(size)
        count=min(size,self.size-self.position)
        start=self.position;self.position+=count
        head=self.prefix[start:min(start+count,len(self.prefix))] if start<len(self.prefix) else b''
        return head+b'\0'*(count-len(head))
    def getvalue(self):
        raise AssertionError('Do not duplicate the upload buffer')


def test_actual_large_stream_exceeds_old_limit_and_preserves_bytes(tmp_path):
    stream=ChunkedInput(24*1024*1024)
    with pytest.raises(ValueError):intake.create([('device.rom',stream)],tmp_path/'small.tgz')
    assert not (tmp_path/'small.tgz').exists()
    intake.create([('device.rom',stream)],tmp_path/'large.tgz',large=True)
    safe_extract(tmp_path/'large.tgz',tmp_path/'data');context=ingest_package(tmp_path/'data')
    path,row=context.by_path('device.rom')
    assert row['size']==24*1024*1024
    with path.open('rb') as handle:assert handle.read(9)==b'TEST_ONLY'
    assert len(stream.read_sizes)>24 and max(stream.read_sizes)<=1024*1024


def test_stream_retry_rewinds_and_creates_identical_request(tmp_path):
    from cvevidence.runner import Runner
    from cvevidence.storage import RunStore
    stream=ChunkedInput(100)
    intake.create([('trace.txt',stream)],tmp_path/'first.tgz')
    intake.create([('trace.txt',stream)],tmp_path/'second.tgz')
    assert (tmp_path/'first.tgz').read_bytes()==(tmp_path/'second.tgz').read_bytes()
    assert (tmp_path/'first.tgz').stat().st_mode & 0o777==0o600
    runner=Runner(RunStore(tmp_path/'runtime'));request_id=str(uuid4())
    first=runner.submit_request(path=tmp_path/'first.tgz',request_id=request_id)
    assert runner.submit_request(path=tmp_path/'second.tgz',request_id=request_id)==first
    assert len(runner.store.list_runs())==1


def test_large_mode_is_single_supported_input_and_bounded(tmp_path,monkeypatch):
    with pytest.raises(ValueError):intake.create([('a.rom',b'x'),('b.rom',b'y')],tmp_path/'two',large=True)
    with pytest.raises(ValueError):intake.create([('a.txt',b'x')],tmp_path/'text',large=True)
    monkeypatch.setattr(intake,'LARGE_FILE',8)
    with pytest.raises(ValueError):intake.create([('a.rom',ChunkedInput(9))],tmp_path/'big',large=True)
    assert not (tmp_path/'big').exists()


def test_archive_expansion_shares_budget_across_files(tmp_path,monkeypatch):
    body=io.BytesIO()
    with zipfile.ZipFile(body,'w',compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('source.c',b'x'*2048)
    monkeypatch.setattr(intake,'MAX_SNAPSHOT',1024)
    with pytest.raises(ValueError):intake.create([('sdk.zip',body)],tmp_path/'sdk',large=True)
    assert not (tmp_path/'sdk').exists()


def test_supplement_checks_combined_snapshot_not_just_new_upload(tmp_path,monkeypatch):
    intake.create([('old.txt',b'x'*1024)],tmp_path/'base.tgz')
    safe_extract(tmp_path/'base.tgz',tmp_path/'base');base=ingest_package(tmp_path/'base')
    before=(tmp_path/'base/old.txt').read_bytes()
    monkeypatch.setattr(intake,'MAX_SNAPSHOT',1500)
    with pytest.raises(ValueError):intake.create_supplement(base,[('new.txt',io.BytesIO(b'y'*1024))],tmp_path/'delta')
    assert (tmp_path/'base/old.txt').read_bytes()==before
    assert not (tmp_path/'delta').exists()


def test_large_sdk_stream_expands_without_running_programs(tmp_path):
    body=io.BytesIO()
    with zipfile.ZipFile(body,'w') as archive:
        archive.writestr('setup.py','raise RuntimeError("MUST_NOT_EXECUTE")')
        archive.writestr('include/device.h','/* TEST_ONLY */')
    intake.create([('sdk.zip',body)],tmp_path/'sdk.tgz',large=True)
    safe_extract(tmp_path/'sdk.tgz',tmp_path/'sdk')
    assert ingest_package(tmp_path/'sdk').by_path('sdk.zip.unpacked/include/device.h')


def test_large_supplement_preserves_original_run(tmp_path):
    from cvevidence.runner import Runner
    from cvevidence.storage import RunStore
    intake.create([('old.txt',b'TEST_ONLY')],tmp_path/'base.tgz')
    runner=Runner(RunStore(tmp_path/'runtime'));base=runner.start_file(tmp_path/'base.tgz')
    before=runner.store._run_path(base.run_id).read_bytes()
    child=runner.supplement_partial(base.run_id,[('device.rom',io.BytesIO(b'TEST_ONLY'))],large=True)
    assert not child.error and child.parent_run_id==base.run_id
    assert runner.store._run_path(base.run_id).read_bytes()==before


def test_large_upload_ui_is_single_file_and_separate_from_small_mode(tmp_path):
    from streamlit.testing.v1 import AppTest
    from tests.test_package_inventory import inventory_app
    app=AppTest.from_function(inventory_app,default_timeout=20)
    app.session_state['test_store']=str(tmp_path/'runtime')
    app.run();app.radio[0].set_value('上傳產品材料').run()
    next(r for r in app.radio if r.label=='依檔案大小選擇收件方式').set_value('大型單檔（最多 256 MiB）').run()
    assert not app.exception
    assert len(app.get('file_uploader'))==1
    assert any('384 MiB' in c.value and '網頁元件仍會暫存' in c.value for c in app.caption)
    assert next(b for b in app.button if b.label=='匯入並建立查核').disabled
    next(r for r in app.radio if r.label=='依檔案大小選擇收件方式').set_value('一般多檔（每檔最多 20 MiB）').run()
    assert not app.exception
    assert any('每檔 20 MiB' in c.value for c in app.caption)
    assert any('補件保留原材料' in x.value for x in app.info)
