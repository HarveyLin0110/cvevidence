"""Failed material intake must explain recovery without leaking raw archive text."""
import io
import tarfile
import zipfile
import pytest
from cvevidence_core import partial_intake as intake
from cvevidence_core.integrity import safe_extract,ingest_package


def test_invalid_archive_is_curated_and_no_output(tmp_path):
    with pytest.raises(intake.IntakeError) as error:
        intake.create([('sdk.zip',b'not a zip')],tmp_path/'out')
    assert error.value.code=='ARCHIVE_INVALID'
    assert '重新提供' in str(error.value)
    assert not (tmp_path/'out').exists()


@pytest.mark.parametrize('kind,code',[('size','EXPANDED_LIMIT'),('count','FILE_LIMIT'),('escape','ARCHIVE_UNSAFE')])
def test_archive_limits_and_unsafe_names_have_distinct_guidance(tmp_path,monkeypatch,kind,code):
    data=io.BytesIO()
    with zipfile.ZipFile(data,'w',compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr('../SECRET_COMPANY_PATH' if kind=='escape' else 'source.c',b'x'*4096)
        z.writestr('second.c',b'y')
    if kind=='size':monkeypatch.setattr(intake,'MAX_SNAPSHOT',1024)
    if kind=='count':monkeypatch.setattr(intake,'MAX_FILES',2)
    with pytest.raises(intake.IntakeError) as error:
        intake.create([('sdk.zip',data)],tmp_path/'out',large=True)
    assert error.value.code==code
    assert 'SECRET_COMPANY_PATH' not in str(error.value)
    assert not (tmp_path/'out').exists()


def test_internal_sdk_link_gets_capability_guidance(tmp_path):
    data=io.BytesIO()
    with tarfile.open(fileobj=data,mode='w') as tar:
        row=tarfile.TarInfo('source.c');row.size=1;tar.addfile(row,io.BytesIO(b'x'))
        row=tarfile.TarInfo('alias.c');row.type=tarfile.SYMTYPE;row.linkname='source.c';tar.addfile(row)
    with pytest.raises(intake.IntakeError) as error:
        intake.create([('sdk.tar',data)],tmp_path/'out')
    assert error.value.code=='LINKS'
    assert '產品缺件' in str(error.value)


def test_base_over_budget_rejected_before_copy(tmp_path,monkeypatch):
    intake.create([('old.txt',b'x'*1024)],tmp_path/'base.tgz')
    safe_extract(tmp_path/'base.tgz',tmp_path/'base');base=ingest_package(tmp_path/'base')
    monkeypatch.setattr(intake,'MAX_SNAPSHOT',1500)
    import shutil
    def forbidden(*args,**kwargs):pytest.fail('Oversized merge must not copy parent files')
    monkeypatch.setattr(shutil,'copyfile',forbidden)
    with pytest.raises(intake.IntakeError) as error:
        intake.create([('new.txt',b'y'*1024)],tmp_path/'out',base=base)
    assert error.value.code=='SNAPSHOT_LIMIT'
    base.assert_current()


def failing_upload_app():
    import io
    import streamlit as st
    from unittest.mock import patch
    from cvevidence.workspace import workspace
    upload=io.BytesIO(b'corrupt ZIP');upload.name='sdk.zip';upload.file_id='TEST_ONLY'
    with patch.object(st,'file_uploader',return_value=[upload]):
        workspace(st,store_root=st.session_state['test_store'])


def test_web_shows_actionable_archive_error_without_crashing(tmp_path):
    from streamlit.testing.v1 import AppTest
    app=AppTest.from_function(failing_upload_app,default_timeout=20)
    app.session_state['test_store']=str(tmp_path/'runtime')
    app.run();app.radio[0].set_value('上傳產品材料').run()
    next(b for b in app.button if b.label=='匯入並建立查核').click().run()
    assert not app.exception
    assert any('封存檔損壞' in x.value and '重新提供' in x.value for x in app.error)
