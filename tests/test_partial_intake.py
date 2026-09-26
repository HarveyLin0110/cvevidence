import json
import pytest
from cvevidence_core.partial_intake import create
from cvevidence_core.integrity import safe_extract,ingest_package
from cvevidence_core.queries import collect_evidence
from cvevidence_core.verifier import verify
from cvevidence_core.assessment import assess

def test_partial_files_do_not_invent_product_identity(tmp_path):
    archive=tmp_path/'p.tgz'
    create([('trace.log',b'TEST_ONLY'),('source/foo.c',b'int foo(void) {return 1;}')],archive)
    safe_extract(archive,tmp_path/'p');c=ingest_package(tmp_path/'p')
    assert c.manifest['artifact_role']=='MATERIAL_INVENTORY_NOT_PRODUCT_BINARY'
    a=assess(c,verify(c,collect_evidence(c,'CVE-2023-38545')))
    assert a['assessment_kind']=='GENERAL_TRIAGE' and a['verdict']=='NEEDS_INVESTIGATION'
    assert c.missing

@pytest.mark.parametrize('files',[[('../escape',b'x')],[('manifest.json',b'x')],[('x',b'x'),('x',b'y')]])
def test_partial_rejects_unsafe_paths(tmp_path,files):
    with pytest.raises(ValueError):create(files,tmp_path/'p.tgz')

def test_loose_supplement_targets_exact_parent_and_rejects_replacement(tmp_path):
    from cvevidence_core.partial_intake import create_supplement
    from cvevidence_core.supplements import validate_supplement
    create([('trace.log',b'TEST_ONLY')],tmp_path/'p.tgz')
    safe_extract(tmp_path/'p.tgz',tmp_path/'p');base=ingest_package(tmp_path/'p')
    create_supplement(base,[('source/foo.c',b'int foo;')],tmp_path/'delta.tgz')
    safe_extract(tmp_path/'delta.tgz',tmp_path/'delta')
    assert validate_supplement(base,tmp_path/'delta')['can_merge']
    with pytest.raises(ValueError):create_supplement(base,[('trace.log',b'changed')],tmp_path/'bad.tgz')

def test_wheel_material_expands_as_data_and_never_executes(tmp_path):
    import zipfile,io
    wheel=io.BytesIO()
    with zipfile.ZipFile(wheel,'w') as z:z.writestr('demo/query.py','raise RuntimeError("MUST_NOT_EXECUTE")')
    create([('demo.whl',wheel.getvalue())],tmp_path/'p.tgz')
    safe_extract(tmp_path/'p.tgz',tmp_path/'p');c=ingest_package(tmp_path/'p')
    assert c.by_path('demo.whl.unpacked/demo/query.py')

def test_partial_runner_keeps_unverified_identity_after_analysis(tmp_path,monkeypatch):
    from cvevidence.runner import Runner
    from cvevidence.storage import RunStore
    monkeypatch.setenv('CVEVIDENCE_PUBLIC_CVE_LOOKUP','0')
    create([('trace.log',b'TEST_ONLY')],tmp_path/'p.tgz')
    r=Runner(RunStore(tmp_path/'runtime'));before=r.start_file(tmp_path/'p.tgz',cve='CVE-2024-42005',symptom='TEST_ONLY')
    after=r.analyze_offline(before.run_id)
    assert after.missing==before.missing and after.missing
    assert after.candidates['symptom']=='TEST_ONLY'
