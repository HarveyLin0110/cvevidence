"""Request behavior tests use real intake with synthetic, clearly marked archives."""
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from uuid import uuid4
import json
from pathlib import Path
import pytest
from streamlit.testing.v1 import AppTest
from cvevidence.runner import Runner
from cvevidence.storage import RunStore
from cvevidence.requests import RequestStore, RequestBusy, parse_cves
from tests.test_real_bridge import archive

def test_draft_is_persisted_without_analysis(tmp_path):
    runner=Runner(RunStore(tmp_path/"store"))
    result=runner.submit_request(symptom="TEST_ONLY: gzip EOF")
    assert result.status=="DRAFT" and not result.runs
    assert not runner.store.list_runs()
    assert result.discovery["symptom_causation"]=="NOT_ESTABLISHED"
    assert runner.read_request(result.spec.request_id)==result

def test_multiple_cves_use_independent_runs_and_frozen_archive(tmp_path):
    runner=Runner(RunStore(tmp_path/"store"))
    result=runner.submit_request(path=archive(tmp_path),cves=["CVE-2014-0160","CVE-2099-9999"])
    runs=[runner.store.read(row.run_id) for row in result.runs]
    assert result.status=="COLLECTED"
    assert len({r.run_id for r in runs})==2
    assert [r.cve_id for r in runs]==result.spec.cves
    assert {r.input_package.archive_sha256 for r in runs}=={result.spec.archive_sha256}
    assert all(r.assessment is None for r in runs)
    assert runner.read_request(result.spec.request_id)==result

def test_same_uuid_replays_but_changed_payload_rejected(tmp_path):
    runner=Runner(RunStore(tmp_path/"store"))
    path=archive(tmp_path)
    uid=str(uuid4())
    first=runner.submit_request(path=path,cves=["CVE-2014-0160"],request_id=uid)
    again=runner.submit_request(path=path,cves=["CVE-2014-0160"],request_id=uid)
    assert again==first and len(runner.store.list_runs())==1
    with pytest.raises(ValueError):
        runner.submit_request(path=path,cves=["CVE-2022-37434"],request_id=uid)
    assert len(runner.store.list_runs())==1

def test_concurrent_request_does_not_duplicate_runs(tmp_path,monkeypatch):
    runner=Runner(RunStore(tmp_path/"store"))
    path=archive(tmp_path)
    entered,release=Event(),Event()
    original=runner.start_file
    def slow(*args,**kwargs):
        entered.set()
        assert release.wait(10)
        return original(*args,**kwargs)
    monkeypatch.setattr(runner,"start_file",slow)
    uid=str(uuid4())
    with ThreadPoolExecutor(max_workers=1) as executor:
        future=executor.submit(runner.submit_request,path=path,request_id=uid)
        assert entered.wait(10)
        try:
            with pytest.raises(RequestBusy): runner.submit_request(path=path,request_id=uid)
        finally: release.set()
        result=future.result()
    assert len(runner.store.list_runs())==1 and result.status=="COLLECTED"

def test_interrupted_request_fails_closed_on_retry(tmp_path,monkeypatch):
    runner=Runner(RunStore(tmp_path/"store"))
    path=archive(tmp_path)
    original=runner.start_file
    calls=[]
    def fail_second(*args,**kwargs):
        calls.append(kwargs["cve"])
        if len(calls)==2: raise RuntimeError("TEST_ONLY interruption")
        return original(*args,**kwargs)
    monkeypatch.setattr(runner,"start_file",fail_second)
    kwargs=dict(path=path,request_id=str(uuid4()),cves=["CVE-2014-0160","CVE-2022-37434"])
    with pytest.raises(RuntimeError): runner.submit_request(**kwargs)
    assert len(runner.store.list_runs())==1
    with pytest.raises(RequestBusy): runner.submit_request(**kwargs)
    assert len(runner.store.list_runs())==1 and len(calls)==2

def test_draft_continuation_keeps_parent(tmp_path):
    runner=Runner(RunStore(tmp_path/"store"))
    draft=runner.submit_request(symptom="TEST_ONLY missing files")
    original=RequestStore(runner.store).path(draft.spec.request_id).read_bytes()
    child=runner.submit_request(path=archive(tmp_path),parent_request_id=draft.spec.request_id)
    assert child.spec.parent_request_id==draft.spec.request_id
    assert RequestStore(runner.store).path(draft.spec.request_id).read_bytes()==original

def test_request_deadline_does_not_restart_for_each_cve(tmp_path):
    runner=Runner(RunStore(tmp_path/"store"))
    result=runner.submit_request(path=archive(tmp_path),timeout=.000001,
        cves=["CVE-2014-0160","CVE-2022-37434"])
    assert result.status=="FAILED"
    assert all(r.status=="TIMED_OUT" for r in result.runs)

def test_parse_and_boundaries():
    assert parse_cves("cve-2014-0160, CVE-2014-0160\nCVE-2099-9999")==["CVE-2014-0160","CVE-2099-9999"]
    for value in ["not-a-cve",",".join(f"CVE-2026-{1000+i}" for i in range(6))]:
        with pytest.raises(ValueError): parse_cves(value)

def test_cli_and_ui_draft_share_request_contract(tmp_path,monkeypatch,capsys):
    from cvevidence.cli import main
    root=tmp_path/"store"
    assert main(["--store",str(root),"request","--symptom","TEST_ONLY CLI"])==0
    data=json.loads(capsys.readouterr().out)
    assert Runner(RunStore(root)).read_request(data["spec"]["request_id"]).status=="DRAFT"
    monkeypatch.setenv("CVEVIDENCE_STORE",str(root))
    app=AppTest.from_file(str(Path(__file__).resolve().parents[1]/"runner_app.py")).run()
    next(r for r in app.radio if r.label=="資料來源").set_value("先描述情境").run()
    app.text_area[0].set_value("TEST_ONLY UI").run()
    next(b for b in app.button if b.label=="匯入並建立查核").click().run()
    assert not app.exception
    request_id=app.session_state["selected_request"]
    assert Runner(RunStore(root)).read_request(request_id).status=="DRAFT"
    next(b for b in app.button if b.label=="匯入並建立查核").click().run()
    assert app.session_state["selected_request"]==request_id
    assert len(RequestStore(RunStore(root)).history()[0])==2
