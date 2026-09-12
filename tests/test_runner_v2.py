import hashlib
import io
import json
import subprocess
import zipfile
from uuid import uuid4
import pytest
from cvevidence.runner import Runner
from cvevidence.storage import RunStore
from cvevidence.cli import main

def package(content=b"TEST ONLY", build="test-build", missing=False):
    return json.dumps(dict(marker="TEST_ONLY",content=content.decode(),build=build,missing=missing)).encode()

def test_persist_reload_and_immutability(tmp_path):
    store=RunStore(tmp_path)
    payload=package()
    run=Runner(store).start(payload,"TEST","CVE-2014-0160")
    assert run.status=="COLLECTED" and run.assessment is None
    assert RunStore(tmp_path).read(run.run_id)==run
    assert store.read_blob(run.input_package.archive_sha256)==payload
    with pytest.raises(FileExistsError):
        store.save(run)

def test_bad_input_and_live_do_not_produce_verdict(tmp_path):
    runner=Runner(RunStore(tmp_path))
    for payload,mode,code in [(b"bad","OFFLINE","INTAKE_REJECTED"),(package(),"LIVE","CORE_UNAVAILABLE")]:
        run=runner.start(payload,"TEST","CVE-2014-0160",mode)
        assert run.status=="FAILED" and run.error.code==code
        assert not run.evidence and run.assessment is None

def test_worker_deadline(tmp_path):
    run=Runner(RunStore(tmp_path)).start(package(),"TEST","CVE-2014-0160",timeout=0.000001)
    assert run.status=="TIMED_OUT" and run.error.code=="TIMEOUT"

def test_missing_is_not_a_verdict(tmp_path):
    run=Runner(RunStore(tmp_path)).start(package(missing=True),"TEST","CVE-2014-0160")
    assert run.missing==["test.txt"] and run.assessment is None

def test_storage_rejects_paths_and_tamper(tmp_path):
    store=RunStore(tmp_path)
    with pytest.raises(ValueError):
        store.read("../secrets")
    digest=store.put_blob(b"test")
    (tmp_path/"blobs"/digest).write_bytes(b"changed")
    with pytest.raises(ValueError):
        store.read_blob(digest)

def test_cli_and_runner_same_payload(tmp_path,capsys):
    payload=package()
    path=tmp_path/"test.zip"; path.write_bytes(payload)
    assert main(["--store",str(tmp_path/"cli"),"run",str(path),"--product","TEST","--cve","CVE-2014-0160"])==0
    cli=json.loads(capsys.readouterr().out)
    direct=Runner(RunStore(tmp_path/"direct")).start(payload,"TEST","CVE-2014-0160").model_dump()
    for item in (cli,direct):
        item.pop("run_id");item.pop("created_at")
    assert cli==direct

def test_save_failure_propagates(tmp_path,monkeypatch):
    store=RunStore(tmp_path)
    def fail(run): raise OSError("disk full")
    monkeypatch.setattr(store,"save",fail)
    with pytest.raises(OSError):
        Runner(store).start(package(),"TEST","CVE-2014-0160")

def test_invalid_cve_does_not_run(tmp_path):
    store=RunStore(tmp_path)
    with pytest.raises(ValueError):
        Runner(store).start(package(),"TEST","not-a-cve")
    assert store.list_runs()==[]

def test_default_core_is_explicitly_unavailable(tmp_path,monkeypatch):
    monkeypatch.delenv("CVEVIDENCE_CORE_MODULE")
    run=Runner(RunStore(tmp_path)).start(b"untrusted input","TEST","CVE-2014-0160")
    assert run.error.code=="CORE_UNAVAILABLE"
    assert run.assessment is None
