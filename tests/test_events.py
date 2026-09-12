import json
from pathlib import Path
import pytest
from cvevidence.events import EventStore
from cvevidence.runner import Runner
from cvevidence.storage import RunStore
from cvevidence.core_service import CoreService
from tests.test_real_bridge import archive

def test_success_and_failure_are_scoped_without_raw_text(tmp_path):
    runner=Runner(RunStore(tmp_path/"store"))
    run=runner.start_file(archive(tmp_path))
    phrase="TEST_ONLY secret search phrase"
    runner.source_tool(run.run_id,"search",term=phrase)
    with pytest.raises(ValueError):
        runner.source_tool(run.run_id,"excerpt",source_id="outside-scope")
    log=EventStore(runner.store).read(run.run_id)
    assert [e["status"] for e in log["events"]]==["SUCCESS","FAILED"]
    assert all(e["context_hash"]==run.input_package.context_hash for e in log["events"])
    assert phrase not in json.dumps(log) and "outside-scope" not in json.dumps(log)
    assert not log["invalid_receipts"]

def test_no_terminal_receipt_is_not_success(tmp_path):
    runner=Runner(RunStore(tmp_path/"store"))
    run=runner.start_file(archive(tmp_path))
    events=EventStore(runner.store)
    events.begin(run,"list",{})
    assert events.read(run.run_id)["events"][0]["status"]=="NO_TERMINAL_RECEIPT"

def test_cannot_overwrite_terminal_receipt(tmp_path):
    runner=Runner(RunStore(tmp_path/"store"))
    run=runner.start_file(archive(tmp_path))
    events=EventStore(runner.store)
    start=events.begin(run,"list",{})
    events.finish(start,result={})
    with pytest.raises(FileExistsError): events.finish(start,result={"different":True})

def test_bad_receipt_is_visible_not_trusted(tmp_path):
    runner=Runner(RunStore(tmp_path/"store"))
    run=runner.start_file(archive(tmp_path))
    events=EventStore(runner.store)
    start=events.begin(run,"list",{})
    path=events.folder(run.run_id)/(start.event_id+".start.json")
    value=json.loads(path.read_text());value["context_hash"]="0"*64
    path.write_text(json.dumps(value))
    result=events.read(run.run_id)
    assert not result["events"] and len(result["invalid_receipts"])==1

def test_audit_write_failure_prevents_tool_call(tmp_path,monkeypatch):
    runner=Runner(RunStore(tmp_path/"store"))
    run=runner.start_file(archive(tmp_path))
    calls=[]
    monkeypatch.setattr(CoreService,"tool",lambda *a,**k:calls.append(True))
    def broken(*a,**k): raise OSError("TEST_ONLY disk full")
    monkeypatch.setattr(runner.store,"_atomic_new",broken)
    with pytest.raises(OSError): runner.source_tool(run.run_id,"list")
    assert not calls
