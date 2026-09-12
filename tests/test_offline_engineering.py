"""Real delivered CMake archive exercises the complete OFFLINE worker boundary."""
import json
from pathlib import Path
import subprocess
import pytest
from cvevidence.runner import Runner
from cvevidence.storage import RunStore
from cvevidence.core_service import CoreService

ROOT = Path(__file__).resolve().parents[1]

@pytest.fixture
def case(tmp_path):
    runner = Runner(RunStore(tmp_path))
    parent = runner.start_file(ROOT / "demo-inputs/runtime-v2/pc3_cmake_static.tar.gz", cve="CVE-2022-37434")
    assert parent.status == "COLLECTED"
    return runner, parent

def test_real_offline_persistence_scope_and_immutable_parent(case):
    runner, parent = case
    before = runner.store._run_path(parent.run_id).read_bytes()
    child = runner.analyze_offline(parent.run_id)
    assert child.status == "COMPLETED" and child.engineering_status == "COMPLETED"
    assert child.ai_status == "OFFLINE" and child.assessment is None
    payload = runner.read_engineering(child.run_id)
    entry = payload["analyses"][0]
    assert len(entry["queries"]) == 5
    assert entry["assessment"]["verdict"] == "NEEDS_INVESTIGATION"
    assert entry["assessment"]["context_hash"] == parent.input_package.context_hash
    assert runner.store._run_path(parent.run_id).read_bytes() == before
    assert runner.source_tool(child.run_id, "list", limit=1)
    with pytest.raises(FileNotFoundError):
        Runner(RunStore(runner.store.root / "another-account")).read_engineering(child.run_id)
    with pytest.raises(ValueError):
        runner.analyze_offline(parent.run_id, cve_id="CVE-2014-0160")
    with pytest.raises(FileExistsError):
        runner.store.save(child)

def test_tampered_saved_payload_rejected(case):
    runner, parent = case
    child = runner.analyze_offline(parent.run_id)
    path = runner.store.root / "blobs" / child.engineering_payload_sha256
    path.write_bytes(b"{}")
    with pytest.raises(ValueError, match="integrity"):
        runner.read_engineering(child.run_id)

def test_wrong_scope_worker_payload_not_published(case, monkeypatch):
    runner, parent = case
    good = runner.analyze_offline(parent.run_id)
    payload = runner.read_engineering(good.run_id)
    payload["analyses"][0]["cve_id"] = "CVE-2014-0160"
    monkeypatch.setattr(CoreService, "invoke", lambda *a, **k: payload)
    failed = runner.analyze_offline(parent.run_id)
    assert failed.status == "FAILED" and failed.engineering_payload_sha256 is None
    assert failed.assessment is None

def test_timeout_keeps_parent_and_no_partial_result(case, monkeypatch):
    runner, parent = case
    before = runner.store._run_path(parent.run_id).read_bytes()
    def timeout(*a, **k):
        raise subprocess.TimeoutExpired("core", 1)
    monkeypatch.setattr(CoreService, "invoke", timeout)
    failed = runner.analyze_offline(parent.run_id)
    assert failed.status == "TIMED_OUT" and failed.error.code == "TIMEOUT"
    assert failed.engineering_payload_sha256 is None and not failed.sources
    assert runner.store._run_path(parent.run_id).read_bytes() == before

def test_unknown_cve_is_not_a_verdict(tmp_path):
    runner = Runner(RunStore(tmp_path))
    parent = runner.start_file(ROOT / "demo-inputs/runtime-v2/pc3_cmake_static.tar.gz", cve="CVE-2099-99999")
    child = runner.analyze_offline(parent.run_id)
    assert child.engineering_status == "UNSUPPORTED_CVE" and child.ai_status == "NOT_RUN"
    assert runner.read_engineering(child.run_id)["analyses"][0]["assessment"] is None

def test_statement_resets_result_and_requires_new_analysis(case):
    runner, parent = case
    analyzed = runner.analyze_offline(parent.run_id)
    note = runner.supplement_file(analyzed.run_id, note="供應商聲稱不受影響，尚未附證據。")
    assert note.status == "COLLECTED" and note.engineering_payload_sha256 is None
    rerun = runner.analyze_offline(note.run_id)
    result = runner.read_engineering(rerun.run_id)["analyses"][0]["assessment"]
    assert result["verdict"] == "NEEDS_INVESTIGATION" and result["statement_reviews"]

def test_real_delta_reanalysis_changes_context_not_parent(case):
    runner, parent = case
    original = runner.analyze_offline(parent.run_id)
    saved = runner.read_engineering(original.run_id)
    supplemented = runner.supplement_file(original.run_id, path=ROOT / "demo-inputs/runtime-v2/supplement_pc3_cmake_runtime.tar.gz")
    child = runner.analyze_offline(supplemented.run_id)
    new = runner.read_engineering(child.run_id)
    assert new["context_hash"] != saved["context_hash"]
    assert new["analyses"][0]["assessment"]["verdict"] == "AFFECTED"
    assert runner.read_engineering(original.run_id) == saved
