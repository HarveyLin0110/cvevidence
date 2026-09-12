"""Real fresh archives verify statement continuity across saved Runner stages."""
from pathlib import Path
from uuid import uuid4
import json

import pytest

from cvevidence.analysis_context import read_analysis_context
from cvevidence.core_service import CoreService
from cvevidence.runner import Runner
from cvevidence.storage import RunStore

ROOT = Path(__file__).resolve().parents[1]
SCOPE_NOTE = "產品還有另一個未交付的網路更新入口，會接收 gzip；該入口的程式與編譯資料尚未提供。"
SYMPTOM = "更新匯入失敗，gzip stream ended before trailer"


@pytest.fixture
def case(tmp_path):
    runner = Runner(RunStore(tmp_path / "runtime"))
    intake = runner.start_file(ROOT / "demo-inputs/cmake/06_cmake.tar.gz",
                               cve="CVE-2022-37434", symptom=SYMPTOM)
    assert intake.status == "COLLECTED"
    return runner, intake


def analyze(runner, intake):
    run = runner.analyze_offline(intake.run_id)
    assert run.status == "COMPLETED"
    return run, runner.read_engineering(run.run_id)


def test_unresolved_scope_survives_delta_and_reload_without_changing_old_runs(case):
    runner, intake = case
    first, _ = analyze(runner, intake)
    note = runner.supplement_file(first.run_id, note=SCOPE_NOTE)
    noted, before = analyze(runner, note)
    old = {p: p.read_bytes() for p in runner.store.root.joinpath("runs").glob("*.json")}
    blob = runner.store.read_blob(noted.engineering_payload_sha256)
    delta = runner.supplement_file(noted.run_id,
                                  path=ROOT / "demo-inputs/cmake/supplement_06_cmake.tar.gz")
    # Fresh process-side facade: no session state or original request is available.
    runner = Runner(RunStore(runner.store.root))
    final, after = analyze(runner, delta)
    a, b = (p["analyses"][0]["assessment"] for p in (before, after))
    assert a["verdict"] == b["verdict"] == "NEEDS_INVESTIGATION"
    assert after["context_hash"] != before["context_hash"]
    assert len(b["statement_context"]) == 1
    original, carried = a["statement_context"][0], b["statement_context"][0]
    assert carried["text"] == SCOPE_NOTE
    assert carried["statement_id"] == original["statement_id"]
    assert carried["source_context_hash"] == original["source_context_hash"]
    assert carried["assessed_context_hash"] == after["context_hash"]
    assert carried["blocks_verdict"] is True
    assert after["discovery"]["symptom"] == SYMPTOM
    assert all(p.read_bytes() == content for p, content in old.items())
    assert runner.store.read_blob(noted.engineering_payload_sha256) == blob
    assert final.parent_run_id == delta.run_id


def test_two_notes_without_intermediate_analysis_are_kept(case):
    runner, intake = case
    first = runner.supplement_file(intake.run_id, note=SCOPE_NOTE)
    second = runner.supplement_file(first.run_id, note="已提供檔案。")
    _, payload = analyze(runner, second)
    assessment = payload["analyses"][0]["assessment"]
    assert [s["text"] for s in assessment["statement_context"]] == [SCOPE_NOTE, "已提供檔案。"]
    assert len(assessment["statement_reviews"]) == 1


def test_new_evidence_can_resolve_a_historical_claim(tmp_path):
    runner = Runner(RunStore(tmp_path))
    intake = runner.start_file(ROOT / "demo-inputs/rom/03_rom.tar.gz", cve="CVE-2014-0160")
    note = runner.supplement_file(intake.run_id, note="heartbeat 已停用")
    old, before = analyze(runner, note)
    delta = runner.supplement_file(old.run_id,
                                  path=ROOT / "demo-inputs/rom/supplement_03_rom.tar.gz")
    _, after = analyze(runner, delta)
    a, b = (p["analyses"][0]["assessment"] for p in (before, after))
    assert a["verdict"] == "NEEDS_INVESTIGATION" and a["statement_reviews"]
    assert b["verdict"] == "NOT_AFFECTED" and b["statement_reviews"] == []
    assert b["statement_context"][0]["statement_id"] == a["statement_context"][0]["statement_id"]
    assert b["statement_context"][0]["blocks_verdict"] is False


def test_explicit_new_symptom_overrides_only_this_child(case):
    runner, intake = case
    child = runner.analyze_offline(intake.run_id, symptom="另一個本次問題")
    assert runner.read_engineering(child.run_id)["discovery"]["symptom"] == "另一個本次問題"
    assert read_analysis_context(runner.store, intake.run_id)["symptom"] == SYMPTOM
    other = Runner(RunStore(runner.store.root / "another-account"))
    with pytest.raises(FileNotFoundError):
        read_analysis_context(other.store, child.run_id)


@pytest.mark.parametrize("fault", ["cycle", "missing", "cve", "build", "note_parent", "depth"])
def test_invalid_ancestry_fails_before_worker(case, monkeypatch, fault):
    runner, intake = case
    child = runner.supplement_file(intake.run_id, note=SCOPE_NOTE)
    parent = runner.store.read(intake.run_id)
    if fault == "cycle":
        parent.parent_run_id = child.run_id
    elif fault == "missing":
        parent.parent_run_id = str(uuid4())
    elif fault == "cve":
        parent.cve_id = "CVE-2014-0160"
    elif fault == "build":
        parent.input_package.declared_build_id = "TEST_ONLY_wrong_build"
    elif fault == "note_parent":
        child.supplement.parent_run_id = str(uuid4())
        runner.store._run_path(child.run_id).write_text(child.model_dump_json())
    else:
        monkeypatch.setattr("cvevidence.analysis_context.MAX_ANCESTORS", 1)
    runner.store._run_path(parent.run_id).write_text(parent.model_dump_json())
    def forbidden(*args, **kwargs):
        pytest.fail("Worker must not receive invalid ancestry")
    monkeypatch.setattr(CoreService, "invoke", forbidden)
    if fault == "note_parent":
        # The stored envelope's own validator already refuses this broken root.
        with pytest.raises(ValueError, match="supplement parent"):
            runner.analyze_offline(child.run_id)
        return
    failed = runner.analyze_offline(child.run_id)
    assert failed.status == "FAILED" and failed.engineering_payload_sha256 is None


@pytest.mark.parametrize("fault", ["hash", "discovery"])
def test_tampered_ancestor_payload_is_not_silently_skipped(case, monkeypatch, fault):
    runner, intake = case
    first, payload = analyze(runner, intake)
    child = runner.supplement_file(first.run_id, note="已提供檔案。")
    if fault == "hash":
        (runner.store.root / "blobs" / first.engineering_payload_sha256).write_bytes(b"{}")
    else:
        payload["discovery"] = None
        first.engineering_payload_sha256 = runner.store.put_blob(json.dumps(payload).encode())
        runner.store._run_path(first.run_id).write_text(first.model_dump_json())
    def forbidden(*args, **kwargs):
        pytest.fail("Worker must not receive corrupt statement history")
    monkeypatch.setattr(CoreService, "invoke", forbidden)
    failed = runner.analyze_offline(child.run_id)
    assert failed.status == "FAILED" and failed.engineering_payload_sha256 is None


def test_history_page_prefills_original_symptom_without_a_selected_request(case, monkeypatch):
    from streamlit.testing.v1 import AppTest
    runner, intake = case
    first, _ = analyze(runner, intake)
    note = runner.supplement_file(first.run_id, note="已提供檔案。")
    monkeypatch.setenv("CVEVIDENCE_STORE", str(runner.store.root))
    app = AppTest.from_file(str(ROOT / "runner_app.py")).run()
    app.session_state.selected_run = note.run_id
    app.session_state.step = "03 分析進度與結果"
    app.run()
    assert not app.exception
    assert next(t for t in app.text_area if t.label == "本次調查情境").value == SYMPTOM
