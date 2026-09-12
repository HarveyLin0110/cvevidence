"""Real delivered CMake package through actual workspace buttons and saved runs."""
from pathlib import Path
from streamlit.testing.v1 import AppTest
from cvevidence.runner import Runner
from cvevidence.storage import RunStore

ROOT = Path(__file__).resolve().parents[1]


def test_request_description_never_prefills_an_unrelated_history_run():
    from types import SimpleNamespace
    from cvevidence.request_ui import symptom_for_run
    request=SimpleNamespace(spec=SimpleNamespace(symptom="TEST_ONLY scenario A"),runs=[SimpleNamespace(run_id="case-A")])
    assert symptom_for_run(request,"case-A")=="TEST_ONLY scenario A"
    assert symptom_for_run(request,"case-B")==""
    assert symptom_for_run(None,"case-A")==""


def test_account_scoped_workspace_omits_local_server_path(tmp_path):
    app=AppTest.from_string("import streamlit as st\nfrom cvevidence.workspace import workspace\nworkspace(st, store_root="+repr(str(tmp_path / "account"))+")").run()
    assert not app.exception
    assert "受控路徑" not in app.radio[0].options
    assert "上傳工程包" in app.radio[0].options


def click(app, label):
    next(b for b in app.button if b.label == label).click().run(timeout=40)
    assert not app.exception


def test_real_analysis_ai_exit_report_and_supplement_reanalysis(tmp_path, monkeypatch):
    runner = Runner(RunStore(tmp_path / "runtime"))
    parent = runner.start_file(ROOT / "demo-inputs/runtime-v2/pc3_cmake_static.tar.gz", cve="CVE-2022-37434")
    before = runner.store._run_path(parent.run_id).read_bytes()
    monkeypatch.setenv("CVEVIDENCE_STORE", str(runner.store.root))
    app = AppTest.from_file(str(ROOT / "runner_app.py")).run()
    app.session_state.selected_run = parent.run_id
    app.run()
    assert next(b for b in app.sidebar.button if b.label == "04 AI 查核與補件").disabled
    click(app, "03 分析進度與結果")
    click(app, "執行 Queries 與正式判定")
    first = runner.store.read(app.session_state.selected_run)
    assert first.parent_run_id == parent.run_id
    assert runner.read_engineering(first.run_id)["analyses"][0]["assessment"]["verdict"] == "NEEDS_INVESTIGATION"
    assert any("需要進一步調查" in t.value for t in app.text)
    assert len([e for e in app.expander if e.label.startswith("Q")]) == 5
    click(app, "下一步：AI 查核與補件")
    assert any("OFFLINE" in t.value for t in app.text)
    click(app, "查看目前報告")
    assert any("需要進一步調查" in c.value for c in app.code)
    click(app, "套用已取得的補件並建立新 run")
    supplemented = runner.store.read(app.session_state.selected_run)
    assert supplemented.parent_run_id == first.run_id and supplemented.engineering_payload_sha256 is None
    assert app.session_state.step == "03 分析進度與結果"
    click(app, "執行 Queries 與正式判定")
    final = runner.store.read(app.session_state.selected_run)
    assert runner.read_engineering(final.run_id)["analyses"][0]["assessment"]["verdict"] == "AFFECTED"
    click(app, "05 報告與後續行動")
    assert any(s.value == "補件前後工程結果" for s in app.subheader)
    assert any("受影響（工程初判）" in c.value for c in app.code)
    assert runner.store._run_path(parent.run_id).read_bytes() == before
    assert runner.read_engineering(first.run_id)["analyses"][0]["assessment"]["verdict"] == "NEEDS_INVESTIGATION"
