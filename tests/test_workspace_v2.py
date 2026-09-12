from pathlib import Path
import pytest
from streamlit.testing.v1 import AppTest
from cvevidence.runner import Runner
from cvevidence.storage import RunStore
from cvevidence.sources import read_package
from tests.test_runner_v2 import package

def test_source_root_boundaries(tmp_path):
    root=tmp_path/"artifacts";root.mkdir()
    (root/"test.zip").write_bytes(package())
    assert read_package(root,"test.zip")== (root/"test.zip").read_bytes()
    outside=tmp_path/"outside.zip";outside.write_bytes(b"private")
    (root/"link.zip").symlink_to(outside)
    for path in ("../outside.zip","link.zip",str(outside)):
        with pytest.raises(ValueError): read_package(root,path)
    with pytest.raises(ValueError): read_package(root,"test.zip",limit=1)

def test_workspace_empty_and_history(tmp_path,monkeypatch):
    monkeypatch.setenv("CVEVIDENCE_STORE",str(tmp_path/"runs"))
    run=Runner(RunStore(tmp_path/"runs")).start(package(),"TEST","CVE-2014-0160")
    app=AppTest.from_file(str(Path(__file__).resolve().parents[1]/"runner_app.py")).run()
    assert not app.exception
    app.session_state["selected_run"]=run.run_id
    for page in ("02 資料確認與缺件","03 分析進度與結果","04 報告與後續行動"):
        app.sidebar.radio[0].set_value(page).run()
        assert not app.exception
    assert any("NOT_ASSESSED" in code.value for code in app.code)

def test_workspace_supplement_note(tmp_path,monkeypatch):
    monkeypatch.setenv("CVEVIDENCE_STORE",str(tmp_path/"runs"))
    store=RunStore(tmp_path/"runs")
    parent=Runner(store).start(package(missing=True),"TEST","CVE-2014-0160")
    app=AppTest.from_file(str(Path(__file__).resolve().parents[1]/"runner_app.py")).run()
    app.session_state["selected_run"]=parent.run_id
    app.sidebar.radio[0].set_value("04 報告與後續行動").run()
    app.text_area[0].set_value("TEST ONLY: supplier statement").run()
    next(button for button in app.button if button.label=="保存補件並建立新 run").click().run()
    assert not app.exception
    child=store.read(app.session_state["selected_run"])
    assert child.parent_run_id==parent.run_id
    assert child.assessment is None and child.missing==parent.missing
