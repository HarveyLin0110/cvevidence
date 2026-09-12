"""Integration with real Horace parser, using explicitly synthetic boundary material."""
import io
import json
import tarfile
from pathlib import Path
import pytest
from streamlit.testing.v1 import AppTest
from cvevidence.runner import Runner
from cvevidence.storage import RunStore
from cvevidence.core_service import CoreService
from cvevidence_core.integrity import scan, file_hash

def archive(tmp_path, name="base", build="b1", delta=False, large=False):
    root=tmp_path/name
    root.mkdir()
    if not delta:
        (root/"artifact.bin").write_bytes(b"TEST_ONLY_NOT_A_REAL_BINARY")
        (root/"source.c").write_text("TEST_ONLY\nint main(void) { return 0; }\n")
        if large:
            with (root/"large.txt").open("wb") as handle:
                for _ in range(21): handle.write(b"a"*1024*1024)
    else:
        (root/"extra.c").write_text("TEST_ONLY supplement\n")
    primary={"path":"artifact.bin","sha256":__import__("hashlib").sha256(b"TEST_ONLY_NOT_A_REAL_BINARY").hexdigest()}
    manifest=dict(schema_version="1.0",format="cmake",kind="supplement" if delta else "initial",
        product_id="TEST_ONLY_PRODUCT",release_id="r1",build_id=build,package_id=name,
        primary_artifact=primary,files=scan(root))
    if delta: manifest["base_package_id"]="base"
    (root/"manifest.json").write_text(json.dumps(manifest))
    path=tmp_path/(name+".tar")
    with tarfile.open(path,"w") as output:
        for item in root.iterdir(): output.add(item,arcname=item.name)
    return path

def test_real_parser_keeps_sources_separate_and_unknown_cve(tmp_path):
    run=Runner(RunStore(tmp_path/"store")).start_file(archive(tmp_path),cve="CVE-2099-9999")
    assert not run.error
    assert run.input_package.product_id=="TEST_ONLY_PRODUCT"
    assert len(run.sources)==2 and not run.evidence and run.assessment is None
    assert run.candidates["candidates"][0]["status"]=="UNSUPPORTED_CVE"

def test_file_backed_input_exceeds_legacy_20mib(tmp_path):
    path=archive(tmp_path,large=True)
    assert path.stat().st_size>20*1024*1024
    run=Runner(RunStore(tmp_path/"store")).start_file(path)
    assert run.error is None and len(run.sources)==3

def test_tampered_blob_and_foreign_source_rejected(tmp_path):
    store=RunStore(tmp_path/"store")
    runner=Runner(store)
    run=runner.start_file(archive(tmp_path))
    with pytest.raises(ValueError): runner.source_tool(run.run_id,"excerpt",source_id="S-foreign")
    target=store.root/"blobs"/run.input_package.archive_sha256
    target.write_bytes(b"tampered")
    with pytest.raises(ValueError): runner.source_tool(run.run_id,"list")

def test_delta_and_note_preserve_parent(tmp_path):
    store=RunStore(tmp_path/"store")
    runner=Runner(store)
    parent=runner.start_file(archive(tmp_path))
    original=store._run_path(parent.run_id).read_bytes()
    child=runner.supplement_file(parent.run_id,path=archive(tmp_path,"delta",delta=True))
    assert not child.error and len(child.sources)==3
    assert child.input_package.context_hash!=parent.input_package.context_hash
    assert store._run_path(parent.run_id).read_bytes()==original
    note=runner.supplement_file(child.run_id,note="TEST_ONLY assertion, not evidence")
    assert not note.error and note.sources==child.sources
    assert note.assessment is None and note.supplement.kind=="NOTE"

def test_wrong_build_delta_saves_failed_child(tmp_path):
    runner=Runner(RunStore(tmp_path/"store"))
    parent=runner.start_file(archive(tmp_path))
    child=runner.supplement_file(parent.run_id,path=archive(tmp_path,"delta",build="b2",delta=True))
    assert child.error.code=="INTEGRITY_ERROR" and not child.sources
    assert child.parent_run_id==parent.run_id and child.assessment is None

def test_catalog_digest_mismatch_is_failed_intake(tmp_path):
    run=Runner(RunStore(tmp_path/"store")).start_file(archive(tmp_path),archive_sha256="0"*64)
    assert run.error.code=="INTEGRITY_ERROR" and not run.sources

def test_timeout_saves_no_partial_result(tmp_path):
    run=Runner(RunStore(tmp_path/"store")).start_file(archive(tmp_path),timeout=0.000001)
    assert run.status=="TIMED_OUT" and run.error.code=="TIMEOUT" and not run.sources

def test_cli_uses_same_real_runner(tmp_path,capsys):
    from cvevidence.cli import main
    store=tmp_path/"store"
    assert main(["--store",str(store),"import",str(archive(tmp_path))])==0
    output=json.loads(capsys.readouterr().out)
    assert RunStore(store).read(output["run_id"]).input_package.context_hash

def test_ui_real_source_navigation_and_note(tmp_path,monkeypatch):
    store=RunStore(tmp_path/"store")
    run=Runner(store).start_file(archive(tmp_path))
    monkeypatch.setenv("CVEVIDENCE_STORE",str(store.root))
    app=AppTest.from_file(str(Path(__file__).resolve().parents[1]/"runner_app.py")).run()
    app.session_state["selected_run"]=run.run_id
    app.run()
    next(b for b in app.sidebar.button if b.label=="02 資料確認與缺件").click().run()
    next(b for b in app.button if b.label=="下一步：調查來源").click().run()
    assert app.session_state.step=="03 分析進度與結果"
    assert next(b for b in app.button if "執行 Q1" in b.label).disabled
    app.selectbox(key="source-"+run.run_id).set_value(next(s.source_id for s in run.sources if s.path=="source.c")).run()
    next(b for b in app.button if b.label=="讀取並核對原文").click().run()
    assert any("int main" in block.value for block in app.code)
    next(b for b in app.button if b.label=="下一步：查核紀錄與補件").click().run()
    app.text_area[0].set_value("TEST_ONLY user statement").run()
    next(b for b in app.button if b.label=="保存補件並建立新 run").click().run()
    assert not app.exception
    assert store.read(app.session_state["selected_run"]).parent_run_id==run.run_id
