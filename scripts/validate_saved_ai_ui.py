"""Read a saved real AI attempt through Streamlit; never calls a model."""
import argparse, os
from pathlib import Path
from streamlit.testing.v1 import AppTest
from cvevidence.runner import Runner
from cvevidence.storage import RunStore
p=argparse.ArgumentParser()
p.add_argument("--store",required=True)
p.add_argument("--ai-id",required=True)
p.add_argument("--apply-cmake-demo-supplement", action="store_true", help="Only for the delivered CMake06 acceptance case")
args=p.parse_args()
root=Path(__file__).resolve().parents[1]
runner=Runner(RunStore(args.store))
record=runner.read_ai(args.ai_id)
run_id=record["request"]["parent_run_id"]
os.environ["CVEVIDENCE_STORE"]=str(runner.store.root)
app=AppTest.from_file(str(root/"runner_app.py")).run()
app.session_state.selected_run=run_id
app.session_state.step="04 AI 查核與補件"
app.session_state["selected-ai-"+run_id]=args.ai_id
app.run(timeout=40)
assert not app.exception, "AI page failed"
assert any(args.ai_id in t.value for t in app.text), "AI identity absent"
assert any(record["status"] in t.value for t in app.text), "AI status absent"
next(b for b in app.button if b.label=="查看目前報告").click().run(timeout=40)
assert not app.exception, "Report failed"
assert any(args.ai_id in c.value for c in app.code), "Selected AI missing from report"
print("Saved AI page and report verified; no model call made.")
if args.apply_cmake_demo_supplement:
    original = runner.store.read(run_id)
    if original.cve_id != "CVE-2022-37434":
        raise SystemExit("This acceptance option is only for the CMake demo.")
    before = runner.store._run_path(run_id).read_bytes()
    next(b for b in app.button if b.label == "套用已取得的補件並建立新 run").click().run(timeout=40)
    assert not app.exception
    supplemented = runner.store.read(app.session_state.selected_run)
    assert supplemented.parent_run_id == run_id
    next(b for b in app.button if b.label == "執行 Q1–Q5 與正式判定").click().run(timeout=40)
    assert not app.exception
    final = runner.store.read(app.session_state.selected_run)
    verdict = runner.read_engineering(final.run_id)["analyses"][0]["assessment"]["verdict"]
    assert verdict == "AFFECTED"
    assert runner.store._run_path(run_id).read_bytes() == before
    assert runner.read_ai(args.ai_id)["status"] == record["status"]
    print("CMake supplement reanalysis verified:", final.run_id, verdict)
