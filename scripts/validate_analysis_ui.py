"""Read an authorized local saved engineering run and exercise UI/report exits.

This checks presentation only; it does not execute core analysis or prove a CVE.
Run after merging the integration Runner.read_engineering API.
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def validate(store_root, run_id):
    from streamlit.testing.v1 import AppTest
    from cvevidence.runner import Runner
    from cvevidence.storage import RunStore
    from cvevidence.analysis_report import export_analysis

    runner = Runner(RunStore(store_root))
    if not hasattr(runner, "read_engineering"):
        raise ValueError("Merge the formal engineering API before running this check")
    run = runner.store.read(run_id)
    payload = runner.read_engineering(run_id)
    context_hash = run.input_package.context_hash
    script = '''import streamlit as st
from cvevidence.analysis_view import render_analysis
def report(): st.session_state.destination = "report"
def supplement(): st.session_state.destination = "supplement"
'''
    # repr of a JSON payload is a literal, never interpolated as raw source content.
    script += "render_analysis(st, " + repr(payload) + ", context_hash=" + repr(context_hash)
    script += ", cve_id=" + repr(run.cve_id) + ", key='acceptance', on_report=report, on_supplement=supplement)"
    app = AppTest.from_string(script).run(timeout=30)
    if app.exception or app.error:
        raise ValueError("Saved-result renderer failed or rejected the selected result")
    for label, expected in (("查看目前報告", "report"), ("提供補充資料", "supplement")):
        button = next(b for b in app.button if b.label == label)
        if button.disabled: raise ValueError("Required next-step button is disabled")
        button.click().run(timeout=30)
        if app.exception or app.session_state.destination != expected:
            raise ValueError("Next-step navigation did not complete")
    report = export_analysis(payload, context_hash=context_hash, cve_id=run.cve_id, run_id=run_id)
    if run_id not in report or context_hash not in report or run.cve_id not in report:
        raise ValueError("Report lost the selected run scope")
    return {"run_id": run_id, "context_hash": context_hash, "cve_id": run.cve_id,
            "engineering_status": run.engineering_status, "ai_status": run.ai_status,
            "renderer": "PASS", "report_exit": "PASS", "supplement_exit": "PASS",
            "report_utf8_bytes": len(report.encode("utf-8")),
            "scope": "Presentation and navigation only; no new analysis or model call"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--store", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    try:
        result = validate(args.store, args.run_id)
    except (ValueError, OSError, RuntimeError, AttributeError, StopIteration):
        print(json.dumps({"status": "FAIL", "reason": "Saved result or UI check failed; no success claimed"}))
        raise SystemExit(1)
    print(json.dumps(result, ensure_ascii=False, indent=2))
