"""TEST_ONLY display cases, not real CVE or citation verification."""
from copy import deepcopy
import pytest
from streamlit.testing.v1 import AppTest
from cvevidence.analysis_view import select_analysis


def sample():
    return {"context_hash": "test-context", "analyses": [{
        "cve_id": "CVE-2099-0001", "status": "COMPLETED",
        "assessment": {"context_hash": "test-context", "cve_id": "CVE-2099-0001",
            "assessment_id": "A-test", "verdict": "NEEDS_INVESTIGATION",
            "reason": "TEST_ONLY missing evidence", "conditions": [
                {"title": "TEST_ONLY condition", "state": "UNKNOWN", "explanation": "not established"}]},
        "queries": [{"query_id": "Q1_COMPONENT", "status": "COMPLETED_WITH_GAPS", "missing": ["test header"]}],
        "ai": {"context_hash": "test-context", "cve_id": "CVE-2099-0001",
            "engineering_assessment_id": "A-test", "mode": "LIVE", "status": "TIMED_OUT", "tasks": []}}]}


def app_for(payload, callbacks=False):
    script = '''import streamlit as st
from cvevidence.analysis_view import render_analysis
def report(): st.session_state.destination = "report"
def supplement(): st.session_state.destination = "supplement"
'''
    script += "render_analysis(st, " + repr(payload) + ", context_hash='test-context', cve_id='CVE-2099-0001', key='test'"
    script += ", on_report=report, on_supplement=supplement)" if callbacks else ")"
    return AppTest.from_string(script).run()


def displayed(app):
    return "\n".join(str(item.value) for kind in (app.text, app.info, app.warning, app.error, app.caption, app.code) for item in kind)


def test_rejects_cross_scope_and_ambiguous_cve_before_render():
    for mutate in (
        lambda p: p.update(context_hash="other"),
        lambda p: p["analyses"].append(deepcopy(p["analyses"][0])),
        lambda p: p["analyses"][0]["assessment"].update(cve_id="CVE-2099-0002"),
    ):
        payload = sample(); mutate(payload)
        with pytest.raises(ValueError):
            select_analysis(payload, context_hash="test-context", cve_id="CVE-2099-0001")
        app = app_for(payload)
        assert not app.exception and app.error
        assert "TEST_ONLY missing evidence" not in displayed(app)


def test_ai_timeout_keeps_engineering_and_both_exits():
    payload = sample(); original = deepcopy(payload)
    app = app_for(payload, callbacks=True)
    assert not app.exception
    assert "需要進一步調查" in displayed(app) and "TIMED_OUT" in displayed(app)
    assert len([e for e in app.expander if e.label.startswith("Q")]) == 1
    assert "未提供" in displayed(app)
    app.button[0].click().run()
    assert app.session_state.destination == "report"
    app.button[1].click().run()
    assert app.session_state.destination == "supplement"
    assert payload == original


def test_unknown_cve_has_no_verdict_or_fake_success():
    payload = sample(); payload["analyses"][0] = {"cve_id": "CVE-2099-0001", "status": "UNSUPPORTED_CVE", "assessment": None}
    app = app_for(payload)
    assert not app.exception
    assert "尚未產生工程判定" in displayed(app)
    assert "不受影響（限本次成品與 CVE）" not in displayed(app)
    assert all(button.disabled for button in app.button)


def test_ai_scope_mismatch_not_shown_but_engineering_kept():
    payload = sample()
    payload["analyses"][0]["ai"].update(engineering_assessment_id="another", tasks=[{"question": "PRIVATE_OTHER_RUN"}])
    app = app_for(payload)
    assert not app.exception and app.error
    assert "PRIVATE_OTHER_RUN" not in displayed(app)
    assert "需要進一步調查" in displayed(app)


def test_untrusted_content_only_literal_and_rejected_not_recommended():
    payload = sample(); entry = payload["analyses"][0]
    attack = '<script>alert(1)</script> ![leak](https://example.invalid/private)'
    entry["assessment"]["reason"] = attack
    entry["ai"].update(mode="REPLAY", status="NEEDS_USER_INPUT", tasks=[
        {"question": attack, "reason": "TEST_ONLY", "action": "ASK_USER", "status": "COMPLETED", "required_files": ["same build log"], "result": {"text": attack}},
        {"question": "bad proposal", "status": "REJECTED", "finding": "DO_NOT_SHOW_AS_FINDING", "required_files": ["DO_NOT_RECOMMEND"]}])
    app = app_for(payload)
    assert not app.exception
    assert attack in displayed(app) and "same build log" in displayed(app)
    assert "DO_NOT_RECOMMEND" not in displayed(app) and "DO_NOT_SHOW_AS_FINDING" not in displayed(app)
    assert "本次未呼叫模型" in displayed(app)
    assert not app.markdown

def test_pc_consolidated_text_stays_literal_and_report_agrees():
    from tests.test_result_summary import grouped_entry
    from cvevidence.analysis_report import export_analysis
    payload = sample()
    entry = payload['analyses'][0]
    grouped = grouped_entry('AFFECTED')
    entry['assessment'].update(grouped['assessment'])
    entry['condition_groups'] = grouped['condition_groups']
    marker = '<script>TEST_ONLY</script> ![image](https://example.invalid/private)'
    entry['assessment']['conditions'][-1]['explanation'] = marker
    app = app_for(payload, callbacks=True)
    assert not app.exception and not app.markdown
    assert 'PC3 · path' in displayed(app) and marker in displayed(app)
    assert '受影響判定的支持條件' in displayed(app)
    report = export_analysis(payload, context_hash='test-context', cve_id=entry['cve_id'], run_id='TEST_ONLY')
    assert 'PC 綜合說明' in report and marker in report
