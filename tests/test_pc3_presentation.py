"""TEST_ONLY PC3 display/scope contracts; no real CVE or runtime verification."""
from copy import deepcopy

import pytest

from cvevidence.analysis_report import compare_analyses, export_analysis
from cvevidence.analysis_view import QUERIES, condition_groups
from tests.test_analysis_view import app_for, displayed, sample


def followup(context="test-context", qid="DQ-receipt", status="WAITING_USER_INPUT"):
    return {"query_id": qid, "origin": "RULE_GAP", "question": "TEST_ONLY 請提供運作收據",
            "reason": "TEST_ONLY PC3 缺少運作觀測", "target_condition_id": "runtime_observation",
            "required_files": ["runtime/observation.json"], "status": status,
            "evidence_ids": [], "context_hash": context}


def pc3_sample():
    payload = sample()
    payload["input"] = {"product_id": "TEST_ONLY", "release_id": "test-release", "build_id": "test-build",
                        "primary_artifact": {"sha256": "a" * 64}}
    entry = payload["analyses"][0]
    shared = ["build_identity", "library_binding", "product_binding", "scope_complete"]
    static = ["vulnerable_implementation", "entry_reachable", "trigger_prerequisites"]
    entry["assessment"]["conditions"] = [
        {"condition_id": cid, "title": "TEST_ONLY " + cid, "state": "SUPPORTED",
         "explanation": "TEST_ONLY 靜態取證", "evidence_ids": ["E-test"]}
        for cid in [*shared, "component", *static]] + [
        {"condition_id": "runtime_observation", "title": "TEST_ONLY 運作觀測", "state": "UNKNOWN",
         "explanation": "TEST_ONLY 尚無原始運作資料", "evidence_ids": []}]
    entry["condition_groups"] = {"schema_version": "2.0", "grouping_only": True, "cve_id": entry["cve_id"],
        "shared_prerequisite_ids": shared, "groups": [
            {"group_id": "PC1", "title": "元件適用性", "condition_ids": ["component"]},
            {"group_id": "PC2", "title": "成品實作與靜態路徑", "condition_ids": static},
            {"group_id": "PC3", "title": "部署與實際運作", "condition_ids": ["runtime_observation"]}]}
    titles = ["元件與 CVE 候選", "建置身分與功能設定", "脆弱實作與修補", "成品綁定與靜態輸入路徑", "實際部署與運作證據"]
    entry["queries"] = [{"query_id": qid, "title": title, "pc_layer": layer, "query_plan_version": "2.0",
                         "status": "COMPLETED", "evidence_ids": []}
                        for qid, title, layer in zip(QUERIES, titles, ["PC1", "PC2", "PC2", "PC2", "PC3"])]
    entry["queries"][-1]["status"] = "COMPLETED_WITH_GAPS"
    entry["runtime_observation"] = {"status": "MISSING", "evidence_basis": "NOT_OBSERVED",
                                    "description": "TEST_ONLY 尚無運作資料", "provenance_verified": False}
    entry["followup_queries"] = [followup()]
    return payload


def report(payload):
    return export_analysis(payload, context_hash="test-context", cve_id="CVE-2099-0001", run_id="TEST_ONLY")


def child_of(parent):
    child = deepcopy(parent)
    child["context_hash"] = "child-context"
    entry = child["analyses"][0]
    entry["assessment"]["context_hash"] = "child-context"
    entry["ai"]["context_hash"] = "child-context"
    for query in entry.get("followup_queries", []):
        query["context_hash"] = "child-context"
    return child


def compare(parent, child, **kwargs):
    return compare_analyses(parent, child, parent_context="test-context", child_context="child-context",
                            cve_id="CVE-2099-0001", **kwargs)


def test_static_pc2_cannot_fill_unknown_pc3_and_new_titles_follow_saved_queries():
    payload = pc3_sample()
    before = deepcopy(payload)
    app = app_for(payload)
    assert not app.exception
    labels = [e.label for e in app.expander]
    entry = payload["analyses"][0]
    assert "PC2 · 成品實作與靜態路徑" in displayed(app) and "PC3 · 部署與實際運作" in displayed(app)
    for query in entry["queries"]:
        assert any(query["query_id"] + " · " + query["title"] in label for label in labels)
        assert query["query_id"] + " · " + query["title"] in report(payload)
    from cvevidence.result_summary import pc_summaries
    pc2 = next(g for g in pc_summaries(entry) if g['group_id']=='PC2')
    pc3 = next(g for g in pc_summaries(entry) if g['group_id']=='PC3')
    assert 'entry_reachable' in pc2['summary'] and 'entry_reachable' not in pc3['summary']
    assert pc2['summary'] in displayed(app) and pc3['summary'] in displayed(app)
    assert "TEST_ONLY 運作觀測（此項條件仍需確認）" in displayed(app)
    assert "缺少實際運作證據（MISSING）" in displayed(app)
    assert "需要進一步調查" in displayed(app)
    assert "RULE_GAP" in displayed(app) and "runtime/observation.json" in displayed(app)
    assert "等待用戶補件" in " ".join(labels)
    assert payload == before


@pytest.mark.parametrize("status", ["MISSING", "AWAITING_EVIDENCE", "VERIFIED", "REJECTED", "NOT_REQUIRED"])
def test_runtime_summary_is_saved_status_not_an_extra_verdict(status):
    payload = pc3_sample()
    entry = payload["analyses"][0]
    entry["runtime_observation"].update(status=status, evidence_basis="CONTROLLED_LOCAL_OBSERVATION")
    before = deepcopy(payload)
    app = app_for(payload)
    exported = report(payload)
    assert not app.exception
    for output in (displayed(app), exported):
        assert "（" + status + "）" in output
        assert "受控環境本機觀測" in output and "不代表實體客戶 FW 認證" in output
        assert "需要進一步調查" in output
    assert "TEST_ONLY 運作觀測（此項條件仍需確認）" in displayed(app)
    assert payload == before


def test_legacy_groups_and_query_labels_are_not_reinterpreted():
    payload = pc3_sample()
    entry = payload["analyses"][0]
    entry.pop("runtime_observation")
    entry.pop("followup_queries")
    entry["assessment"]["conditions"].pop()
    groups = entry["condition_groups"]
    groups["schema_version"] = "1.0"
    groups["groups"][1].update(title="實作與修補", condition_ids=["vulnerable_implementation"])
    groups["groups"][2].update(title="產品輸入路徑", condition_ids=["entry_reachable", "trigger_prerequisites"])
    for query in entry["queries"]:
        for key in ("title", "pc_layer", "query_plan_version"):
            query.pop(key)
    app = app_for(payload)
    assert not app.exception
    labels = [e.label for e in app.expander]
    assert "PC3 · 產品輸入路徑" in displayed(app)
    for qid, title in QUERIES.items():
        assert any(qid + " · " + title in label for label in labels)
        assert qid + " · " + title in report(payload)
    for output in (displayed(app), report(payload)):
        assert "PC3 運作證據狀態" not in output
        assert "PC2：成品實作與靜態輸入路徑" not in output


def test_query_metadata_title_and_untrusted_content_remain_literal():
    payload = pc3_sample()
    query = payload["analyses"][0]["queries"][-1]
    query.pop("title")
    query["metadata"] = {"title": "TEST_ONLY 自訂運作查核"}
    marker = '<script>alert(1)</script> ![leak](https://example.invalid/private)'
    payload["analyses"][0]["followup_queries"][0]["question"] = marker
    app = app_for(payload)
    assert not app.exception and not app.markdown
    assert marker in displayed(app) and marker in report(payload)
    assert any("Q5_PATH · TEST_ONLY 自訂運作查核" in e.label for e in app.expander)
    assert "Q5_PATH · TEST_ONLY 自訂運作查核" in report(payload)


@pytest.mark.parametrize("mutation", ["foreign", "duplicate", "missing_context", "malformed_files", "unknown_status"])
def test_bad_followup_scope_or_identity_hides_contents_but_keeps_engineering(mutation):
    payload = pc3_sample()
    queries = payload["analyses"][0]["followup_queries"]
    queries[0].update(question="PRIVATE_OTHER_SNAPSHOT", reason="PRIVATE_REASON")
    if mutation == "foreign": queries[0]["context_hash"] = "another"
    if mutation == "duplicate": queries.append(deepcopy(queries[0]))
    if mutation == "missing_context": queries[0].pop("context_hash")
    if mutation == "malformed_files": queries[0]["required_files"] = "not-a-list"
    if mutation == "unknown_status": queries[0]["status"] = "COMPLETED"
    app = app_for(payload)
    assert not app.exception and app.error
    exported = report(payload)
    for output in (displayed(app), exported):
        assert "PRIVATE_OTHER_SNAPSHOT" not in output and "PRIVATE_REASON" not in output
        assert "需要進一步調查" in output
    assert "FOLLOWUP_SCOPE_MISMATCH" in exported


def test_rejected_evidence_keeps_correction_request_visible():
    payload = pc3_sample()
    payload["analyses"][0]["followup_queries"][0].update(status="REJECTED", required_files=["runtime/corrected.log"])
    app = app_for(payload)
    assert not app.exception
    for output in (displayed(app), report(payload)):
        assert "runtime/corrected.log" in output
        assert "此證據未通過驗證" in output

def test_received_material_does_not_claim_completed_content_verification():
    payload=pc3_sample()
    payload['analyses'][0]['followup_queries'][0]['status']='WAITING_VERIFICATION'
    app=app_for(payload)
    assert not app.exception and not app.error
    assert any('材料已收到，等待交叉驗證' in e.label for e in app.expander)
    assert 'WAITING_VERIFICATION' in report(payload)


def test_model_ask_user_waits_while_tool_completion_is_not_condition_verification():
    payload = pc3_sample()
    payload["analyses"][0]["ai"].update(mode="REPLAY", status="NEEDS_USER_INPUT", tasks=[
        {"task_id": "I-ask", "question": "TEST_ONLY ask", "action": "ASK_USER", "status": "COMPLETED",
         "required_files": ["test-same-build-log"], "result": {}},
        {"task_id": "I-list", "question": "TEST_ONLY list", "action": "LIST", "status": "COMPLETED"},
        {"task_id": "I-read", "question": "TEST_ONLY read", "action": "READ", "status": "COMPLETED"}])
    app = app_for(payload)
    assert not app.exception
    labels = [e.label for e in app.expander]
    assert "追加 Query · MODEL · I-ask" in labels
    for output in (displayed(app), report(payload)):
        assert "WAITING_USER_INPUT；補件要求已提出" in output
        assert "調查動作已完成（不代表 CVE 條件成立）" in output
        assert "test-same-build-log" in output
        assert "TEST_ONLY 尚無原始運作資料" in output


def test_optional_comparison_tracks_query_resolution_and_additions_without_mutation():
    parent = pc3_sample()
    child = child_of(parent)
    queries = child["analyses"][0]["followup_queries"]
    queries[0].update(status="VERIFIED", evidence_ids=["E-receipt"])
    queries.append(followup("child-context", "DQ-capture"))
    saved = deepcopy((parent, child))
    legacy = compare(parent, child)
    assert "followup_query_changes" not in legacy
    delta = compare(parent, child, include_followup_queries=True)
    assert {k: v for k, v in delta.items() if k != "followup_query_changes"} == legacy
    changes = {q["query_id"]: q for q in delta["followup_query_changes"]}
    assert changes["DQ-receipt"]["before_status"] == "WAITING_USER_INPUT"
    assert changes["DQ-receipt"]["after_status"] == "VERIFIED"
    assert changes["DQ-capture"]["change"] == "ADDED"
    assert changes["DQ-capture"]["before"] is None
    assert delta["condition_changes"] == []
    assert delta["before_verdict"] == delta["after_verdict"] == "NEEDS_INVESTIGATION"
    assert (parent, child) == saved


def test_optional_comparison_ignores_context_only_changes_and_handles_old_runs():
    parent = pc3_sample()
    child = child_of(parent)
    assert compare(parent, child, include_followup_queries=True)["followup_query_changes"] == []
    parent["analyses"][0].pop("followup_queries")
    delta = compare(parent, child, include_followup_queries=True)
    assert delta["followup_query_changes"][0]["change"] == "ADDED"
    child["analyses"][0].pop("followup_queries")
    assert compare(parent, child, include_followup_queries=True)["followup_query_changes"] == []


@pytest.mark.parametrize("mismatch", ["query_scope", "duplicate", "build", "cve"])
def test_optional_comparison_rejects_scope_mismatch_and_ambiguous_queries(mismatch):
    parent = pc3_sample()
    child = child_of(parent)
    entry = child["analyses"][0]
    if mismatch == "query_scope": entry["followup_queries"][0]["context_hash"] = "wrong"
    if mismatch == "duplicate": entry["followup_queries"].append(deepcopy(entry["followup_queries"][0]))
    if mismatch == "build": child["input"]["build_id"] = "wrong"
    if mismatch == "cve": entry["cve_id"] = "CVE-2099-0002"
    with pytest.raises(ValueError):
        compare(parent, child, include_followup_queries=True)
