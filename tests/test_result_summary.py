from copy import deepcopy
from cvevidence.result_summary import conclusion, query_summaries

def grouped_entry(verdict):
    return {"cve_id": "CVE-2099-0001", "assessment": {"verdict": verdict, "conditions": [
        {"condition_id": cid, "state": "SUPPORTED", "title": cid, "explanation": "TEST_ONLY " + cid}
        for cid in ("build", "component", "implementation", "path", "trigger")
    ]}, "condition_groups": {"cve_id": "CVE-2099-0001", "grouping_only": True,
        "shared_prerequisite_ids": ["build"], "groups": [
            {"group_id": "PC1", "title": "component", "condition_ids": ["component"]},
            {"group_id": "PC2", "title": "implementation", "condition_ids": ["implementation"]},
            {"group_id": "PC3", "title": "path", "condition_ids": ["path", "trigger"]}]}}

def test_pc_summary_combines_conditions_without_promoting_neutral_evidence():
    from cvevidence.result_summary import pc_summaries
    for verdict in ("AFFECTED", "NOT_AFFECTED", "NEEDS_INVESTIGATION", None):
        entry = grouped_entry(verdict)
        before = deepcopy(entry)
        groups = pc_summaries(entry)
        assert groups[0]["tone"] == "neutral"
        assert all((g["tone"] == "affected") == (verdict == "AFFECTED") for g in groups[1:])
        assert "TEST_ONLY path" in groups[3]["summary"] and "TEST_ONLY trigger" in groups[3]["summary"]
        assert entry == before
    entry = grouped_entry("AFFECTED")
    entry["assessment"]["conditions"][-1]["state"] = "UNKNOWN"
    assert pc_summaries(entry)[3]["tone"] == "pending"

def test_pc_mapping_rejects_overlap_and_omitted_conditions():
    from cvevidence.result_summary import pc_summaries
    entry = grouped_entry("AFFECTED")
    entry["condition_groups"]["groups"][0]["condition_ids"].append("build")
    assert pc_summaries(entry) == []
    entry = grouped_entry("AFFECTED")
    entry["condition_groups"]["groups"][-1]["condition_ids"].remove("trigger")
    assert pc_summaries(entry) == []

def test_summary_never_infers_verdict_from_conditions():
    entry={"assessment":{"verdict":"NEEDS_INVESTIGATION","reason":"TEST_ONLY uncertain",
        "conditions":[{"title":"TEST_ONLY blocked","state":"BLOCKED"}]}}
    before=deepcopy(entry)
    assert "還不能確認" in conclusion(entry)["text"]
    assert entry==before
    entry["assessment"]["verdict"]=None
    assert "尚未提供有效判定" in conclusion(entry)["text"]

def test_each_query_has_findings_or_explicit_unknown_without_cross_query_leak():
    entry={"queries":[{"query_id":"Q1_COMPONENT","status":"COMPLETED","evidence_ids":["E-test"]}],
           "evidence":[{"evidence_id":"E-test","reason":"TEST_ONLY found component"}]}
    rows=query_summaries(entry)
    assert len(rows)==1 and rows[0]["findings"]==["TEST_ONLY found component"]
    assert query_summaries({}) == []
    entry["queries"].append(deepcopy(entry["queries"][0]))
    assert query_summaries(entry)[0]["state"]=="結果重複，需覆核"
    assert not query_summaries(entry)[0]["findings"]

def test_missing_and_conflict_are_not_hidden_by_completed_status():
    entry={"queries":[{"query_id":"Q1_COMPONENT","status":"COMPLETED","missing":["TEST_ONLY header"],
                      "conflicts":["TEST_ONLY conflicting build"]}]}
    row=query_summaries(entry)[0]
    assert row["state"]=="存在矛盾，需覆核"
    assert row["missing"] and row["conflicts"]

def test_runtime_v2_summary_uses_saved_query_semantics():
    entry={"queries":[{"query_id":"Q5_PATH","title":"實際部署與運作證據",
                       "pc_layer":"PC3","query_plan_version":"2.0"}]}
    assert query_summaries(entry)[0]["label"]=="實際部署與運作證據"
    assert query_summaries({})==[]

def test_dimensions_do_not_invent_reproduction_from_positive_engineering():
    from cvevidence.result_summary import conclusion_dimensions, condition_interpretation
    for verdict in ("AFFECTED", "NOT_AFFECTED", "NEEDS_INVESTIGATION", None):
        entry={"assessment":{"verdict":verdict},"ai":{"finding":"TEST_ONLY vulnerability reproduced"}}
        before=deepcopy(entry)
        dimensions=conclusion_dimensions(entry)
        assert "尚無獨立覆核" in dimensions[1]["本次結論"]
        assert "尚無獨立覆核" in dimensions[2]["本次結論"]
        assert entry==before
    status, boundary=condition_interpretation({"condition_id":"trigger_prerequisites","state":"SUPPORTED"})
    assert status=="支持此項工程條件" and "不代表已實際觸發" in boundary
    assert condition_interpretation({"state":"UNKNOWN"})[0]=="此項條件仍需確認"
