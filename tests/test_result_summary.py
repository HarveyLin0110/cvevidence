from copy import deepcopy
from cvevidence.result_summary import conclusion, query_summaries

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
    assert len(rows)==5 and rows[0]["findings"]==["TEST_ONLY found component"]
    assert all(not row["findings"] and row["state"]=="未提供可用結果" for row in rows[1:])
    entry["queries"].append(deepcopy(entry["queries"][0]))
    assert query_summaries(entry)[0]["state"]=="結果重複，需覆核"
    assert not query_summaries(entry)[0]["findings"]

def test_missing_and_conflict_are_not_hidden_by_completed_status():
    entry={"queries":[{"query_id":"Q1_COMPONENT","status":"COMPLETED","missing":["TEST_ONLY header"],
                      "conflicts":["TEST_ONLY conflicting build"]}]}
    row=query_summaries(entry)[0]
    assert row["state"]=="存在矛盾，需覆核"
    assert row["missing"] and row["conflicts"]
