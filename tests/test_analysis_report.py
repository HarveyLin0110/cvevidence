"""TEST_ONLY report behaviour, not a real supplement validation."""
from copy import deepcopy
import pytest
from cvevidence.analysis_report import export_analysis, compare_analyses
from tests.test_analysis_view import sample


def pair():
    parent = sample()
    parent["input"] = {"product_id": "TEST_ONLY", "release_id": "test-release", "build_id": "test-build",
                       "primary_artifact": {"sha256": "a" * 64}}
    parent["analyses"][0]["assessment"]["conditions"][0]["condition_id"] = "test-condition"
    child = deepcopy(parent)
    child["context_hash"] = "child-context"
    child["analyses"][0]["assessment"]["context_hash"] = "child-context"
    return parent, child


def compare(parent, child):
    return compare_analyses(parent, child, parent_context="test-context", child_context="child-context", cve_id="CVE-2099-0001")


def test_report_timeout_keeps_result_and_rejects_wrong_ai_scope():
    payload = sample()
    report = export_analysis(payload, context_hash="test-context", cve_id="CVE-2099-0001", run_id="TEST_ONLY")
    assert "需要進一步調查" in report and "TIMED_OUT" in report
    assert "Q1_COMPONENT" in report
    assert all(q not in report for q in ("Q2_BUILD", "Q3_IMPLEMENTATION", "Q4_BINDING", "Q5_PATH"))
    payload["analyses"][0]["ai"].update(context_hash="another", tasks=[{"question": "PRIVATE"}])
    report = export_analysis(payload, context_hash="test-context", cve_id="CVE-2099-0001", run_id="TEST_ONLY")
    assert "AI_SCOPE_MISMATCH" in report and "PRIVATE" not in report


def test_report_rejected_proposal_cannot_appear_as_recommendation():
    payload = sample()
    payload["analyses"][0]["ai"]["tasks"] = [{"question": "test", "status": "REJECTED", "required_files": ["DO_NOT_RECOMMEND"]}]
    assert "DO_NOT_RECOMMEND" not in export_analysis(payload, context_hash="test-context", cve_id="CVE-2099-0001", run_id="TEST_ONLY")


def test_compare_preserves_inputs_and_reports_evidence_change_without_verdict_change():
    parent, child = pair()
    child["analyses"][0]["assessment"]["conditions"][0]["evidence_ids"] = ["E-test-new"]
    saved = deepcopy((parent, child))
    delta = compare(parent, child)
    assert delta["before_verdict"] == delta["after_verdict"] == "NEEDS_INVESTIGATION"
    assert len(delta["condition_changes"]) == 1
    assert (parent, child) == saved


@pytest.mark.parametrize("field", ["product_id", "release_id", "build_id", "primary_artifact"])
def test_compare_refuses_other_or_missing_build(field):
    parent, child = pair()
    child["input"][field] = {"sha256": "b" * 64} if field == "primary_artifact" else "different"
    with pytest.raises(ValueError): compare(parent, child)
    child["input"].pop(field)
    with pytest.raises(ValueError): compare(parent, child)


def test_compare_does_not_silently_collapse_duplicate_conditions():
    parent, child = pair()
    conditions = child["analyses"][0]["assessment"]["conditions"]
    conditions.append(deepcopy(conditions[0]))
    with pytest.raises(ValueError): compare(parent, child)
