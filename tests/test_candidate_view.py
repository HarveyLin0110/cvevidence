from streamlit.testing.v1 import AppTest
from cvevidence.candidate_view import partition_candidates, render_candidates

ROWS = [
    {"cve_id": "CVE-2014-0160", "status": "CANDIDATE_ONLY", "requested": True},
    {"cve_id": "CVE-2022-37434", "status": "CANDIDATE_ONLY", "requested": False,
     "match_basis": [{"version_hint": "FIX_RELEASE_VERSION"}]},
]

def test_selected_scope_not_expanded_by_component_association():
    selected, others = partition_candidates(ROWS, "CVE-2014-0160")
    assert selected == [ROWS[0]] and others == [ROWS[1]]
    assert partition_candidates(ROWS, "") == ([], ROWS)

def test_sidebar_candidate_disclosure_and_fix_version_hint():
    def app(rows):
        import streamlit as st
        from cvevidence.candidate_view import render_candidates
        render_candidates(st, rows, "CVE-2014-0160")
    at = AppTest.from_function(app, args=(ROWS,)).run()
    assert not at.exception
    assert "本次指定 CVE" in [item.value for item in at.subheader]
    assert any("未選入本次分析" in e.label for e in at.expander)
    assert any("修正版本" in e.value for e in at.info)
