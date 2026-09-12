"""Synthetic lineage regressions; real demo workflow is separately recorded."""
from types import SimpleNamespace as Row
from cvevidence.request_ui import request_lineage, open_run
from cvevidence.workflow_navigation import PAGES

def run(id, parent=None, cve='CVE-2099-0001', created='1', **kwargs):
    return Row(run_id=id, parent_run_id=parent, cve_id=cve, created_at=created, **kwargs)

def test_latest_request_result_follows_parents_and_preserves_failures():
    root = run('root')
    analyzed = run('analysis', 'root', created='2')
    failed = run('failed-supplement', 'analysis', created='3')
    unrelated = run('same-cve-other-request', created='9')
    foreign = run('foreign-cve', 'root', cve='CVE-2099-0002', created='8')
    cycle = run('cycle', 'cycle', created='7')
    assert [r.run_id for r in request_lineage(root, [root, analyzed, failed, unrelated, foreign, cycle])] == ['failed-supplement', 'analysis', 'root']
    # A missing parent is not permission to attach an orphan by CVE.
    assert request_lineage(root, [failed, unrelated]) == []

def test_switch_destination_uses_selected_run_state():
    st = Row(session_state=Row())
    for error, payload, page in [(None, 'hash', PAGES[2]), (None, None, PAGES[1]), ('failure', None, PAGES[4])]:
        selected = run('selected', error=error, engineering_payload_sha256=payload)
        open_run(st, selected)
        assert st.session_state.selected_run == 'selected'
        assert st.session_state.step == page
