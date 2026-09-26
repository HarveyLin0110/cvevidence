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


def test_discovered_cves_have_independent_request_branches():
    from cvevidence.request_ui import request_branches
    root = run('discovery', cve=None)
    first = run('first', 'discovery', created='2')
    second = run('second', 'discovery', cve='CVE-2099-0002', created='3')
    retry = run('retry', 'discovery', created='4')
    supplement = run('supplement', 'first', created='5')
    unrelated = run('other-request', created='9')
    rows, histories = request_branches([root], [root, first, second, retry, supplement, unrelated])
    assert set(rows) == {'discovery', 'first', 'second'}
    assert [r.run_id for r in histories['discovery']] == ['discovery']
    assert [r.run_id for r in histories['first']] == ['supplement', 'retry', 'first']
    assert [r.run_id for r in histories['second']] == ['second']


def test_reload_request_opens_latest_first_cve_without_hiding_failure():
    from cvevidence.request_ui import open_request
    root = run('root', error=None, engineering_payload_sha256=None)
    analyzed = run('analysis', 'root', created='2', error=None, engineering_payload_sha256='hash')
    failed = run('failed', 'analysis', created='3', error='failure', engineering_payload_sha256=None)
    other = run('other-cve', cve='CVE-2099-0002', created='9', error=None, engineering_payload_sha256='other')
    result = Row(spec=Row(request_id='request'), runs=[root, other])
    st = Row(session_state=Row())
    open_request(st, result, [root, analyzed, other])
    assert (st.session_state.selected_request, st.session_state.selected_run, st.session_state.step) == ('request', 'analysis', PAGES[2])
    open_request(st, result, [root, analyzed, failed, other])
    assert (st.session_state.selected_run, st.session_state.step) == ('failed', PAGES[4])


def test_reload_draft_clears_previous_run():
    from cvevidence.request_ui import open_request
    st = Row(session_state=Row(selected_run='previous', step=PAGES[4]))
    open_request(st, Row(spec=Row(request_id='draft'), runs=[]), [])
    assert st.session_state.selected_request == 'draft'
    assert st.session_state.selected_run is None
    assert st.session_state.step == PAGES[0]
