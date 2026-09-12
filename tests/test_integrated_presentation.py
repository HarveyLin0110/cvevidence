"""Display contract checks, not CVE verification."""
from copy import deepcopy
from cvevidence.analysis_view import condition_groups
from cvevidence.analysis_report import export_analysis
from tests.test_analysis_view import sample, app_for, displayed


def test_groups_preserve_unknown_and_reject_foreign_or_missing_conditions():
    payload = sample()
    entry = payload['analyses'][0]
    entry['assessment']['conditions'][0]['condition_id'] = 'test-condition'
    entry['condition_groups'] = {'cve_id': entry['cve_id'], 'grouping_only': True,
        'shared_prerequisite_ids': ['test-condition'],
        'groups': [{'group_id': 'PC1', 'title': 'TEST_ONLY', 'condition_ids': ['test-condition']}]}
    before = deepcopy(payload)
    app = app_for(payload)
    assert not app.exception and '尚待確認' in displayed(app)
    assert condition_groups(entry)[1]['conditions'][0]['state'] == 'UNKNOWN'
    assert payload == before
    entry['condition_groups']['cve_id'] = 'CVE-2099-0002'
    assert condition_groups(entry) == []
    entry['condition_groups']['cve_id'] = entry['cve_id']
    entry['condition_groups']['groups'][0]['condition_ids'] = ['not-in-result']
    assert condition_groups(entry) == []


def test_excerpts_display_and_export_literal_text_with_locator():
    payload = sample()
    entry = payload['analyses'][0]
    marker = '<script>alert(1)</script> ![image](https://example.invalid/secret)'
    entry['evidence'] = [{'evidence_id': 'E-test', 'reason': 'TEST_ONLY', 'witnesses': [],
        'excerpts': [{'excerpt_id': 'X-test', 'source_id': 'S-test', 'start_line': 4,
            'end_line': 5, 'file_sha256': 'a'*64, 'text': marker}]}]
    entry['queries'][0]['evidence_ids'] = ['E-test']
    app = app_for(payload)
    assert not app.exception and marker in displayed(app) and '行 4–5' in displayed(app)
    assert not app.markdown
    report = export_analysis(payload, context_hash='test-context', cve_id=entry['cve_id'], run_id='TEST_ONLY')
    assert marker in report and 'X-test' in report and 'file_sha256' in report
