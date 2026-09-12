"""Real archive outputs, with explicitly adversarial copies for scope checks.

Known display omissions intentionally FAIL so the owner has a regression case.
RecordingStreamlit is an interface recorder, not real browser end-to-end testing.
"""
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/qa_contract'))
from probe import RecordingStreamlit, consumers


@pytest.fixture(scope='session')
def data():
    value = os.environ.get('QA_CONTRACT_INPUT')
    if not value:
        pytest.skip('Use scripts/qa_contract/acceptance.py with captured real outputs')
    folder = Path(value)
    view, report, _ = consumers(folder / 'objects')
    return folder, json.loads((folder / 'engineering.json').read_text()), view, report


def display(view, payload, cve='CVE-2014-0160', context=None):
    st = RecordingStreamlit()
    view.render_analysis(st, payload, context_hash=context or payload['context_hash'], cve_id=cve, key='qa-' + cve)
    return st


def exported(report, payload, cve='CVE-2014-0160'):
    return report.export_analysis(payload, context_hash=payload['context_hash'], cve_id=cve, run_id='QA_ONLY')


@pytest.mark.parametrize('index', [0, 1, 2])
def test_real_multi_cve_selection_and_immutable_render(data, index):
    _, payload, view, report = data
    before = deepcopy(payload)
    entry = payload['analyses'][index]
    assert view.select_analysis(payload, context_hash=payload['context_hash'], cve_id=entry['cve_id']) == entry
    st = display(view, payload, entry['cve_id'])
    result = exported(report, payload, entry['cve_id'])
    assert not [c for c in st.calls if c['method'] == 'error']
    assert 'AI_SCOPE_MISMATCH' not in result
    assert payload == before
    if entry['assessment']:
        assert view.VERDICTS[entry['assessment']['verdict']] in st.displayed()
        for query in entry['queries']:
            assert query['query_id'] in st.displayed() and query['status'] in result
    else:
        assert 'UNSUPPORTED_CVE' in result
        assert all(title not in st.displayed() for title in view.VERDICTS.values())


@pytest.mark.parametrize('index', [0, 1])
def test_real_ai_binding_and_query_evidence_references(data, index):
    _, payload, _, _ = data
    entry = payload['analyses'][index]
    ai, assessment = entry['ai'], entry['assessment']
    assert ai['context_hash'] == assessment['context_hash'] == payload['context_hash']
    assert ai['cve_id'] == assessment['cve_id'] == entry['cve_id']
    assert ai['engineering_assessment_id'] == assessment['assessment_id']
    assert ai['status'] == ai['mode'] == 'OFFLINE' and not ai['calls']
    ids = {e['evidence_id'] for e in entry['evidence']}
    for item in entry['queries'] + assessment['conditions']:
        assert set(item['evidence_ids']) <= ids
    sources = {s['source_id']: s for s in payload['input']['sources']}
    for evidence in entry['evidence']:
        for witness in evidence['witnesses']:
            assert all(witness[k] == sources[witness['source_id']][k] for k in ['path', 'sha256', 'size'])
        for excerpt in evidence['excerpts']:
            assert excerpt['context_hash'] == payload['context_hash']
            assert excerpt['file_sha256'] == sources[excerpt['source_id']]['sha256']
            assert excerpt['start_line'] <= excerpt['end_line'] and excerpt['text']


@pytest.mark.parametrize('mutation', ['context', 'duplicate_cve', 'assessment_cve'])
def test_scope_rejected_before_engineering_content(data, mutation):
    _, original, view, report = data
    payload = deepcopy(original)
    context = payload['context_hash']
    if mutation == 'context':
        context = 'other-context'
    elif mutation == 'duplicate_cve':
        payload['analyses'].append(deepcopy(payload['analyses'][0]))
    else:
        payload['analyses'][0]['assessment']['cve_id'] = 'CVE-2022-37434'
    st = display(view, payload, context=context)
    assert [c for c in st.calls if c['method'] == 'error']
    assert original['analyses'][0]['assessment']['reason'] not in st.displayed()
    with pytest.raises(ValueError):
        report.export_analysis(payload, context_hash=context, cve_id='CVE-2014-0160', run_id='QA_ONLY')


@pytest.mark.parametrize('field', ['context_hash', 'cve_id', 'engineering_assessment_id'])
def test_wrong_ai_identity_hidden_engineering_retained(data, field):
    _, original, view, report = data
    payload = deepcopy(original)
    payload['analyses'][0]['ai'][field] = 'ADVERSARIAL_OTHER_SCOPE'
    st = display(view, payload)
    text = exported(report, payload)
    assert [c for c in st.calls if c['method'] == 'error']
    assert 'ADVERSARIAL_OTHER_SCOPE' not in st.displayed()
    assert 'AI_SCOPE_MISMATCH' in text
    assert original['analyses'][0]['assessment']['reason'] in st.displayed()


def test_real_other_cve_ai_is_not_reused(data):
    _, original, view, report = data
    payload = deepcopy(original)
    payload['analyses'][0]['ai'] = deepcopy(payload['analyses'][1]['ai'])
    assert [c for c in display(view, payload).calls if c['method'] == 'error']
    assert 'AI_SCOPE_MISMATCH' in exported(report, payload)


def b_engineering(folder):
    parent = json.loads((folder / 'b/engineering-before-supplement.json').read_text())
    child = json.loads((folder / 'b/engineering-saved.json').read_text())
    return parent, child


def test_real_supplement_comparison_and_separate_identities(data):
    folder, _, view, report = data
    parent, child = b_engineering(folder)
    original = deepcopy((parent, child))
    assert parent['context_hash'] != child['context_hash']
    assert parent['analyses'][0]['assessment']['assessment_id'] != child['analyses'][0]['assessment']['assessment_id']
    result = report.compare_analyses(parent, child, parent_context=parent['context_hash'],
        child_context=child['context_hash'], cve_id='CVE-2014-0160')
    assert result['before_verdict'] == 'NEEDS_INVESTIGATION'
    assert result['after_verdict'] == 'NOT_AFFECTED' and result['condition_changes']
    for payload in (parent, child):
        assert not [c for c in display(view, payload).calls if c['method'] == 'error']
    assert (parent, child) == original


def test_old_ai_not_attached_to_supplemented_context(data):
    folder, _, view, report = data
    parent, child = b_engineering(folder)
    child['analyses'][0]['ai'] = parent['analyses'][0]['ai']
    st = display(view, child)
    assert [c for c in st.calls if c['method'] == 'error']
    assert view.VERDICTS['NOT_AFFECTED'] in st.displayed()
    assert 'AI_SCOPE_MISMATCH' in exported(report, child)


@pytest.mark.parametrize('consumer', ['renderer', 'report'])
def test_real_excerpt_locator_is_available_to_reviewer(data, consumer):
    _, payload, view, report = data
    excerpt = next(x for e in payload['analyses'][0]['evidence'] for x in e['excerpts'])
    text = display(view, payload).displayed() if consumer == 'renderer' else exported(report, payload)
    assert excerpt['excerpt_id'] in text, f'{consumer} drops real evidence.excerpts X-ID and line locator'
    assert excerpt['text'] in text
