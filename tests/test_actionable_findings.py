"""Real saved evidence presentation and collection-contract drift checks."""
from copy import deepcopy
import json
from unittest.mock import patch

import pytest
from streamlit.testing.v1 import AppTest

from cvevidence.analysis_report import export_analysis
from cvevidence.analysis_view import saved_collection_guide
from cvevidence.result_summary import condition_finding, pc_summaries
from cvevidence_core.ai import investigate
from cvevidence_core.collection_guidance import collection_guide
from cvevidence_core.integrity import digest
from cvevidence_core.queries import collect_evidence
from cvevidence_core.verifier import verify
from tests.test_ai_reliability import CONFIG, arguments, response
from tests.test_runtime_layers import CASES, real_cases


@pytest.mark.parametrize('family', CASES)
def test_collection_checklist_matches_actual_accepted_runtime_files(real_cases, family):
    context, complete, before, after = real_cases[family]
    entry = before['analyses'][0]
    verified = verify(context, collect_evidence(context, CASES[family]))
    guide = collection_guide(context, verified, entry['assessment'])
    actual_added = {r['path'] for r in complete.sources.values()} - {r['path'] for r in context.sources.values()}
    assert {r['path'] for r in guide['items']} == actual_added
    assert all(not r['present'] and r['how'] and r['purpose'] for r in guide['items'])
    assert guide['origin'] == 'CORE_PARSER_CONTRACT'
    assert guide['context_hash'] == context.context_hash
    assert guide['details']['scope']['primary_artifact'] == context.manifest['primary_artifact']
    assert '故障日誌' in guide['details']['collection_note']
    verified_after = verify(complete, collect_evidence(complete, CASES[family]))
    assert collection_guide(complete, verified_after, after['analyses'][0]['assessment']) is None
    original = deepcopy(context.manifest)
    guide['details']['scope']['primary_artifact']['sha256'] = '0' * 64
    assert context.manifest == original


@pytest.mark.parametrize('family', CASES)
def test_real_pc_cards_show_component_and_bound_source_locations(real_cases, family):
    _, _, _, payload = real_cases[family]
    entry = payload['analyses'][0]
    saved = deepcopy(entry)
    groups = {g['group_id']: g for g in pc_summaries(entry)}
    component = next(e['value'] for e in entry['evidence'] if e['fact_key'] == 'component')
    assert component['name'] in groups['PC1']['findings'][0]['headline']
    assert component['version'] in groups['PC1']['findings'][0]['headline']
    assert groups['PC1']['findings'][0]['locations']
    assert any(loc['excerpt'] for f in groups['PC2']['findings'] for loc in f['locations'])
    runtime = groups['PC3']['findings'][0]
    assert runtime['state'] == 'SUPPORTED' and any(loc['excerpt'] for loc in runtime['locations'])
    assert all(loc['path'].startswith(('runtime/', 'product/', 'sdk/', 'install/')) for loc in runtime['locations'])
    report = export_analysis(payload, context_hash=payload['context_hash'], cve_id=CASES[family], run_id='TEST_REAL_SAVED')
    assert component['version'] in report
    for group in ('PC1', 'PC2', 'PC3'):
        assert groups[group]['findings'][0]['locations'][0]['label'] in report
    assert entry == saved


def test_cmake_findings_are_specific_and_unknown_never_becomes_runtime_hit(real_cases):
    _, _, before, after = real_cases['cmake']
    groups = {g['group_id']: g for g in pc_summaries(after['analyses'][0])}
    assert 'zlib 1.2.12' in groups['PC1']['findings'][0]['headline']
    assert any('inflate.c' in loc['label'] and '第 ' in loc['label'] for loc in groups['PC2']['findings'][0]['locations'])
    assert 'inflateGetHeader' in groups['PC2']['findings'][1]['headline']
    assert '32 bytes' in groups['PC2']['findings'][2]['headline']
    old = next(g for g in pc_summaries(before['analyses'][0]) if g['group_id'] == 'PC3')['findings'][0]
    assert old['state'] == 'UNKNOWN' and '尚未確認' in old['headline']
    assert any('runtime/observation.json' in m for m in old['missing'])
    assert not old['locations']


@pytest.mark.parametrize('mutation', ('context', 'hash', 'duplicate_evidence', 'negative_line'))
def test_inconsistent_locations_are_not_presented_as_matching_lines(real_cases, mutation):
    entry = deepcopy(real_cases['cmake'][3]['analyses'][0])
    condition = next(c for c in entry['assessment']['conditions'] if c['condition_id'] == 'vulnerable_implementation')
    record = next(e for e in entry['evidence'] if e['evidence_id'] == condition['evidence_ids'][0])
    if mutation == 'context': record['excerpts'][0]['context_hash'] = 'wrong-scope'
    elif mutation == 'hash': record['excerpts'][0]['file_sha256'] = '0' * 64
    elif mutation == 'negative_line': record['excerpts'][0]['start_line'] = -1
    else: entry['evidence'].append(deepcopy(record))
    finding = condition_finding(entry, condition)
    assert not any(loc['excerpt'] for loc in finding['locations'])


def test_simulated_ai_gets_parser_guide_without_promoting_it_to_evidence(real_cases):
    context, _, before, _ = real_cases['cmake']
    assessment = before['analyses'][0]['assessment']
    verified = verify(context, collect_evidence(context, CASES['cmake']))
    seen = []
    def transport(config, items, timeout):
        seen.append(json.loads(items[0]['content']))
        return response(arguments('ASK_USER', required_files=['runtime/observation.json']))
    old = digest(assessment)
    with patch('cvevidence_core.ai.settings', return_value=CONFIG):
        ai = investigate(context, verified, assessment, mode='LIVE', transport=transport, max_calls=1)
    guide = ai['tasks'][0]['result']['collection_guide']
    assert guide == seen[0]['collection_guide']
    assert any(i['path'] == 'runtime/normal.gz' for i in guide['items'])
    assert ai['mode'] == 'SIMULATED' and ai['status'] == 'NEEDS_USER_INPUT'
    assert not ai['verified_ai_facts'] and digest(assessment) == old
    selection = dict(context_hash=context.context_hash, cve_id=CASES['cmake'], assessment_id=assessment['assessment_id'])
    assert saved_collection_guide(ai, **selection) == guide
    invalid = deepcopy(ai); invalid['tasks'][0]['result']['collection_guide']['context_hash'] = 'foreign'
    assert saved_collection_guide(invalid, **selection) is None
    invalid = deepcopy(ai); invalid['tasks'][0]['status'] = 'REJECTED'
    assert saved_collection_guide(invalid, **selection) is None
    script = 'import streamlit as st\nfrom cvevidence.analysis_view import render_ai\nrender_ai(st,' + repr(ai) + ',**' + repr(selection) + ')'
    app = AppTest.from_string(script).run(timeout=30)
    assert not app.exception
    visible = '\n'.join(e.value for e in app.text)
    assert '該次正常匯入使用的 gzip 原檔' in visible and '取得方式：' in visible
    details = next(e for e in app.expander if e.label == '詳細格式、成品範圍與驗收方式')
    assert details.proto.expanded is False
    payload = deepcopy(before); payload['analyses'][0]['ai'] = ai
    report = export_analysis(payload, context_hash=context.context_hash, cve_id=CASES['cmake'], run_id='SIMULATED_ONLY')
    assert 'runtime/normal.gz' in report and '取得方式：' in report
