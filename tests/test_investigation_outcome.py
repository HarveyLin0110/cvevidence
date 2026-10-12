"""Decision presentation, not semantic validation of model observations."""
from copy import deepcopy
import pytest
from cvevidence_core.integrity import digest
from cvevidence_core.investigation_outcome import summarize
from tests.test_condition_plan import conditions


def record(states, status='COMPLETED'):
    rows=conditions()
    for row,state in zip(rows,states):row['state']=state
    return {'context_hash':'TEST_ONLY','cve_id':'CVE-2099-0001','status':status,
        'condition_plan':{'context_hash':'TEST_ONLY','cve_id':'CVE-2099-0001',
            'conditions':rows,'plan_hash':digest(rows)}}


@pytest.mark.parametrize('remaining',['USER_MATERIAL_MISSING','CAPABILITY_GAP','NOT_REVIEWED'])
def test_exclusion_is_reviewed_before_unnecessary_remaining_material(remaining):
    ai=record(['OBSERVED_SUPPORT','OBSERVED_EXCLUSION',remaining]); before=deepcopy(ai)
    result=summarize(ai)
    assert result['status']=='EXCLUSION_OBSERVED'
    assert result['decisive_condition_ids']==['C2']
    assert '全部相關副本' in result['next_step']
    assert result['conditions'][2]['state']==remaining
    assert result['formal_verdict_unchanged'] is True
    assert ai==before


@pytest.mark.parametrize('status',['TIMED_OUT','BUDGET_EXHAUSTED','FAILED','CANCELLED'])
def test_unfinished_investigation_does_not_look_successful_even_with_exclusion(status):
    result=summarize(record(['OBSERVED_SUPPORT','OBSERVED_EXCLUSION','USER_MATERIAL_MISSING'],status))
    assert result['status']=='INCOMPLETE'
    assert not result['decisive_condition_ids']


def test_conflicting_evidence_precedes_exclusion_review():
    result=summarize(record(['CONFLICT','OBSERVED_EXCLUSION','USER_MATERIAL_MISSING']))
    assert result['status']=='CONFLICT' and result['decisive_condition_ids']==['C1']


def test_missing_build_binding_is_not_promoted_by_source_fix_narrative():
    ai=record(['OBSERVED_SUPPORT','USER_MATERIAL_MISSING','USER_MATERIAL_MISSING'])
    ai['condition_plan']['conditions'][1]['explanation']='TEST_ONLY 原碼看似已修補，但尚未連到目標成品。'
    ai['condition_plan']['plan_hash']=digest(ai['condition_plan']['conditions'])
    result=summarize(ai)
    assert result['status']=='NEEDS_MATERIAL' and not result['decisive_condition_ids']


def test_web_and_report_show_exclusion_next_step_without_hiding_pc3_gap():
    from streamlit.testing.v1 import AppTest
    from cvevidence.investigation_view import lines
    ai=record(['OBSERVED_SUPPORT','OBSERVED_EXCLUSION','USER_MATERIAL_MISSING'])
    app=AppTest.from_string('import streamlit as st\n'
        'from cvevidence.investigation_view import render_overview\n'
        'render_overview(st,'+repr(ai)+')').run(timeout=15)
    assert not app.exception
    assert any('排除線索' in x.value for x in app.info)
    assert any('下一步：先覆核排除線索' in x.value for x in app.text)
    assert any('優先覆核條件：C2'==x.value for x in app.caption)
    assert any('使用者材料缺口' in x.value for x in app.caption)
    report='\n'.join(lines(ai))
    assert '下一步：先覆核排除線索' in report and 'C3 · PC3 · 使用者材料缺口' in report
