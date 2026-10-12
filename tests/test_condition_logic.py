"""Branch absence is not an exclusion of every CVE path. TEST_ONLY proposals."""
from copy import deepcopy
import pytest
from cvevidence_core.condition_plan import validate
from cvevidence_core.evidence_requests import validate as requests,require_actionable_completion
from cvevidence_core.integrity import digest
from cvevidence_core.investigation_outcome import summarize
from tests.test_condition_plan import conditions,PUBLIC
from tests.test_evidence_requests import request
from tests.test_investigation_outcome import record


def set_logic(ai,roles):
    for row,role in zip(ai['condition_plan']['conditions'],roles):
        if role is None:row.pop('necessity',None)
        else:row['necessity']=role
    ai['condition_plan']['plan_hash']=digest(ai['condition_plan']['conditions'])
    return ai


@pytest.mark.parametrize('pending,expected',[('NOT_REVIEWED','INCOMPLETE'),
    ('USER_MATERIAL_MISSING','NEEDS_MATERIAL'),('CAPABILITY_GAP','CAPABILITY_GAP')])
def test_one_absent_path_does_not_hide_other_paths(pending,expected):
    ai=set_logic(record(['OBSERVED_SUPPORT','OBSERVED_EXCLUSION',pending]),
        ['REQUIRED','ALTERNATIVE_PATH','REQUIRED']);before=deepcopy(ai)
    out=summarize(ai)
    assert out['status']==expected and out['decisive_condition_ids']==[] and ai==before


def test_alternative_exclusion_does_not_prevent_relevant_minimal_material_request():
    ai=set_logic(record(['OBSERVED_SUPPORT','OBSERVED_EXCLUSION','USER_MATERIAL_MISSING']),
        ['REQUIRED','ALTERNATIVE_PATH','REQUIRED']);rows=ai['condition_plan']['conditions']
    with pytest.raises(ValueError,match='ASK_USER'):require_actionable_completion(rows)
    assert requests([request()],rows,generic=True)[0]['condition_id']=='C3'


def test_all_common_requirements_supported_despite_unused_alternative():
    ai=set_logic(record(['OBSERVED_SUPPORT','OBSERVED_EXCLUSION','OBSERVED_SUPPORT']),
        ['REQUIRED','ALTERNATIVE_PATH','REQUIRED'])
    out=summarize(ai)
    assert out['status']=='SUPPORT_OBSERVED' and out['decisive_condition_ids']==['C1','C3']
    assert out['formal_verdict_unchanged']


@pytest.mark.parametrize('pending',['NOT_REVIEWED','USER_MATERIAL_MISSING','CAPABILITY_GAP'])
def test_unused_alternative_gaps_are_preserved_without_blocking_supported_required_conditions(pending):
    ai=set_logic(record(['OBSERVED_SUPPORT',pending,'OBSERVED_SUPPORT']),
        ['REQUIRED','ALTERNATIVE_PATH','REQUIRED']);before=deepcopy(ai)
    out=summarize(ai)
    assert out['status']=='SUPPORT_OBSERVED' and out['decisive_condition_ids']==['C1','C3']
    assert out['conditions'][1]['state']==pending and ai==before
    require_actionable_completion(ai['condition_plan']['conditions'])
    if pending=='USER_MATERIAL_MISSING':
        with pytest.raises(ValueError,match='替代路徑'):
            requests([{**request(),'condition_id':'C2'}],ai['condition_plan']['conditions'],generic=True)


def test_required_fix_is_prioritized_but_alternative_is_not_a_decisive_condition():
    ai=set_logic(record(['OBSERVED_EXCLUSION','OBSERVED_EXCLUSION','NOT_REVIEWED']),
        ['REQUIRED','ALTERNATIVE_PATH','REQUIRED'])
    out=summarize(ai)
    assert out['status']=='EXCLUSION_OBSERVED' and out['decisive_condition_ids']==['C1']


@pytest.mark.parametrize('role',[None,'UNDETERMINED'])
def test_legacy_or_unknown_logic_goes_to_analyst_not_user(role):
    ai=set_logic(record(['OBSERVED_SUPPORT','OBSERVED_EXCLUSION','USER_MATERIAL_MISSING']),
        ['REQUIRED',role,'REQUIRED']);before=deepcopy(ai)
    out=summarize(ai);rows=ai['condition_plan']['conditions']
    assert out['status']=='LOGIC_REVIEW_REQUIRED' and not out['decisive_condition_ids']
    assert ai==before
    require_actionable_completion(rows)
    with pytest.raises(ValueError,match='分析端'):requests([request()],rows,generic=True)


def test_classification_is_immutable_during_review_and_legacy_not_rewritten():
    rows=conditions();before=deepcopy(rows);changed=deepcopy(rows)
    changed[1]['necessity']='ALTERNATIVE_PATH'
    with pytest.raises(ValueError,match='必要性'):validate(changed,PUBLIC,previous=rows)
    for row in rows:row.pop('necessity')
    assert validate(rows,PUBLIC)==rows and 'necessity' not in rows[0]
    changed=deepcopy(rows);changed[1]['necessity']='REQUIRED'
    with pytest.raises(ValueError,match='必要性'):validate(changed,PUBLIC,previous=rows)
    assert before[1]['necessity']=='REQUIRED'


def test_model_schema_requires_explicit_role_and_instructions_distinguish_or_paths():
    from cvevidence_core.ai import TOOL,SYSTEM
    schema=TOOL['parameters']['properties']['conditions']['items']
    assert 'necessity' in schema['required']
    assert schema['properties']['necessity']['enum']==['REQUIRED','ALTERNATIVE_PATH','UNDETERMINED']
    assert '至少一條適用途徑存在' in SYSTEM


def test_web_and_export_explain_legacy_logic_without_rewriting_original():
    from streamlit.testing.v1 import AppTest
    from cvevidence.investigation_view import lines
    ai=set_logic(record(['OBSERVED_SUPPORT','OBSERVED_EXCLUSION','NOT_REVIEWED']),[None,None,None])
    old=deepcopy(ai)
    app=AppTest.from_string('import streamlit as st\nfrom cvevidence.investigation_view import render_overview\n'
        'render_overview(st,'+repr(ai)+')').run(timeout=15)
    assert not app.exception
    assert any('必要條件與替代路徑' in v.value for v in app.info)
    text='\n'.join(lines(ai))
    assert '必要性尚未分類' in text and '局部路徑缺席不能排除整體 CVE' in text
    assert ai==old


def test_unclassified_rule_requires_new_review_and_active_legacy_rule_falls_back(tmp_path):
    from cvevidence_core.rule_library import draft,review,install,activate,select
    from tests.test_rule_library import investigation,reviewed
    ai=investigation();ai['condition_plan']['conditions'][1].pop('necessity')
    ai['condition_plan']['plan_hash']=digest(ai['condition_plan']['conditions'])
    ai['record_hash']=digest({k:v for k,v in ai.items() if k!='record_hash'})
    proposal=draft(ai)
    with pytest.raises(ValueError,match='必要條件'):review(proposal,reviewer='TEST_ONLY',rationale='test',
        applicability='test',validation_reference='test')
    legacy=reviewed()
    for row in legacy['conditions']:row.pop('necessity')
    legacy['rule_hash']=digest({k:v for k,v in legacy.items() if k!='rule_hash'})
    install(legacy,tmp_path);activate(legacy['cve_id'],legacy['rule_hash'],tmp_path)
    result=select(legacy['cve_id'],legacy['public_sources'],tmp_path)
    assert result['status']=='CONDITION_LOGIC_UNREVIEWED' and 'conditions' not in result
