import pytest
from tests.test_general_triage import context
from tests.test_condition_plan import conditions
from cvevidence_core.condition_plan import record
from cvevidence_core.integrity import digest
from cvevidence_core.sources import read_excerpt
from cvevidence_core.investigation_control import continuation,usage

def test_resume_retains_only_current_bytes_and_pending_questions(context):
    x=read_excerpt(context,context.by_path('source/main.c')[1]['source_id'])
    rows=conditions();rows[1].update(citations=[x['excerpt_id']],state='USER_MATERIAL_MISSING')
    previous={'context_hash':context.context_hash,'cve_id':'CVE-2024-1179','condition_plan':record(context,'CVE-2024-1179',rows),'excerpts':[x]}
    previous['record_hash']=digest(previous)
    r=continuation(context,'CVE-2024-1179',previous)
    assert r['excerpts']==[x] and r['conditions'][1]['state']=='NOT_REVIEWED'
    with pytest.raises(ValueError):continuation(context,'CVE-2024-0001',previous)
    previous['excerpts'][0]['text']='forged'
    with pytest.raises(ValueError):continuation(context,'CVE-2024-1179',previous)

def test_usage_unknown_is_not_zero_cost_claim():
    u=usage([{'usage':{'input_tokens':10,'output_tokens':20}},{}])
    assert u['total_tokens']==30 and not u['complete']

@pytest.mark.parametrize('raw', [{}, {'total_tokens':None}, {'input_tokens':True,'output_tokens':-1}, {'total_tokens':'bad'}])
def test_unknown_usage_is_incomplete(raw):
    summary=usage([{'usage':raw}])
    assert not summary['complete']
    assert summary['reported_calls']==0
    assert summary['total_tokens']==0


def test_nullable_total_uses_known_input_and_output_without_counting_cache_twice():
    summary=usage([{'usage':{'input_tokens':100,'output_tokens':20,'cached_input_tokens':80,'total_tokens':None}}])
    assert summary['total_tokens']==120
    assert summary['complete']


def test_partial_usage_keeps_known_lower_bound_without_claiming_complete():
    summary=usage([{'usage':{'input_tokens':100}}])
    assert summary['total_tokens']==100
    assert not summary['complete']


def test_token_forecast_reserves_review_and_final_without_raising_limit():
    from cvevidence_core.investigation_control import budget_forecast
    calls=[{'usage':{'total_tokens':n}} for n in (27000,29000,35000)]
    advice=budget_forecast(calls,200000,9,True)
    assert advice['remaining_reported_token_allowance']==109000
    assert advice['estimated_next_call_tokens']==50000
    assert advice['estimated_affordable_calls_including_current']==2
    assert advice['recommended_phase']=='REVIEW_NOW'
    calls.append({'usage':{'total_tokens':44000}})
    advice=budget_forecast(calls,200000,8,False)
    assert advice['recommended_phase']=='FINALIZE_NOW'
    assert advice['remaining_reported_token_allowance']==65000


def test_token_forecast_unknown_usage_and_call_limit_still_disclosed():
    from cvevidence_core.investigation_control import budget_forecast
    advice=budget_forecast([{'usage':None}],200000,2,True)
    assert advice['estimated_next_call_tokens'] is None
    assert advice['recommended_phase']=='REVIEW_NOW'
    advice=budget_forecast([{'usage':{'input_tokens':10000}}],200000,8,False)
    assert advice['estimated_next_call_tokens'] is None
    assert advice['remaining_reported_token_allowance']==190000
    assert advice['recommended_phase']=='INVESTIGATE'


def test_final_affordable_call_requests_combined_report_not_review_only():
    from cvevidence_core.investigation_control import budget_forecast
    # Receipt sizes from a real failed continuation: REVIEW alone left no
    # budget for COMPLETE. The advice must name the combined validated action.
    calls=[{'usage':{'total_tokens':n}} for n in (36820,37254,40235,42843)]
    advice=budget_forecast(calls,200000,8,True)
    assert advice['remaining_reported_token_allowance']==42848
    assert advice['estimated_affordable_calls_including_current']==1
    assert advice['recommended_phase']=='REPORT_NOW'
    assert budget_forecast([],200000,1,True)['recommended_phase']=='REPORT_NOW'
    assert budget_forecast(calls,200000,8,False)['recommended_phase']=='FINALIZE_NOW'
