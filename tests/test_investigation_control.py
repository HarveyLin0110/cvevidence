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


def test_token_forecast_reserves_one_report_and_allows_one_last_read():
    from cvevidence_core.investigation_control import budget_forecast
    calls=[{'usage':{'total_tokens':n}} for n in (27000,29000,35000)]
    advice=budget_forecast(calls,200000,9,True)
    assert advice['remaining_reported_token_allowance']==109000
    assert advice['estimated_next_call_tokens']==50000
    assert advice['estimated_affordable_calls_including_current']==2
    assert advice['recommended_phase']=='LAST_CHECK_OR_REPORT'
    calls.append({'usage':{'total_tokens':44000}})
    advice=budget_forecast(calls,200000,8,False)
    assert advice['recommended_phase']=='FINALIZE_NOW'
    assert advice['remaining_reported_token_allowance']==65000


def test_token_forecast_unknown_usage_and_call_limit_still_disclosed():
    from cvevidence_core.investigation_control import budget_forecast
    advice=budget_forecast([{'usage':None}],200000,2,True)
    assert advice['estimated_next_call_tokens'] is None
    assert advice['recommended_phase']=='LAST_CHECK_OR_REPORT'
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


def test_unfinished_report_uses_post_response_receipts_and_preserves_conditions():
    from copy import deepcopy
    from cvevidence_core.investigation_control import unfinished_report_followup
    rows=conditions();before=deepcopy(rows)
    calls=[{'usage':{'total_tokens':n}} for n in (27338,27917,36442)]
    followup=unfinished_report_followup(rows,calls,200000,9,143.4)
    assert followup['condition_ids']==['C1','C2','C3'] and rows==before
    assert followup['budget_forecast']['remaining_reported_token_allowance']==108303
    assert followup['budget_forecast']['estimated_affordable_calls_including_current']==2


@pytest.mark.parametrize('limit',['time','calls','tokens','unknown_usage','once','alternative','exclusion','tool_gap','material_gap','already_read'])
def test_unfinished_report_never_forces_extra_work_or_promotes_states(limit):
    from copy import deepcopy
    from cvevidence_core.investigation_control import unfinished_report_followup
    rows=conditions();calls=[{'usage':{'total_tokens':10000}}]
    kwargs=dict(threshold=200000,remaining_calls=5,remaining_seconds=200,already_deferred=False)
    if limit=='time':kwargs['remaining_seconds']=129.99
    if limit=='calls':kwargs['remaining_calls']=1
    if limit=='tokens':kwargs['threshold']=45000
    if limit=='unknown_usage':calls.append({'usage':None})
    if limit=='once':kwargs['already_deferred']=True
    if limit=='alternative':
        for row in rows:row['necessity']='ALTERNATIVE_PATH'
    if limit=='exclusion':rows[0]['state']='OBSERVED_EXCLUSION'
    if limit in ('tool_gap','material_gap','already_read'):
        for row in rows:row['state']={'tool_gap':'CAPABILITY_GAP','material_gap':'USER_MATERIAL_MISSING','already_read':'OBSERVED_SUPPORT'}[limit]
    before=deepcopy(rows)
    assert unfinished_report_followup(rows,calls,**kwargs) is None and rows==before
