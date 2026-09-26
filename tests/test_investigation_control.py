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
