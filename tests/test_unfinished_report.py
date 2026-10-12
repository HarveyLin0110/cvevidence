"""TEST_ONLY scheduling checks; the model's conclusion is never forced."""
from copy import deepcopy
import hashlib
import pytest
from tests.test_turnkey import context
from tests.test_condition_plan import conditions,PUBLIC
from tests.test_general_triage import public_record
from tests.test_ai_provider_core import SimulatedProvider,decision
from cvevidence_core.ai import investigate
from cvevidence_core.queries import collect_evidence
from cvevidence_core.verifier import verify
from cvevidence_core.assessment import assess
from cvevidence_core.integrity import digest
from cvevidence_core.providers import ProviderStep,ProviderError


@pytest.mark.parametrize('provider_id',['openai_api','codex_cli'])
@pytest.mark.parametrize('finish',['incomplete','timeout'])
def test_one_followup_preserves_partial_report_and_does_not_force_success(tmp_path,monkeypatch,provider_id,finish):
    c=context(tmp_path,[('source.c',b'TEST_ONLY source first section\nTEST_ONLY source later section')])
    cve='CVE-2099-0001';v=verify(c,collect_evidence(c,cve));assessment=assess(c,v);before=deepcopy(assessment)
    public=[{**r,'url':'https://example.org/TEST_ONLY',
        'raw_sha256':hashlib.sha256(r['text'].encode()).hexdigest(),
        'text_sha256':hashlib.sha256(r['text'].encode()).hexdigest()} for r in PUBLIC]
    monkeypatch.setattr('cvevidence_core.public_sources.collect',lambda *a,**kw:{'sources':public})
    def receipt(d):
        return ProviderStep(d,{'provider':provider_id,'status':'completed','model':'TEST_ONLY','usage':{'total_tokens':1000}})
    def report(kw):
        x=kw['history'][-1]['result'];rows=conditions()
        for row in rows:row.update(citations=[x['excerpt_id']],explanation='已讀 TEST_ONLY 局部，整體條件仍未查完。',
            evidence_quotes=[{'excerpt_id':x['excerpt_id'],'quote':x['text']}])
        return receipt(decision('REPORT',conditions=rows,citations=[x['excerpt_id']],finding='PC1 未完成。PC2 未完成。PC3 未完成。'))
    def followup(kw):
        saved=kw['history'][-1]
        assert saved['decision']['action']=='REPORT' and saved['result']['accepted'] is True
        assert saved['result']['finalized'] is False and saved['result']['condition_ids']==['C1','C2','C3']
        assert 'condition_plan' not in saved['result']  # Raw report retained; feedback avoids duplicating it.
        if finish=='timeout':raise ProviderError('TIMED_OUT','TEST_ONLY_TIMEOUT')
        return receipt(decision('READ',source_ids=[c.by_path('source.c')[1]['source_id']],start_line=2,end_line=2))
    provider=SimulatedProvider([receipt(decision('PLAN',conditions=conditions())),
        receipt(decision('READ',source_ids=[c.by_path('source.c')[1]['source_id']])),report,followup,report])
    provider.provider_id=provider_id
    result=investigate(c,v,assessment,mode='LIVE',provider=provider,max_calls=8,timeout_seconds=240,
        analysis_depth='pc',public_record=public_record(cve))
    assert assessment==before and result['record_hash']==digest({k:v for k,v in result.items() if k!='record_hash'})
    reports=[t for t in result['tasks'] if t['action']=='REPORT']
    assert reports[0]['status']=='COMPLETED' and reports[0]['result']['summary']=='PC1 未完成。PC2 未完成。PC3 未完成。'
    assert reports[0]['result']['finalization_deferred']['condition_ids']==['C1','C2','C3']
    assert all(r['state']=='NOT_REVIEWED' for r in result['condition_plan']['conditions'])
    if finish=='incomplete':
        assert result['status']=='COMPLETED' and len(reports)==2 and len(result['calls'])==5
        assert 'finalization_deferred' not in reports[1]['result']
        assert result['investigation_outcome']['status']=='INCOMPLETE'
        assert result['condition_plan']['conditions'][0]['evidence_quotes'][0]['quote']=='TEST_ONLY source later section'
    else:
        assert result['status']=='TIMED_OUT' and len(reports)==1
        assert result['condition_plan']['conditions'][0]['evidence_quotes'][0]['quote']=='TEST_ONLY source first section'
