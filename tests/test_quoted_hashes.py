"""Exact source quotations can contain unverified declarations, not new facts."""
from copy import deepcopy
import pytest
from tests.test_turnkey import context
from tests.test_condition_plan import conditions,PUBLIC
from tests.test_general_triage import public_record
from tests.test_ai_provider_core import SimulatedProvider,decision
from cvevidence_core.ai import investigate
from cvevidence_core.queries import collect_evidence
from cvevidence_core.verifier import verify
from cvevidence_core.assessment import assess


@pytest.mark.parametrize('kind,expected',[
    ('raw_quote','COMPLETED'),('invented_quote','TOOL_ERROR'),('prose_claim','REJECTED')])
def test_unverified_declared_hash_can_be_quoted_but_not_invented_or_promoted(tmp_path,monkeypatch,kind,expected):
    external_hash='a'*64
    text='TEST_ONLY unsigned download declaration: '+external_hash+'\n'
    c=context(tmp_path,[('build/receipt.txt',text.encode())]);cve='CVE-2099-0001'
    v=verify(c,collect_evidence(c,cve));assessment=assess(c,v);before=deepcopy(assessment)
    monkeypatch.setattr('cvevidence_core.public_sources.collect',lambda *a,**kw:{'sources':PUBLIC})
    sid=c.by_path('build/receipt.txt')[1]['source_id']
    def review_step(kwargs):
        x=kwargs['history'][-1]['result']['excerpt_id'];rows=conditions()
        for row in rows:
            row.update(state='OBSERVED_SUPPORT',citations=[x],explanation='TEST_ONLY 只觀察收據宣告，未認證其雜湊指向的內容。',
                evidence_quotes=[{'excerpt_id':x,'quote':text.strip()}])
        if kind=='invented_quote':rows[0]['evidence_quotes'][0]['quote']=text.replace(external_hash,'b'*64).strip()
        if kind=='prose_claim':rows[0]['explanation']='TEST_ONLY 成品已驗證為 '+external_hash
        return decision('REVIEW',conditions=rows)
    provider=SimulatedProvider([decision('PLAN',conditions=conditions()),decision('READ',source_ids=[sid]),review_step])
    result=investigate(c,v,assessment,mode='LIVE',provider=provider,max_calls=3,public_record=public_record(cve))
    assert result['tasks'][-1]['status']==expected
    assert assessment==before
    if expected=='COMPLETED':
        assert result['status']=='BUDGET_EXHAUSTED'  # no final step in this test
        assert all(x['engineering_inference_verified'] is False for x in result['verified_ai_facts'])
    elif expected=='TOOL_ERROR':
        repair=result['tasks'][-1]['result']['citation_repair']
        assert repair['condition_id']=='C1' and repair['accepted'] is False
    else:
        assert result['tasks'][-1]['citation_verification']['invalid_hash_mentions']==[external_hash]
