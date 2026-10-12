"""Lossless input sharing, not token-price or real model correctness claims."""
from copy import deepcopy
import hashlib
import json
import pytest
from cvevidence_core.investigation_packet import compact, EXCERPT_FIELDS
from cvevidence_core.integrity import digest, IntegrityError
from cvevidence_core.sources import read_excerpt
from tests.test_turnkey import context as make_context
from tests.test_condition_plan import conditions, PUBLIC


@pytest.fixture
def material(tmp_path):
    c=make_context(tmp_path,[('source/receipt.txt',('TEST_ONLY submitted observation\n'+'remaining content\n'*20).encode())])
    x=read_excerpt(c,c.by_path('source/receipt.txt')[1]['source_id'],1,20)
    return c,x


def test_packet_shares_equal_conditions_and_excerpts_without_mutating_records(material):
    c,x=material;rows=conditions()
    p={'condition_plan':{'conditions':rows,'plan_hash':digest(rows)},
       'rule_library':{'conditions':deepcopy(rows),'status':'CURRENT_REVIEWED_RULE','applicability':'TEST_ONLY'},
       'initial_product_excerpts':[x,x],
       'pc_evidence_packet':[{'evidence_id':'E-TEST_ONLY','excerpts':[{**x,'path':'source/receipt.txt'}]}],
       'continuation':{'conditions':deepcopy(rows),'excerpts':[x],'retained_read_excerpt_ids':[x['excerpt_id']],
           'previous_questions':[{'finding':'TEST_ONLY outstanding question'}]},
       'public_sources':{'sources':[{'text':'TEST_ONLY no changes to authoritative sources'}]}}
    original=deepcopy(p);out,metrics=compact(c,p)
    assert p==original
    assert out['condition_plan']==p['condition_plan']
    assert out['public_sources']==p['public_sources']
    assert out['rule_library']['applicability']=='TEST_ONLY'
    assert out['rule_library']['conditions_ref']=='condition_plan.conditions'
    assert out['continuation']['conditions_ref']=='condition_plan.conditions'
    assert 'conditions' not in out['rule_library'] and 'conditions' not in out['continuation']
    assert 'excerpts' not in out['continuation']
    pool={e['excerpt_id']:e for e in out['initial_product_excerpts']}
    assert list(pool)==[x['excerpt_id']]
    for references in (out['continuation']['excerpt_ids'],out['pc_evidence_packet'][0]['excerpt_ids']):
        assert [{k:pool[xid][k] for k in EXCERPT_FIELDS} for xid in references]==[x]
    assert pool[x['excerpt_id']]['path']=='source/receipt.txt'
    assert metrics['duplicate_condition_sets_removed']==2
    assert metrics['duplicate_excerpt_occurrences_removed']==3
    assert metrics['bytes_removed']==metrics['original_bytes']-metrics['transmitted_bytes']>0
    assert metrics['transmitted_bytes']==len(json.dumps(out,ensure_ascii=False).encode())
    assert not metrics['content_truncated_by_compaction']


def test_distinct_overlapping_ranges_and_changed_conditions_are_not_discarded(material):
    c,x=material;y=read_excerpt(c,x['source_id'],2,20)
    original=conditions();different=deepcopy(original);different[0]['requirement']='TEST_ONLY different scope'
    p={'condition_plan':{'conditions':original},'rule_library':{'conditions':different},
       'initial_product_excerpts':[x,y]}
    out,stats=compact(c,p)
    assert out==p
    assert stats['duplicate_condition_sets_removed']==stats['duplicate_excerpt_occurrences_removed']==0


@pytest.mark.parametrize('change',['text','scope','path','unknown_field'])
def test_conflicting_or_forged_excerpt_fails_closed(material,change):
    c,x=material;y=deepcopy(x)
    if change=='text':y['text']='invented copied text'
    if change=='scope':y['context_hash']='foreign-case'
    if change=='path':y['path']='different.c'
    if change=='unknown_field':y['undeclared_metadata']='must not silently discard'
    with pytest.raises(IntegrityError):compact(c,{'initial_product_excerpts':[x,y]})


@pytest.mark.parametrize('provider_id',['openai_api','codex_cli'])
def test_continuation_can_review_shared_evidence_without_reading_again(material,monkeypatch,provider_id):
    from tests.test_ai_provider_core import SimulatedProvider,decision
    from tests.test_general_triage import public_record
    from cvevidence_core.ai import investigate
    from cvevidence_core.queries import collect_evidence
    from cvevidence_core.verifier import verify
    from cvevidence_core.assessment import assess
    from cvevidence_core.condition_plan import record
    from cvevidence_core.investigation_control import control
    c,x=material;rows=conditions()
    public={'sources':[{**PUBLIC[0],'text_sha256':hashlib.sha256(PUBLIC[0]['text'].encode()).hexdigest()}]}
    rows[1].update(state='USER_MATERIAL_MISSING',citations=[x['excerpt_id']],
        evidence_quotes=[{'excerpt_id':x['excerpt_id'],'quote':'TEST_ONLY submitted observation'}])
    previous={'context_hash':c.context_hash,'cve_id':'CVE-2024-1179','condition_plan':record(c,'CVE-2024-1179',rows),
        'public_sources':public,'excerpts':[x],
        'tasks':[{'action':'READ','status':'COMPLETED','result':x}]}
    previous['record_hash']=digest(previous);original=deepcopy(previous)
    monkeypatch.setattr('cvevidence_core.public_sources.collect',lambda *a,**kw:deepcopy(public))
    monkeypatch.setenv('CVEVIDENCE_RULE_LIBRARY',str(c.root/'unused-rule-library'))
    def review(kwargs):
        p=kwargs['packet'];continuation=p['continuation']
        assert 'excerpts' not in continuation and 'conditions' not in continuation
        assert continuation['conditions_ref']=='condition_plan.conditions'
        assert continuation['retained_read_excerpt_ids']==[x['excerpt_id']]
        pool={e['excerpt_id']:e for e in p['initial_product_excerpts']}
        assert pool[x['excerpt_id']]['text']==x['text']
        reviewed=deepcopy(p['condition_plan']['conditions'])
        for row in reviewed:row.update(state='CAPABILITY_GAP',explanation='TEST_ONLY still requires a dedicated verifier')
        return decision('REVIEW',conditions=reviewed)
    provider=SimulatedProvider([review,decision('COMPLETE',citations=[x['excerpt_id']],finding='TEST_ONLY capability gap remains')])
    provider.provider_id=provider_id;provider.auth_type='api_key' if provider_id=='openai_api' else 'chatgpt'
    v=verify(c,collect_evidence(c,'CVE-2024-1179'))
    marker=control.set({'previous':previous})
    try:result=investigate(c,v,assess(c,v),mode='LIVE',provider=provider,public_record=public_record())
    finally:control.reset(marker)
    assert previous==original
    assert result['status']=='COMPLETED' and result['mode']=='SIMULATED'
    assert result['continuation_from']==previous['record_hash']
    assert result['input_compaction']['duplicate_condition_sets_removed']==1
    assert result['input_compaction']['duplicate_excerpt_occurrences_removed']>=1
    assert result['condition_dossier']['conditions'][1]['focus'][0]['start_line']==1
    assert [t['action'] for t in result['tasks']]==['REVIEW','COMPLETE']
