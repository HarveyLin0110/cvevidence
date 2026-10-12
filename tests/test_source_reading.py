"""Bounded multi-file reads with simulated providers; no live quality claims."""
import pytest
from cvevidence_core.source_reading import read_batch,completed_reads
from cvevidence_core.integrity import IntegrityError
from cvevidence_core.sources import verify_excerpt,search_sources
from cvevidence_core.investigation_intake import check_copy_reads
from cvevidence_core.investigation_control import continuation
from cvevidence_core.quality import evaluate
from tests.test_source_search_coverage import context,ids
from tests.test_copy_read_gate import previous_reads


def test_reads_keep_separate_exact_citations_and_do_not_execute_input(tmp_path):
    c=context(tmp_path,{'a/main.c':b'TEST_ONLY source\nsecond\n','b/main.c':b'$(never execute)\nsecond\n'})
    a,b=ids(c,'a/main.c','b/main.c')
    result=read_batch(c,[a,b],1,2)
    assert [x['source_id'] for x in result['matches']]==[a,b]
    assert all(verify_excerpt(c,x) for x in result['matches'])
    assert len({x['excerpt_id'] for x in result['matches']})==2
    task={'action':'READ_BATCH','status':'COMPLETED','result':result}
    tasks=[{'action':'SEARCH','status':'COMPLETED','result':search_sources(c,'second')},task]
    assert check_copy_reads(c,tasks)['unread_copy_count']==0
    previous=previous_reads(c,result['matches'],[task])
    resumed=continuation(c,'CVE-2024-1179',previous)
    assert set(resumed['retained_read_excerpt_ids'])=={x['excerpt_id'] for x in result['matches']}
    assert set(evaluate({'tasks':[task]})['explicit_read_source_ids'])=={a,b}


@pytest.mark.parametrize('variant',['empty','single','duplicate','too_many','unknown','overlong'])
def test_invalid_batch_request_fails_as_a_whole(tmp_path,variant):
    c=context(tmp_path,{'a.txt':b'TEST_ONLY\n','b.txt':b'TEST_ONLY\n','c.txt':b'\x00binary'})
    a,b,binid=ids(c,'a.txt','b.txt','c.txt')
    selected={'empty':[],'single':[a],'duplicate':[a,a],'too_many':[a,b,binid,'S-unknown'],
        'unknown':[a,'S-unknown'],'overlong':[a,b]}[variant]
    with pytest.raises((ValueError,IntegrityError)):
        read_batch(c,selected,1,201 if variant=='overlong' else 1)


def test_batch_aggregate_utf8_limit_preserves_only_returned_reads(tmp_path):
    c=context(tmp_path,{n:('中'*6000).encode() for n in ('a.txt','b.txt','c.txt')})
    a,b,last=ids(c,'a.txt','b.txt','c.txt')
    result=read_batch(c,[a,b,last],1,1)
    assert [x['source_id'] for x in result['matches']]==[a,b]
    assert result['coverage_limited'] and result['failures'][0]['source_id']==last
    assert '48000' in result['failures'][0]['error']
    assert len(completed_reads({'action':'READ_BATCH','status':'COMPLETED','result':result}))==2
    assert completed_reads({'action':'READ_BATCH','status':'TOOL_ERROR','result':{'matches':[{'source_id':'a'}]}})==[]
    assert completed_reads({'action':'SEARCH','status':'COMPLETED','result':{'matches':[{'source_id':'a'}]}})==[]


@pytest.mark.parametrize('provider_id',['openai_api','codex_cli'])
def test_both_provider_paths_cite_batch_results_and_preserve_formal_verdict(tmp_path,provider_id):
    from tests.test_ai_provider_core import SimulatedProvider,decision
    from cvevidence_core.ai import investigate
    from cvevidence_core.queries import collect_evidence
    from cvevidence_core.verifier import verify
    from cvevidence_core.assessment import assess
    from cvevidence_core.investigation_evidence import reassess_after_investigation
    from cvevidence_core.integrity import digest
    c=context(tmp_path,{'a.txt':b'TEST_ONLY first observation','b.txt':b'TEST_ONLY second observation'})
    v=verify(c,collect_evidence(c,'CVE-2023-38545'));assessment=assess(c,v);before=digest(assessment)
    def finish(kwargs):
        xs=kwargs['history'][-1]['result']['matches']
        return decision('COMPLETE',finding='TEST_ONLY 觀察，不改正式判定。',citations=[x['excerpt_id'] for x in xs])
    provider=SimulatedProvider([decision('READ_BATCH',source_ids=list(ids(c,'a.txt','b.txt'))),finish])
    provider.provider_id=provider_id
    result=investigate(c,v,assessment,mode='LIVE',provider=provider,max_calls=2)
    assert result['status']=='COMPLETED' and result['mode']=='SIMULATED'
    assert result['tasks'][0]['status']=='COMPLETED' and len(result['excerpts'])==2
    followup=reassess_after_investigation(c,assessment,result)
    assert len(followup['new_evidence'])==2 and followup['verdict_changed'] is False
    assert digest(assessment)==before


def test_one_unreadable_batch_member_does_not_discard_valid_reads(tmp_path):
    from tests.test_ai_provider_core import SimulatedProvider,decision
    from cvevidence_core.ai import investigate
    from cvevidence_core.queries import collect_evidence
    from cvevidence_core.verifier import verify
    from cvevidence_core.assessment import assess
    c=context(tmp_path,{'a.txt':b'TEST_ONLY valid','b.txt':b'\x00unreadable'})
    v=verify(c,collect_evidence(c,'CVE-2023-38545'))
    provider=SimulatedProvider([decision('READ_BATCH',source_ids=list(ids(c,'a.txt','b.txt')))])
    result=investigate(c,v,assess(c,v),mode='LIVE',provider=provider,max_calls=1)
    assert result['tasks'][0]['status']=='COMPLETED'
    assert len(result['excerpts'])==1 and len(result['verified_ai_facts'])==1
    assert result['tasks'][0]['result']['failures'][0]['read_completed'] is False
    assert result['status']=='BUDGET_EXHAUSTED'  # a partial read is not a report


def test_large_map_does_not_discard_receipt_and_runtime_or_satisfy_unread_copy(tmp_path):
    c=context(tmp_path,{'large/main.c':b'TEST_ONLY '+b'x'*24000,
        'small/main.c':b'TEST_ONLY short source','runtime.txt':b'TEST_ONLY normal observation'})
    large,small,runtime=ids(c,'large/main.c','small/main.c','runtime.txt')
    result=read_batch(c,[large,small,runtime],1,100)
    assert [x['source_id'] for x in result['matches']]==[small,runtime]
    assert [x['source_id'] for x in result['failures']]==[large]
    task={'action':'READ_BATCH','status':'COMPLETED','result':result}
    tasks=[{'action':'SEARCH','status':'COMPLETED','result':search_sources(c,'TEST_ONLY')},task]
    with pytest.raises(ValueError,match='未 READ'):check_copy_reads(c,tasks)
    previous=previous_reads(c,result['matches'],[task])
    resumed=continuation(c,'CVE-2024-1179',previous)
    assert set(resumed['retained_read_excerpt_ids'])=={x['excerpt_id'] for x in result['matches']}


def test_all_unreadable_members_have_no_excerpts(tmp_path):
    c=context(tmp_path,{'a.bin':b'\x00TEST_ONLY','b.bin':b'\x00TEST_ONLY'})
    result=read_batch(c,list(ids(c,'a.bin','b.bin')),1,1)
    assert result['matches']==[] and len(result['failures'])==2
    assert completed_reads({'action':'READ_BATCH','status':'COMPLETED','result':result})==[]


def test_later_changed_file_invalidates_whole_batch(tmp_path):
    c=context(tmp_path,{'a.txt':b'TEST_ONLY valid','b.txt':b'TEST_ONLY original'})
    a,b=ids(c,'a.txt','b.txt');c.source(b)[0].write_text('TEST_ONLY changed')
    with pytest.raises(IntegrityError):read_batch(c,[a,b],1,1)
