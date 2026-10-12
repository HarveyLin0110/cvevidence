"""TEST_ONLY exact public selection; never semantic or real-CVE proof."""
from copy import deepcopy
import pytest
from cvevidence_core.public_quotes import options,offered_ids,resolve_submissions
from cvevidence_core.public_packet import compact
from cvevidence_core.public_reader import read
from cvevidence_core.integrity import IntegrityError
from tests.test_public_reader import bundle
from tests.test_condition_plan import conditions


def selection(data):
    packet=compact(data);q=packet['sources'][0]['quote_options'][0]
    row={**conditions()[0],'public_quote_id':q['quote_id'],'public_quote':''}
    return row,offered_ids(packet['sources']),q


def test_exact_selection_preserves_diff_whitespace_crlf_unicode_and_raw_submission():
    text='TEST_ONLY patch\r\n\r\n-  while (中文) {\r\n+    for (i = 1; i < e; i++) {\r\n'
    data=bundle(text);row,offered,q=selection(data);before=deepcopy(row)
    resolved,receipt=resolve_submissions([row],data,offered)
    assert resolved[0]['public_quote']==q['text'] and q['text'] in text
    assert '\r\n-  while' in resolved[0]['public_quote']
    assert 'public_quote_id' not in resolved[0] and row==before
    item=receipt[0];assert text[item['start_char']:item['end_char']]==resolved[0]['public_quote']
    assert item['text_sha256']==data['sources'][0]['text_sha256'] and item['meaning_verified'] is False


@pytest.mark.parametrize('kind',['unknown','other_source','not_offered','bad_type','conflicting_text','tampered'])
def test_selection_fails_closed_without_repairing_or_guessing(kind):
    data=bundle('TEST_ONLY original authoritative text');row,offered,_=selection(data)
    if kind=='unknown':row['public_quote_id']='Q0-9999'
    if kind=='other_source':row['public_source_id']='P-other'
    if kind=='not_offered':offered=set()
    if kind=='bad_type':row['public_source_id']={}
    if kind=='conflicting_text':row['public_quote']='TEST_ONLY invented meaning'
    if kind=='tampered':data['sources'][0]['text']='TEST_ONLY forged source'
    before=deepcopy(row)
    with pytest.raises(IntegrityError if kind=='tampered' else ValueError):resolve_submissions([row],data,offered)
    assert row==before


def test_options_do_not_join_over_an_omitted_patch_line():
    text='TEST_ONLY first line\n'+'x'*2000+'\nTEST_ONLY last line\n'
    data=bundle(text);packet=compact(data);opts=packet['sources'][0]['quote_options']
    assert len(opts)==2 and packet['sources'][0]['omitted_lines']==1
    assert (opts[0]['start_line'],opts[0]['end_line'])==(1,1)
    assert (opts[1]['start_line'],opts[1]['end_line'])==(3,3)
    for q in opts:
        row={**conditions()[0],'public_quote_id':q['quote_id'],'public_quote':''}
        resolved,_=resolve_submissions([row],data,offered_ids(packet['sources']))
        assert resolved[0]['public_quote']==q['text'] and q['text'] in text


def test_read_public_can_offer_previously_omitted_text_with_stable_source_offsets():
    data=bundle(('x'*149+'\n')*40+'TEST_ONLY late condition\nsecond line\n')
    packet=compact(data);old=offered_ids(packet['sources']);later=read(data,'P-test',41,42)
    q=later['quote_options'][0];assert ('P-test',q['quote_id']) not in old
    row={**conditions()[0],'public_quote_id':q['quote_id'],'public_quote':''}
    with pytest.raises(ValueError):resolve_submissions([row],data,old)
    resolved,_=resolve_submissions([row],data,old|{('P-test',q['quote_id'])})
    assert resolved[0]['public_quote']=='TEST_ONLY late condition\nsecond line'
    assert (q['start_line'],q['end_line'])==(41,42)


def test_long_cna_paragraph_has_bounded_exact_options_without_retyping_or_duplicate_root_text():
    data=bundle('TEST_ONLY '+'a'*2000);data['sources'][0]['source_id']='P-CNA-test'
    p=compact(data)['sources'][0];assert 'text' not in p and p['omitted_lines']==0
    assert len(p['quote_options'])>1
    assert all(8<=len(q['text'])<=600 and q['text'] in data['sources'][0]['text'] for q in p['quote_options'])
    assert sum(len(q['text']) for q in p['quote_options'])<=6000


def test_literal_quote_and_historical_records_unchanged():
    rows=conditions();original=deepcopy(rows)
    assert resolve_submissions(rows,{},set())==(rows,[])
    for row in rows:row['public_quote_id']=''
    assert resolve_submissions(rows,{},set())==(original,[])


def test_changing_to_another_valid_option_cannot_redefine_an_accepted_plan():
    from cvevidence_core.condition_plan import validate
    data=bundle('TEST_ONLY original requirement\n'+('a'*90+'\n')*10+'TEST_ONLY unrelated different paragraph\n')
    packet=compact(data);opts=packet['sources'][0]['quote_options'];offered=offered_ids(packet['sources'])
    rows=conditions()
    for row in rows:row.update(public_quote_id=opts[0]['quote_id'],public_quote='')
    planned,_=resolve_submissions(rows,data,offered);validate(planned,data['sources'])
    rows[1]['public_quote_id']=opts[-1]['quote_id']
    reviewed,_=resolve_submissions(rows,data,offered)
    with pytest.raises(ValueError,match='REVIEW'):validate(reviewed,data['sources'],previous=planned)


@pytest.mark.parametrize('read_late',[False,True])
@pytest.mark.parametrize('provider_id',['openai_api','codex_cli'])
def test_core_resolves_selected_public_quote_and_keeps_raw_decisions(tmp_path,monkeypatch,read_late,provider_id):
    from tests.test_turnkey import context
    from tests.test_ai_provider_core import SimulatedProvider,decision
    from tests.test_general_triage import public_record
    from cvevidence_core.ai import investigate
    from cvevidence_core.queries import collect_evidence
    from cvevidence_core.verifier import verify
    from cvevidence_core.assessment import assess
    c=context(tmp_path,[('source.c',b'TEST_ONLY exact product observation')]);cve='CVE-2099-0001'
    data=bundle(('x'*149+'\n')*40+'TEST_ONLY condition must have implementation\nsecond exact line\n') if read_late else bundle('TEST_ONLY condition must have implementation\n+    preserve whitespace\n')
    monkeypatch.setattr('cvevidence_core.public_sources.collect',lambda *a,**kw:deepcopy(data))
    raw=[];expected=[]
    def plan(kw):
        opts=kw['history'][-1]['result']['quote_options'] if read_late else next(s for s in kw['packet']['public_sources']['sources'] if s['source_id']=='P-test')['quote_options']
        q=opts[0];expected.append(q['text']);rows=conditions()
        for row in rows:row.update(public_quote_id=q['quote_id'],public_quote='')
        raw.extend(deepcopy(rows));return decision('PLAN',conditions=rows)
    def finish(kw):
        rows=deepcopy(raw);x=kw['history'][-1]['result']['excerpt_id']
        for row in rows:row.update(state='OBSERVED_SUPPORT',citations=[x],evidence_quotes=[{'excerpt_id':x,'quote':'TEST_ONLY exact product observation'}])
        return decision('REPORT',conditions=rows,citations=[x],finding='PC1 TEST_ONLY。PC2 TEST_ONLY。PC3 TEST_ONLY。')
    steps=([decision('READ_PUBLIC',source_ids=['P-test'],start_line=41,end_line=42)] if read_late else [])
    steps += [plan,decision('READ',source_ids=[c.by_path('source.c')[1]['source_id']]),finish]
    provider=SimulatedProvider(steps);provider.provider_id=provider_id
    v=verify(c,collect_evidence(c,cve));assessment=assess(c,v);before=deepcopy(assessment)
    result=investigate(c,v,assessment,mode='LIVE',provider=provider,max_calls=len(steps),analysis_depth='pc',public_record=public_record(cve))
    assert result['status']=='COMPLETED' and assessment==before
    assert all(row['public_quote']==expected[0] and 'public_quote_id' not in row for row in result['condition_plan']['conditions'])
    for task in [t for t in result['tasks'] if t['action'] in ('PLAN','REPORT')]:
        assert all(row['public_quote']=='' and row['public_quote_id'] for row in task['conditions'])
        assert len(task['public_quote_selections'])==3
    assert provider.seen[-1]['history'][-2]['decision']['conditions']==raw
