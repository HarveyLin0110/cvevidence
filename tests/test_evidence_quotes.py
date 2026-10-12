"""Synthetic position/retention checks, not real CVE or semantic validation."""
from copy import deepcopy
import pytest
from cvevidence_core.evidence_quotes import resolve, reject_prose_locations, numbered_text
from cvevidence_core.sources import read_excerpt
from cvevidence_core.integrity import digest, IntegrityError
from tests.test_turnkey import context as make_context
from tests.test_condition_plan import conditions, PUBLIC


@pytest.fixture
def material(tmp_path):
    # Distinct raw byte layout, blank lines and Unicode exercise offsets.
    lines=['/* TEST_ONLY */']+['']*276+[
        '  if(subdomain && sts->includeSubDomains) {',
        '    return sts; /* 中文 */',
        '  }',
        '  repeated_statement();',
        '  repeated_statement();']
    c=make_context(tmp_path,[('sample.c',('\r\n'.join(lines)+'\r\n').encode())])
    x=read_excerpt(c,c.by_path('sample.c')[1]['source_id'],180,282)
    row=conditions()[1]
    row.update(state='OBSERVED_SUPPORT',citations=[x['excerpt_id']],
        evidence_quotes=[{'excerpt_id':x['excerpt_id'],'quote':'if(subdomain && sts->includeSubDomains) {\n    return sts; /* 中文 */'}])
    return c,x,row


def test_exact_quote_derives_original_lines_without_rewriting_parent(material):
    c,x,row=material;before=deepcopy(x)
    focus=resolve(c,row,{x['excerpt_id']:x},require=True)
    assert (focus[0]['start_line'],focus[0]['end_line'])==(278,279)
    assert focus[0]['text'].startswith('  if(subdomain')
    assert focus[0]['parent_excerpt_id']==x['excerpt_id']
    assert not focus[0]['meaning_verified'] and x==before
    assert '  278 |   if(' in numbered_text(focus[0])


@pytest.mark.parametrize('case',['invented','ambiguous','foreign','uncited','empty','oversize','tampered','missing'])
def test_quote_rejects_unverifiable_locations(material,case):
    c,x,row=material;excerpts={x['excerpt_id']:x}
    if case=='invented':row['evidence_quotes'][0]['quote']='if(subdomain && FIXED_CONDITION)'
    if case=='ambiguous':row['evidence_quotes'][0]['quote']='repeated_statement();'
    if case=='foreign':excerpts={}
    if case=='uncited':row['citations']=[]
    if case=='empty':row['evidence_quotes'][0]['quote']='   '
    if case=='oversize':row['evidence_quotes'][0]['quote']='x'*1601
    if case=='tampered':x['text']='forged raw text'
    if case=='missing':row.pop('evidence_quotes')
    with pytest.raises(ValueError):resolve(c,row,excerpts,require=True)


@pytest.mark.parametrize('value',['第 254–279 行命中','第438行','270–282 行',
    'lines 427-436 update','line: 283','L277–L283','hsts.c:438'])
def test_generated_prose_cannot_estimate_its_own_line_numbers(value):
    with pytest.raises(ValueError,match='數字行號'):reject_prose_locations(value)


def test_versions_condition_ids_and_quoted_line_descriptions_are_not_removed():
    reject_prose_locations('PC2 C3：curl 8.10.1 / CVE-2024-9681；256 bytes；引用 X-123456abcdef')


def test_dossier_precise_focus_tamper_and_legacy_read_ranges(material):
    from cvevidence_core.condition_plan import record
    from cvevidence_core.condition_review import dossier,verify_review
    c,x,row=material;rows=conditions();rows[1]=row
    ai={'context_hash':c.context_hash,'cve_id':'CVE-2099-0001',
        'condition_plan':record(c,'CVE-2099-0001',rows),'excerpts':[x]}
    d=dossier(c,ai)
    assert d['conditions'][1]['evidence'][0]['start_line']==180
    assert d['conditions'][1]['focus'][0]['start_line']==278
    decision={'reviewer':'TEST_ONLY','dossier_hash':d['dossier_hash'],'conditions':[
        {'condition_id':r['condition_id'],'relation':'UNRESOLVED','rationale':'TEST_ONLY'} for r in rows]}
    assert verify_review(c,d,decision)['formal_verdict_unchanged']
    bad=deepcopy(d);bad['conditions'][1]['focus'][0]['start_line']=254
    bad['dossier_hash']=digest({k:v for k,v in bad.items() if k!='dossier_hash'})
    with pytest.raises(IntegrityError):verify_review(c,bad,{**decision,'dossier_hash':bad['dossier_hash']})
    rows[1].pop('evidence_quotes');ai['condition_plan']=record(c,ai['cve_id'],rows)
    assert dossier(c,ai)['conditions'][1]['focus']==[]


def test_quotes_can_change_at_review_but_not_be_smuggled_into_rule_plan(material):
    from cvevidence_core.condition_plan import validate
    c,x,row=material;rows=conditions();rows[1]=row
    assert validate(rows,PUBLIC,previous=conditions())[1]['evidence_quotes']==row['evidence_quotes']
    rows[1]['state']='NOT_REVIEWED'
    with pytest.raises(ValueError):validate(rows,PUBLIC)


def test_invalid_prose_and_quote_can_be_repaired_without_changing_previous_plan(material,monkeypatch):
    from tests.test_ai_provider_core import SimulatedProvider,decision
    from tests.test_general_triage import public_record
    from cvevidence_core.ai import investigate
    from cvevidence_core.queries import collect_evidence
    from cvevidence_core.verifier import verify
    from cvevidence_core.assessment import assess
    c,x,row=material;rows=conditions();reviewed=deepcopy(rows);reviewed[1]=row
    for r in (reviewed[0],reviewed[2]):r['state']='CAPABILITY_GAP'
    wrong_quote=deepcopy(reviewed);wrong_quote[1]['evidence_quotes'][0]['quote']='invented exact source'
    wrong_line=deepcopy(reviewed);wrong_line[1]['explanation']='第 254–279 行命中'
    monkeypatch.setattr('cvevidence_core.public_sources.collect',lambda *a,**kw:{'sources':PUBLIC})
    monkeypatch.setenv('CVEVIDENCE_RULE_LIBRARY',str(c.root/'unused-rule-library'))
    v=verify(c,collect_evidence(c,'CVE-2024-1179'))
    provider=SimulatedProvider([
        decision('PLAN',conditions=rows),
        decision('READ',source_ids=[x['source_id']],start_line=x['start_line'],end_line=x['end_line']),
        decision('REVIEW',conditions=wrong_line),decision('REVIEW',conditions=wrong_quote),
        decision('REVIEW',conditions=reviewed),
        decision('COMPLETE',citations=[x['excerpt_id']],finding='TEST_ONLY PC1／PC3 能力缺口；PC2 原文線索仍待覆核。')])
    result=investigate(c,v,assess(c,v),mode='LIVE',provider=provider,max_calls=6,public_record=public_record())
    assert result['status']=='COMPLETED' and result['mode']=='SIMULATED'
    assert [t['status'] for t in result['tasks']]==['COMPLETED','COMPLETED','TOOL_ERROR','TOOL_ERROR','COMPLETED','COMPLETED']
    assert result['condition_dossier']['conditions'][1]['focus'][0]['start_line']==278
    assert result['investigation_outcome']['conditions'][1]['hits'][0]['location_kind']=='EXACT_QUOTE'


def test_ui_and_report_distinguish_exact_quote_from_read_range(material):
    from streamlit.testing.v1 import AppTest
    from cvevidence_core.condition_plan import record
    from cvevidence_core.condition_review import dossier
    from cvevidence.investigation_view import lines
    from tests.test_investigation_view import render
    c,x,row=material;rows=conditions();rows[1]=row
    ai={'context_hash':c.context_hash,'cve_id':'CVE-2099-0001',
        'condition_plan':record(c,'CVE-2099-0001',rows),'excerpts':[x]}
    ai['condition_dossier']=dossier(c,ai)
    app=AppTest.from_function(render,args=(ai,)).run(timeout=15)
    assert not app.exception
    assert any('關鍵原文位置：sample.c:278–279' in t.value for t in app.text)
    assert any('已讀引用範圍' in e.label and '180–282' in e.label for e in app.expander)
    assert '關鍵原文位置：sample.c:278–279' in '\n'.join(lines(ai))
    assert '  278 |' in '\n'.join(t.value for t in app.code)
