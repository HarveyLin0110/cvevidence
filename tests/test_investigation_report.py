"""Atomic model REVIEW + COMPLETE; never an engineering verdict promotion."""
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


def run_report(tmp_path,monkeypatch,mutation=None,provider_id='openai_api'):
    c=context(tmp_path,[('source.c',b'TEST_ONLY exact source observation')]);cve='CVE-2099-0001'
    v=verify(c,collect_evidence(c,cve));a=assess(c,v);before=deepcopy(a)
    public=[{**row,'url':'https://example.org/TEST_ONLY',
        'raw_sha256':hashlib.sha256(row['text'].encode()).hexdigest(),
        'text_sha256':hashlib.sha256(row['text'].encode()).hexdigest()} for row in PUBLIC]
    monkeypatch.setattr('cvevidence_core.public_sources.collect',lambda *a,**kw:{'sources':public})
    def finish(kw):
        x=kw['history'][-1]['result']['excerpt_id'];rows=conditions()
        for row in rows:row.update(state='OBSERVED_SUPPORT',citations=[x],explanation='TEST_ONLY 待覆核觀察。',
            evidence_quotes=[{'excerpt_id':x,'quote':'TEST_ONLY exact source observation'}])
        if mutation:mutation(rows)
        return decision('REPORT',conditions=rows,citations=[x],finding='PC1：TEST_ONLY 元件觀察。PC2：TEST_ONLY 實作觀察。PC3：TEST_ONLY 運作觀察。')
    provider=SimulatedProvider([decision('PLAN',conditions=conditions()),
        decision('READ',source_ids=[c.by_path('source.c')[1]['source_id']]),finish])
    provider.provider_id=provider_id
    result=investigate(c,v,a,mode='LIVE',provider=provider,max_calls=3,analysis_depth='pc',public_record=public_record(cve))
    assert a==before
    return result


@pytest.mark.parametrize('provider_id',['openai_api','codex_cli'])
def test_report_completes_review_and_summary_in_one_actual_model_step(tmp_path,monkeypatch,provider_id):
    r=run_report(tmp_path,monkeypatch,provider_id=provider_id)
    assert r['status']=='COMPLETED' and r['mode']=='SIMULATED'
    assert [t['action'] for t in r['tasks']]==['PLAN','READ','REPORT']
    assert len(r['calls'])==3 and r['tasks'][-1]['status']=='COMPLETED'
    assert r['condition_dossier'] and r['investigation_outcome']['status']=='SUPPORT_OBSERVED'
    assert r['condition_plan']['plan_hash']==r['tasks'][-1]['result']['condition_plan']['plan_hash']


@pytest.mark.parametrize('kind',['missing','quote','redefined','public'])
def test_report_cannot_bypass_material_or_quote_checks(tmp_path,monkeypatch,kind):
    def mutate(rows):
        if kind=='missing':rows[1]['state']='USER_MATERIAL_MISSING'
        if kind=='quote':rows[1]['evidence_quotes'][0]['quote']='Invented TEST_ONLY observation'
        if kind=='redefined':rows[1]['requirement']='Different condition'
        if kind=='public':rows[1]['public_quote']='Invented announcement quote'
    r=run_report(tmp_path,monkeypatch,mutate)
    assert r['status']=='BUDGET_EXHAUSTED' and r['tasks'][-1]['status']=='TOOL_ERROR'
    # Failed combined operation must not replace the last accepted plan.
    assert all(row['state']=='NOT_REVIEWED' for row in r['condition_plan']['conditions'])


def test_report_cannot_close_other_gaps_with_an_unverified_exclusion(tmp_path,monkeypatch):
    def mutate(rows):rows[1]['state']='OBSERVED_EXCLUSION';rows[2]['state']='USER_MATERIAL_MISSING'
    r=run_report(tmp_path,monkeypatch,mutate)
    assert r['status']=='BUDGET_EXHAUSTED' and r['tasks'][-1]['status']=='TOOL_ERROR'
    assert '排除依據' in r['tasks'][-1]['result']['error']
    assert all(row['state']=='NOT_REVIEWED' for row in r['condition_plan']['conditions'])


def test_report_can_save_verified_quotes_without_promoting_incomplete_conditions(tmp_path,monkeypatch):
    def mutate(rows):
        for row in rows:row['state']='NOT_REVIEWED'
    r=run_report(tmp_path,monkeypatch,mutate)
    assert r['status']=='COMPLETED' and r['investigation_outcome']['status']=='INCOMPLETE'
    assert all(row['state']=='NOT_REVIEWED' for row in r['condition_plan']['conditions'])
    assert all(row['focus'] for row in r['condition_dossier']['conditions'])


@pytest.mark.parametrize('kind',['none','forged'])
def test_incomplete_report_still_requires_exact_observation(tmp_path,monkeypatch,kind):
    def mutate(rows):
        for row in rows:
            row['state']='NOT_REVIEWED'
            if kind=='none':row['evidence_quotes']=[]
            else:row['evidence_quotes'][0]['quote']='TEST_ONLY invented source'
    r=run_report(tmp_path,monkeypatch,mutate)
    assert r['status']=='BUDGET_EXHAUSTED' and r['tasks'][-1]['status']=='TOOL_ERROR'
    assert all(not row.get('evidence_quotes') for row in r['condition_plan']['conditions'])


def test_report_narrative_visible_in_web_without_extra_complete_task(tmp_path,monkeypatch):
    from streamlit.testing.v1 import AppTest
    r=run_report(tmp_path,monkeypatch)
    app=AppTest.from_string('import streamlit as st\nfrom cvevidence.analysis_view import render_ai\n'
        'render_ai(st,'+repr(r)+',context_hash='+repr(r['context_hash'])+',cve_id='+repr(r['cve_id'])+
        ',assessment_id='+repr(r['engineering_assessment_id'])+')').run(timeout=15)
    assert not app.exception
    assert any('PC1：TEST_ONLY 元件觀察' in x.value for x in app.text)


@pytest.mark.parametrize('provider_id',['openai_api','codex_cli'])
def test_explicit_quote_id_need_not_be_repeated_in_condition_citations(tmp_path,monkeypatch,provider_id):
    def mutate(rows):
        for row in rows:row['citations']=[]
    r=run_report(tmp_path,monkeypatch,mutate,provider_id)
    assert r['status']=='COMPLETED'
    task=r['tasks'][-1]
    assert all(row['citations']==[] for row in task['conditions'])  # Raw decision retained.
    for row in r['condition_plan']['conditions']:
        xid=row['evidence_quotes'][0]['excerpt_id']
        assert row['citations']==[xid]
        assert task['expanded_quote_citations'][row['condition_id']]==[xid]
    assert task['citation_verification']['valid']
    assert all(row['focus'] for row in r['condition_dossier']['conditions'])


@pytest.mark.parametrize('kind',['foreign','invented','empty','public','capacity'])
def test_quote_citation_expansion_never_repairs_unverified_evidence(tmp_path,monkeypatch,kind):
    def mutate(rows):
        row=rows[1];row['citations']=[]
        if kind=='foreign':row['evidence_quotes'][0]['excerpt_id']='X-another-run'
        if kind=='invented':row['evidence_quotes'][0]['quote']='invented TEST_ONLY text'
        if kind=='empty':row['evidence_quotes'][0]['quote']=''
        if kind=='public':row['evidence_quotes'][0]['excerpt_id']='P-test'
        if kind=='capacity':row['citations']=[rows[0]['citations'][0]]*8;row['evidence_quotes']*=5
    r=run_report(tmp_path,monkeypatch,mutate)
    assert r['status']!='COMPLETED' and r['tasks'][-1]['status'] in ('REJECTED','TOOL_ERROR')
    assert all(row['state']=='NOT_REVIEWED' for row in r['condition_plan']['conditions'])
