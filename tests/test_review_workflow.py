"""TEST_ONLY AI fixtures; real archive/worker/review persistence and UI paths."""
from copy import deepcopy
import json
import tarfile
from uuid import uuid4
import pytest
from streamlit.testing.v1 import AppTest
from tests.test_general_triage import context
from tests.test_condition_plan import conditions
from tests.test_ai_provider_service import settings, synthetic
from cvevidence.runner import Runner
from cvevidence.storage import RunStore
from cvevidence.ai_service import AIService
from cvevidence.ai_config import provider_configuration
from cvevidence.reviews import ReviewStore
from cvevidence_core.sources import read_excerpt
from cvevidence_core.condition_plan import record
from cvevidence_core.condition_review import dossier
from cvevidence_core.integrity import digest


@pytest.fixture
def review_case(context,settings,monkeypatch,tmp_path):
    monkeypatch.setenv('CVEVIDENCE_PUBLIC_CVE_LOOKUP','0')
    x=read_excerpt(context,context.by_path('source/main.c')[1]['source_id'])
    rows=conditions();rows[1].update(citations=[x['excerpt_id']],state='OBSERVED_SUPPORT')
    planned=record(context,'CVE-2024-1179',rows)
    data={'context_hash':context.context_hash,'cve_id':'CVE-2024-1179','condition_plan':planned,'excerpts':[x]}
    evidence=dossier(context,data)
    archive=tmp_path/'input.tgz'
    names=[r['path'] for r in context.manifest['files']]+['manifest.json']
    with tarfile.open(archive,'w:gz') as out:
        for name in names:out.add(context.root/name,arcname=name)
    runner=Runner(RunStore(tmp_path/'runtime'))
    run=runner.analyze_offline(runner.start_file(archive,cve='CVE-2024-1179').run_id)
    def invoke(self,req,*args):
        payload=synthetic(req);ai=payload['analyses'][0]['ai']
        ai.update(data,condition_dossier=evidence)
        ai['record_hash']=digest({k:v for k,v in ai.items() if k!='record_hash'})
        return payload
    monkeypatch.setattr(AIService,'invoke',invoke)
    saved=runner.investigate_ai(run.run_id,provider='openai_api',config_id=provider_configuration('openai_api')[1]['config_id'],consent=True)
    decision={'dossier_hash':evidence['dossier_hash'],'reviewer':'TEST_ONLY 工程師','conditions':[
        {'condition_id':r['condition_id'],'relation':'SUPPORTED' if i==1 else 'UNRESOLVED','rationale':'測試原文與範圍核對'} for i,r in enumerate(rows)]}
    return runner,run,saved,decision


def test_review_roundtrip_and_idempotency_do_not_modify_engineering_or_ai(review_case):
    runner,run,ai,decision=review_case
    before=runner.store._run_path(run.run_id).read_bytes()
    ai_id=ai['request']['ai_id'];review_id=str(uuid4())
    result=runner.review_conditions(run.run_id,ai_id,decision,review_id=review_id)
    assert result['receipt']['formal_verdict_unchanged'] and not result['receipt']['reviewer_authenticated']
    assert runner.review_conditions(run.run_id,ai_id,decision,review_id=review_id)==result
    assert runner.condition_reviews(run.run_id,ai_id)==([result],[])
    assert runner.store._run_path(run.run_id).read_bytes()==before
    assert runner.read_ai(ai_id)==ai
    changed=deepcopy(decision);changed['reviewer']='other'
    with pytest.raises(ValueError):runner.review_conditions(run.run_id,ai_id,changed,review_id=review_id)


def test_review_rejects_foreign_run_invalid_relation_and_tampered_history(review_case):
    runner,run,ai,decision=review_case;ai_id=ai['request']['ai_id']
    with pytest.raises(ValueError):runner.review_conditions(run.parent_run_id,ai_id,decision)
    bad=deepcopy(decision);bad['conditions'][0]['relation']='EXCLUDED'
    with pytest.raises(ValueError):runner.review_conditions(run.run_id,ai_id,bad)
    bad=deepcopy(decision);bad['dossier_hash']='0'*64
    with pytest.raises(ValueError):runner.review_conditions(run.run_id,ai_id,bad)
    result=runner.review_conditions(run.run_id,ai_id,decision)
    path=ReviewStore(runner.store).path(result['review_id'])
    raw=json.loads(path.read_bytes());raw['receipt']['reviewer']='forged';path.write_text(json.dumps(raw))
    valid,rejected=runner.condition_reviews(run.run_id,ai_id)
    assert valid==[] and rejected==[path.name]


def test_review_rechecks_product_archive_bytes(review_case):
    runner,run,ai,decision=review_case
    path=runner.store.root/'blobs'/run.input_package.archive_sha256
    path.write_bytes(b'changed archive')
    with pytest.raises(ValueError):runner.review_conditions(run.run_id,ai['request']['ai_id'],decision)
    assert not list((runner.store.root/'condition-reviews').glob('*.json'))


def review_app():
    import streamlit as st
    from cvevidence.review_workspace import review_workspace,report_text
    runner,run,ai=st.session_state['case']
    selected=review_workspace(st,runner,run,ai)
    if selected:st.text(report_text(selected))


def test_ui_requires_review_and_appends_scoped_report(review_case):
    runner,run,ai,decision=review_case
    app=AppTest.from_function(review_app,default_timeout=15)
    app.session_state['case']=(runner,run,ai)
    app.run()
    assert not app.exception
    app.button[0].click().run()
    assert any('每項理由' in x.value for x in app.error)
    app.text_input[0].set_value('TEST_ONLY reviewer')
    for text in app.text_area:text.set_value('已讀；此測試保留未確認')
    app.checkbox[0].check()
    app.button[0].click().run()
    assert not app.exception
    records,rejected=runner.condition_reviews(run.run_id,ai['request']['ai_id'])
    assert len(records)==1 and not rejected
    assert any('TEST_ONLY reviewer' in x.value and '人工條件覆核' in x.value for x in app.text)
    # Editing creates a separate immutable review, with no widget-state error.
    app.text_area[0].set_value('補充確認理由，仍保留未知')
    next(b for b in app.button if b.label=='保存人工覆核').click().run()
    assert not app.exception
    assert len(runner.condition_reviews(run.run_id,ai['request']['ai_id'])[0])==2
