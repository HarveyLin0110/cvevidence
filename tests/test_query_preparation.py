from pathlib import Path
from streamlit.testing.v1 import AppTest
from cvevidence.query_preparation import prepare_queries
from cvevidence_core.evidence import QUERY_IDS
from cvevidence.pc_context import openssl_context

def test_cve_specific_plan_uses_core_ids_and_never_claims_execution():
    openssl=prepare_queries('CVE-2014-0160','rom')
    zlib=prepare_queries('CVE-2022-37434','cmake')
    assert [q['query_id'] for q in openssl['queries']]==list(QUERY_IDS)
    assert all(q['status']=='PLANNED' for q in openssl['queries'])
    assert 'heartbeat' in openssl['queries'][2]['description']
    assert 'EXTRA' in zlib['queries'][2]['description']
    assert openssl['queries']!=zlib['queries']
    general=prepare_queries('CVE-2099-9999','rom')
    assert general['status']=='GENERAL_TRIAGE'
    assert len(general['queries'])==5
    assert all(q['verification_status']=='NOT_RUN' for q in general['queries'])
    mismatch=prepare_queries('CVE-2014-0160','cmake')
    assert mismatch['status']=='FORMAT_GAP'
    assert [q['query_id'] for q in mismatch['queries'] if q['status']=='PLANNED']==['Q2_BUILD']

def test_input_keeps_query_plan_in_analysis_step(tmp_path,monkeypatch):
    monkeypatch.setenv('CVEVIDENCE_STORE',str(tmp_path/'store'))
    root=Path(__file__).resolve().parents[1]
    app=AppTest.from_file(str(root/'runner_app.py')).run()
    field=next(t for t in app.text_input if t.label.startswith('CVE ID'))
    field.set_value('CVE-2014-0160').run()
    assert not app.exception
    assert not any('OPENSSL_NO_HEARTBEATS' in t.value for t in app.text)
    field.set_value('CVE-2022-37434').run()
    assert not any('EXTRA' in t.value for t in app.text)
    assert not any('OPENSSL_NO_HEARTBEATS' in t.value for t in app.text)
    field.set_value('CVE-2099-9999').run()
    assert not any(e.label.startswith('Q1_COMPONENT') or '預覽查核計畫' in e.label for e in app.expander)
    assert not any('準備執行的 Queries' in h.value for h in app.subheader)
    assert not list((tmp_path/'store'/'runs').glob('*.json'))

def test_openssl_explanation_does_not_promote_unknown_or_legacy():
    entry={'cve_id':'CVE-2014-0160','assessment':{'profile_version':'x-runtime-v2','conditions':[]}}
    assert '1.0.1～1.0.1f' in openssl_context(entry,'PC1')
    assert '本次工程證據核對到' not in openssl_context(entry,'PC1')
    assert openssl_context(entry,'PC2')==''
    assert openssl_context(entry,'PC3')==''
    entry['assessment']['profile_version']='legacy'
    assert openssl_context(entry,'PC1')==''

def test_wrong_package_format_cannot_execute_deep_analysis(tmp_path,monkeypatch):
    from cvevidence.runner import Runner
    from cvevidence.storage import RunStore
    root=Path(__file__).resolve().parents[1]
    runner=Runner(RunStore(tmp_path/'mismatch'))
    intake=runner.start_file(root/'demo-inputs/runtime-v2/pc3_cmake_static.tar.gz',cve='CVE-2014-0160')
    assert not intake.error
    monkeypatch.setenv('CVEVIDENCE_STORE',str(runner.store.root))
    app=AppTest.from_file(str(root/'runner_app.py')).run(timeout=30)
    app.session_state.selected_run=intake.run_id
    app.session_state.step='03 分析進度與結果'
    app.run(timeout=30)
    assert not app.exception
    assert any('準備執行的 Queries' in h.value for h in app.subheader)
    assert any(e.label.startswith('Q1_COMPONENT') for e in app.expander)
    assert next(b for b in app.button if b.label=='執行 Queries 與正式判定').disabled
    assert any('資料包與此 CVE' in w.value for w in app.warning)
    assert len(runner.store.list_runs())==1
