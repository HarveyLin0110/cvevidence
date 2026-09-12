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
    assert prepare_queries('CVE-2099-9999','rom')['queries']==[]
    mismatch=prepare_queries('CVE-2014-0160','cmake')
    assert mismatch['status']=='FORMAT_GAP'
    assert [q['query_id'] for q in mismatch['queries'] if q['status']=='PLANNED']==['Q2_BUILD']

def test_input_switches_query_preview_without_creating_runs(tmp_path,monkeypatch):
    monkeypatch.setenv('CVEVIDENCE_STORE',str(tmp_path/'store'))
    root=Path(__file__).resolve().parents[1]
    app=AppTest.from_file(str(root/'runner_app.py')).run()
    field=next(t for t in app.text_input if t.label.startswith('CVE ID'))
    field.set_value('CVE-2014-0160').run()
    assert not app.exception
    assert any('OPENSSL_NO_HEARTBEATS' in t.value for t in app.text)
    field.set_value('CVE-2022-37434').run()
    assert any('EXTRA' in t.value for t in app.text)
    assert not any('OPENSSL_NO_HEARTBEATS' in t.value for t in app.text)
    field.set_value('CVE-2099-9999').run()
    assert any('尚無已審查' in t.value for t in app.text)
    assert not any(e.label.startswith('Q1_COMPONENT') for e in app.expander)
    assert not list((tmp_path/'store'/'runs').glob('*.json'))

def test_openssl_explanation_does_not_promote_unknown_or_legacy():
    entry={'cve_id':'CVE-2014-0160','assessment':{'profile_version':'x-runtime-v2','conditions':[]}}
    assert '1.0.1～1.0.1f' in openssl_context(entry,'PC1')
    assert '本次工程證據核對到' not in openssl_context(entry,'PC1')
    assert openssl_context(entry,'PC2')==''
    assert openssl_context(entry,'PC3')==''
    entry['assessment']['profile_version']='legacy'
    assert openssl_context(entry,'PC1')==''
