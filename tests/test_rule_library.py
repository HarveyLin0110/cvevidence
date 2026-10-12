from copy import deepcopy
import hashlib
import pytest
from cvevidence_core.integrity import digest
from cvevidence_core.rule_library import draft,review,install,activate,select,check
from tests.test_condition_plan import conditions,PUBLIC


def investigation():
    sources=[{**PUBLIC[0],'url':'https://example.org/advisory',
        'text_sha256':hashlib.sha256(PUBLIC[0]['text'].encode()).hexdigest()}]
    rows=conditions();rows[0].update(state='OBSERVED_SUPPORT',citations=['X-private'],explanation='PRIVATE_PRODUCT_TEXT')
    r={'cve_id':'CVE-2099-0001','context_hash':'private-scope','condition_plan':{'cve_id':'CVE-2099-0001',
        'conditions':rows,'plan_hash':digest(rows),'context_hash':'private-scope'},'public_sources':{'sources':sources},'excerpts':[{'text':'SECRET_PRODUCT'}]}
    return {**r,'record_hash':digest(r)}


def reviewed():
    return review(draft(investigation()),reviewer='TEST_ONLY',rationale='Test review',
        applicability='TEST_ONLY package',validation_reference='tests/test_rule_library.py')


def test_draft_scrubs_product_results_and_cannot_activate(tmp_path):
    r=draft(investigation())
    assert 'SECRET_PRODUCT' not in str(r) and 'PRIVATE_PRODUCT_TEXT' not in str(r) and 'X-private' not in str(r)
    assert all(x['state']=='NOT_REVIEWED' and not x['citations'] for x in r['conditions'])
    with pytest.raises(ValueError):install(r,tmp_path)


def test_draft_rejects_cross_context_plan_even_with_valid_hashes():
    r=investigation();r['condition_plan']['context_hash']='different-case'
    r['record_hash']=digest({k:v for k,v in r.items() if k!='record_hash'})
    with pytest.raises(ValueError):draft(r)


def test_cli_accepts_ui_download_and_invalid_input_leaves_no_output(tmp_path,monkeypatch):
    import importlib.util
    import json
    from pathlib import Path
    import sys
    spec=importlib.util.spec_from_file_location('rule_cli',Path(__file__).resolve().parents[1]/'scripts/rule_library.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    source=tmp_path/'download.json';output=tmp_path/'draft.json'
    source.write_text(json.dumps({'request':{},'result':{'analyses':[{'ai':investigation()}]}}))
    monkeypatch.setattr(sys,'argv',['rule_library.py','draft',str(source),str(output)])
    module.main();assert check(json.loads(output.read_text()))['status']=='DRAFT'
    rejected=tmp_path/'rejected.json'
    source.write_text(json.dumps({'result':None}))
    monkeypatch.setattr(sys,'argv',['rule_library.py','draft',str(source),str(rejected)])
    with pytest.raises(ValueError):module.main()
    assert not rejected.exists()


def test_versioned_install_activation_stale_and_rollback(tmp_path):
    r=reviewed();install(r,tmp_path);activate(r['cve_id'],r['rule_hash'],tmp_path)
    sources=deepcopy(r['public_sources']);sources[0]['source_id']='P-new'
    selected=select(r['cve_id'],sources,tmp_path)
    assert selected['status']=='CURRENT_REVIEWED_RULE'
    assert selected['conditions'][0]['public_source_id']=='P-new'
    assert not selected['formal_verdict_enabled']
    with pytest.raises(FileExistsError):install(r,tmp_path)
    sources[0]['text']+=' modified'
    assert select(r['cve_id'],sources,tmp_path)['status']=='SOURCE_CHANGED_OR_UNAVAILABLE'
    assert select('CVE-2099-0002',[],tmp_path)['status']=='NO_ACTIVE_RULE'
    r2=reviewed();install(r2,tmp_path);activate(r2['cve_id'],r2['rule_hash'],tmp_path)
    activate(r['cve_id'],r['rule_hash'],tmp_path)
    assert select(r['cve_id'],r['public_sources'],tmp_path)['rule_hash']==r['rule_hash']


def test_tamper_unknown_paths_and_missing_review_fail_closed(tmp_path):
    r=reviewed();p=install(r,tmp_path);activate(r['cve_id'],r['rule_hash'],tmp_path)
    p.write_text('{}')
    assert select(r['cve_id'],r['public_sources'],tmp_path)['status']=='INVALID_RULE'
    with pytest.raises(ValueError):activate('../bad','a'*64,tmp_path)
    with pytest.raises(ValueError):activate(r['cve_id'],'../bad',tmp_path)
    with pytest.raises(ValueError):review(draft(investigation()),reviewer='',rationale='r',applicability='a',validation_reference='t')


def test_outcome_distinguishes_incomplete_capability_material_and_support():
    from cvevidence_core.investigation_outcome import summarize
    r=investigation();r['condition_plan']['context_hash']=r['context_hash'];r['status']='COMPLETED'
    for state,status in [('CAPABILITY_GAP','CAPABILITY_GAP'),('USER_MATERIAL_MISSING','NEEDS_MATERIAL'),
                         ('OBSERVED_SUPPORT','SUPPORT_OBSERVED'),('OBSERVED_EXCLUSION','EXCLUSION_OBSERVED'),('CONFLICT','CONFLICT')]:
        for row in r['condition_plan']['conditions']:row['state']=state
        r['condition_plan']['plan_hash']=digest(r['condition_plan']['conditions'])
        assert summarize(r)['status']==status
    r['status']='TIMED_OUT';assert summarize(r)['status']=='INCOMPLETE'
    r['condition_plan']['plan_hash']='forged';assert summarize(r)['status']=='NOT_ANALYZED'


@pytest.mark.parametrize('close_fails',[False,True])
def test_active_rule_reads_current_product_and_preserves_revision_after_review(tmp_path,monkeypatch,close_fails):
    from tests.test_turnkey import context
    from tests.test_general_triage import public_record
    from tests.test_ai_provider_core import SimulatedProvider,decision
    from cvevidence_core.ai import investigate
    from cvevidence_core.queries import collect_evidence
    from cvevidence_core.verifier import verify
    from cvevidence_core.assessment import assess
    from cvevidence_core.investigation_outcome import summarize
    c=context(tmp_path,[('current.c',b'/* TEST_ONLY current product bytes */\n')])
    rule=reviewed();library=tmp_path/'rules';install(rule,library);activate(rule['cve_id'],rule['rule_hash'],library)
    monkeypatch.setenv('CVEVIDENCE_RULE_LIBRARY',str(library))
    monkeypatch.setattr('cvevidence_core.public_sources.collect',lambda *a,**kw:{'sources':rule['public_sources']})
    v=verify(c,collect_evidence(c,rule['cve_id']));sid=c.by_path('current.c')[1]['source_id']
    def review_step(kwargs):
        x=kwargs['history'][-1]['result']['excerpt_id']
        rows=deepcopy(rule['conditions'])
        for row in rows:row.update(state='OBSERVED_SUPPORT',citations=[x],explanation='TEST_ONLY 模擬觀察，不是真實漏洞證明')
        return decision('REVIEW',conditions=rows)
    def complete_step(kwargs):
        x=kwargs['history'][0]['result']['excerpt_id']
        return decision('COMPLETE',citations=[x],finding='TEST_ONLY 仍須工程覆核，規則版本 '+rule['rule_hash'])
    provider=SimulatedProvider([decision('READ',source_ids=[sid],end_line=1),review_step,complete_step])
    if close_fails:
        def bad_close():raise RuntimeError('TEST_ONLY cleanup')
        provider.close=bad_close
    result=investigate(c,v,assess(c,v),mode='LIVE',provider=provider,public_record=public_record(rule['cve_id']))
    assert [t['action'] for t in result['tasks']]==['READ','REVIEW','COMPLETE']
    assert result['condition_plan']['origin']=='REVIEWED_INVESTIGATION_RULE'
    assert result['condition_plan']['rule_hash']==rule['rule_hash']
    assert result['condition_plan']['context_hash']==c.context_hash
    assert result['investigation_outcome']==summarize(result)
    assert result['investigation_outcome']['status']==('INCOMPLETE' if close_fails else 'SUPPORT_OBSERVED')
    assert result['status']==('FAILED' if close_fails else 'COMPLETED')
