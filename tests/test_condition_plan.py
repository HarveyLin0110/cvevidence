from copy import deepcopy
import pytest
from cvevidence_core.condition_plan import validate

PUBLIC=[{'source_id':'P-test','text':'TEST_ONLY cookie parsing must reject invalid bytes.'}]

def conditions():
    return [{'condition_id':f'C{i}','layer':layer,'requirement':'TEST_ONLY 必要條件','exclusion':'有修補可排除',
        'check':'讀取實作','public_source_id':'P-test','public_quote':'cookie parsing must reject invalid bytes.',
        'state':'NOT_REVIEWED','citations':[],'explanation':'待讀產品原文'} for i,layer in enumerate(['PC1','PC2','PC3'],1)]

def test_plan_and_review_separate_observations_from_facts():
    plan=validate(conditions(),PUBLIC)
    updated=deepcopy(plan); updated[0].update(state='OBSERVED_EXCLUSION',citations=['X-real'],explanation='原文顯示修補，待覆核')
    assert validate(updated,PUBLIC,previous=plan)[0]['state']=='OBSERVED_EXCLUSION'
    assert plan[0]['state']=='NOT_REVIEWED'

@pytest.mark.parametrize('mutation',['quote','pc','fact','redefine','remove'])
def test_reject_ungrounded_or_redefined_conditions(mutation):
    plan=conditions(); row=deepcopy(plan)
    if mutation=='quote':row[0]['public_quote']='invented quote'
    if mutation=='pc':row[2]['layer']='PC2'
    if mutation=='fact':row[0]['state']='OBSERVED_SUPPORT'
    if mutation=='redefine':row[0]['requirement']='changed condition'
    if mutation=='remove':row.pop()
    with pytest.raises(ValueError):validate(row,PUBLIC,previous=plan)


def test_generic_depth_budget_is_shared_and_bounded(tmp_path):
    from unittest.mock import patch
    from tests.test_general_triage import public_record
    from cvevidence_core.integrity import scan, file_hash, ingest_package
    from cvevidence_core.workflow import analyze_package, investigate_after_engineering
    import json
    (tmp_path/'artifact.bin').write_bytes(b'TEST_ONLY')
    manifest={'schema_version':'1.0','package_id':'test','product_id':'test','release_id':'r','build_id':'b','format':'cmake',
        'primary_artifact':{'path':'artifact.bin','sha256':file_hash(tmp_path/'artifact.bin')},'files':scan(tmp_path)}
    (tmp_path/'manifest.json').write_text(json.dumps(manifest))
    context=ingest_package(tmp_path)
    with patch('cvevidence_core.public_cve.lookup',return_value=public_record()):saved=analyze_package(context,['CVE-2024-1179'])
    for outer, expected in [(300,240),(20,20)]:
        with patch('cvevidence_core.workflow.investigate',return_value={'status':'CONFIG_REQUIRED'}) as call:
            investigate_after_engineering(context,saved,analysis_depth='pc',timeout_seconds=outer)
        assert 0<call.call_args.kwargs['timeout_seconds']<=expected
        assert call.call_args.kwargs['max_calls']==12


def test_quote_failure_returns_bounded_exact_source_hints_without_acceptance():
    from cvevidence_core.condition_plan import QuoteMismatch
    rows=conditions();rows[1]['public_quote']='cookie parsing is now completely safe'
    before=deepcopy(rows)
    source={'source_id':'P-test','text':'Unrelated introductory text.\nTEST_ONLY cookie parsing must reject invalid bytes.\n'+'z'*200000}
    with pytest.raises(QuoteMismatch) as caught:validate(rows,[source])
    hint=caught.value.feedback
    assert not hint['accepted'] and hint['condition_id']=='C2'
    assert 1<=len(hint['candidate_quotes'])<=3
    assert sum(len(q['text']) for q in hint['candidate_quotes'])<=1800
    for q in hint['candidate_quotes']:
        assert source['text'][q['start_char']:q['start_char']+len(q['text'])]==q['text']
    assert rows==before
    with pytest.raises(QuoteMismatch):validate(rows,[source])


def test_unknown_public_source_does_not_suggest_another_sources_text():
    from cvevidence_core.condition_plan import QuoteMismatch
    rows=conditions();rows[0]['public_source_id']='P-unknown'
    with pytest.raises(QuoteMismatch) as caught:validate(rows,PUBLIC)
    assert not caught.value.feedback['source_known']
    assert caught.value.feedback['candidate_quotes']==[]
