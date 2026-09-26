from cvevidence_core.quality import evaluate

def test_metrics_detect_repeat_and_unread_key_path_without_self_grading():
    req={'material':'query.py','condition_id':'C2'}
    old={'tasks':[{'evidence_requests':[req]}]}
    ai={'status':'NEEDS_USER_INPUT','mode':'SIMULATED','calls':[{}],
        'tasks':[{'status':'COMPLETED','action':'ASK_USER','evidence_requests':[req]}],
        'condition_dossier':{'conditions':[{'layer':'PC2','evidence':[{'path':'other.py'}]}]}}
    m=evaluate(ai,expected_paths=['query.py'],previous=old)
    assert m['expected_key_paths_missing']==['query.py']
    assert m['repeated_materials']==['query.py']
    assert m['semantic_correctness']=='REQUIRES_INDEPENDENT_REVIEW'


def test_available_read_and_cited_are_distinct_not_understanding_claims():
    ai={'initial_product_excerpts':[{'source_id':'S-initial'}],
        'excerpts':[{'source_id':'S-initial'},{'source_id':'S-read'},{'source_id':'S-search'}],
        'tasks':[{'action':'READ','status':'COMPLETED','result':{'source_id':'S-read'}},
                 {'action':'READ','status':'TOOL_ERROR','result':{'source_id':'S-failed'}},
                 {'action':'PLAN','status':'TOOL_ERROR'}],
        'condition_dossier':{'conditions':[{'layer':'PC2','evidence':[{'source_id':'S-search','path':'config'}]}]}}
    m=evaluate(ai,expected_paths=['config','unused-source'])
    assert m['available_excerpt_source_ids']==['S-initial','S-read','S-search']
    assert m['explicit_read_source_ids']==['S-read']
    assert m['condition_cited_source_ids']==['S-search']
    assert m['available_but_not_condition_cited_source_ids']==['S-initial','S-read']
    assert m['expected_key_paths_found']==['config']
    assert m['expected_key_paths_missing']==['unused-source']
    assert m['failed_steps_by_action']=={'READ':1,'PLAN':1}
    assert m['semantic_correctness']=='REQUIRES_INDEPENDENT_REVIEW'


def test_legacy_record_without_excerpt_fields_remains_measurable():
    result=evaluate({'tasks':[],'condition_dossier':None})
    assert result['available_excerpt_source_ids']==[]
    assert result['explicit_read_source_ids']==[]
    assert result['failed_steps_by_action']=={}
