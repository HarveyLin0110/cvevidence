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
