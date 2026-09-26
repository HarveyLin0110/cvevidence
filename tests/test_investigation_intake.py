import pytest
from cvevidence_core.investigation_intake import prepare,check_existing
from cvevidence_core.sources import read_excerpt
from tests.test_general_triage import context
from tests.test_evidence_requests import request

def test_identity_read_before_model_and_unread_existing_file_blocks_ask(context):
    pre=prepare(context,[])
    assert pre['initial_product_excerpts'][0]['text']
    req=request();req['search_terms']=['main.c']
    with pytest.raises(ValueError,match='未讀材料'):check_existing(context,[req],pre['initial_product_excerpts'])
    sid=context.by_path('source/main.c')[1]['source_id']
    ex=read_excerpt(context,sid)
    with pytest.raises(ValueError,match='已找到材料'):check_existing(context,[req],[ex])
    req['existing_source_ids']=[sid]
    assert check_existing(context,[req],[ex])[0]['unread_matches']==0


def test_unread_declared_source_and_no_reads_rejected(context):
    req=request();req['existing_source_ids']=['S-invented']
    with pytest.raises(ValueError,match='尚未讀取'):check_existing(context,[req],[])
    req['existing_source_ids']=[]
    with pytest.raises(ValueError,match='尚未讀取任何'):check_existing(context,[req],[])
