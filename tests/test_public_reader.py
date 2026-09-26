import hashlib
import pytest
from cvevidence_core.public_reader import read,search
from cvevidence_core.public_packet import compact
from cvevidence_core.integrity import IntegrityError


def bundle(text):
    return {'sources':[{'source_id':'P-test','url':'https://example.com/test',
                       'text':text,'text_sha256':hashlib.sha256(text.encode()).hexdigest(),'truncated':False}]}


def test_search_and_read_recover_saved_detail_omitted_from_model_packet():
    data=bundle(('p'*149+'\n')*40+'target_condition = check_length(input)\nreturn reject\n')
    packet=compact(data)
    assert 'target_condition' not in packet['sources'][0]['text']
    assert packet['sources'][0]['total_saved_lines']==42
    found=search(data,[],'target_condition')['public_matches'][0]
    assert found['line']==41
    excerpt=read(data,found['public_source_id'],41,42)
    assert excerpt['text']=='target_condition = check_length(input)\nreturn reject'
    assert 'excerpt_id' not in excerpt and 'matches' not in search(data,[],'target_condition')
    assert excerpt['role']=='PUBLIC_REFERENCE_NOT_PRODUCT_EVIDENCE'


def test_source_scope_and_saved_hash_checked():
    data=bundle('TEST_ONLY')
    for sid in ['S-product','https://example.com/test','P-other']:
        with pytest.raises(ValueError):read(data,sid,1,1)
    data['sources'][0]['text']='changed'
    with pytest.raises(IntegrityError):read(data,'P-test',1,1)
    with pytest.raises(IntegrityError):search(data,[],'changed')


@pytest.mark.parametrize('start,end',[(0,1),(2,1),(1,201),(True,1),(4,4)])
def test_invalid_public_ranges_rejected(start,end):
    with pytest.raises(ValueError):read(bundle('a\nb'),'P-test',start,end)


def test_long_lines_search_and_byte_limits_are_explicit():
    data=bundle('目標'+'中'*3000)
    found=search(data,[],'目標')['public_matches'][0]
    assert found['line_truncated'] and len(found['text'])==700
    with pytest.raises(ValueError,match='8000'):read(data,'P-test',1,1)
    results=search(bundle('target\n'*10),['P-test','P-test'],'target')
    assert len(results['public_matches'])==8 and results['matches_limited']


def test_snapshot_truncation_remains_visible_and_no_match_is_not_proof():
    data=bundle('TEST_ONLY');data['sources'][0]['truncated']=True
    assert read(data,'P-test',1,10)['snapshot_truncated']
    assert not search(data,[],'absent')['public_matches']
    with pytest.raises(ValueError):search(data,[],'')
