"""A whole tiny input/config is valid evidence; a one-character snippet is not."""
import pytest
from cvevidence_core.evidence_quotes import resolve
from cvevidence_core.sources import read_bounded_excerpt
from tests.test_source_search_coverage import context,ids


def row(x,quote):return {'condition_id':'C1','state':'OBSERVED_SUPPORT','citations':[x['excerpt_id']],
    'evidence_quotes':[{'excerpt_id':x['excerpt_id'],'quote':quote}]}


@pytest.mark.parametrize('content',['4 17','0','false'])
def test_whole_short_file_can_be_cited_without_invented_padding(tmp_path,content):
    c=context(tmp_path,{'runtime/input.txt':(content+'\n').encode()})
    x=read_bounded_excerpt(c,ids(c,'runtime/input.txt')[0],1,10)
    result=resolve(c,row(x,content),{x['excerpt_id']:x},require=True)
    assert result[0]['text']==content and result[0]['start_line']==result[0]['end_line']==1
    assert result[0]['meaning_verified'] is False


@pytest.mark.parametrize('content,quote',[('TEST_ONLY = 0','0'),('0\nTEST_ONLY','0'),('TEST_ONLY\n0','0')])
def test_short_fragment_or_line_is_not_promoted_to_whole_source(tmp_path,content,quote):
    c=context(tmp_path,{'runtime.txt':content.encode()});sid=ids(c,'runtime.txt')[0]
    line=2 if content.startswith('TEST_ONLY\n') else 1
    x=read_bounded_excerpt(c,sid,line,line)
    with pytest.raises(ValueError,match='完整原文'):resolve(c,row(x,quote),{x['excerpt_id']:x},require=True)
