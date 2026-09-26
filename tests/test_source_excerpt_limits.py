import pytest
from cvevidence_core import sources
from tests.test_source_search_coverage import context, ids


def test_utf8_limit_and_historical_exact_verification(tmp_path):
    ctx=context(tmp_path,{'a.c':('中'*8001).encode()})
    sid=ids(ctx,'a.c')[0]
    original=sources.read_excerpt(ctx,sid,1,1)
    assert sources.verify_excerpt(ctx,original)
    with pytest.raises(sources.ExcerptTooLarge,match='CAPABILITY_GAP'):
        sources.read_bounded_excerpt(ctx,sid,1,1)
    assert sources.verify_excerpt(ctx,original)


def test_neighbor_too_large_keeps_exact_matching_line(tmp_path):
    ctx=context(tmp_path,{'a.c':b'x'*24001+b'\ntarget fixed\n'})
    result=sources.search_sources(ctx,'target',ids(ctx,'a.c'))
    excerpt=result['matches'][0]
    assert excerpt['start_line']==excerpt['end_line']==2
    assert excerpt['text']=='target fixed' and sources.verify_excerpt(ctx,excerpt)
    assert result['omitted_excerpt_count']==0


def test_giant_matching_line_does_not_hide_other_copy(tmp_path):
    ctx=context(tmp_path,{'a.c':b'target'+b'x'*24001,'b.c':b'target readable'})
    result=sources.search_sources(ctx,'target',ids(ctx,'a.c','b.c'))
    assert result['matching_file_count']==2 and len(result['matches'])==1
    assert result['omitted_excerpt_count']==1 and result['truncated']
    assert result['omitted_excerpts'][0]['reason']=='SINGLE_LINE_BYTE_LIMIT'
    assert result['matches'][0]['text']=='target readable'


def test_total_budget_keeps_later_small_match(tmp_path,monkeypatch):
    ctx=context(tmp_path,{'a.c':b'target'+b'x'*100,'b.c':b'target'+b'x'*100,'c.c':b'target'})
    monkeypatch.setattr(sources,'MAX_SEARCH_RESULT_BYTES',115)
    result=sources.search_sources(ctx,'target',ids(ctx,'a.c','b.c','c.c'))
    assert result['excerpt_bytes']==112 and len(result['matches'])==2
    assert result['omitted_excerpts'][0]['reason']=='SEARCH_RESULT_BYTE_LIMIT'
    assert all(sources.verify_excerpt(ctx,e) for e in result['matches'])


def test_compare_never_returns_partial_giant_line(tmp_path):
    ctx=context(tmp_path,{'a.c':b'x'*24001,'b.c':b'y'*24001})
    result=sources.compare_sources(ctx,*ids(ctx,'a.c','b.c'))
    assert result['truncated'] and not result['identical_bytes']
    assert len(result['diff'].encode())<=24000
    assert 'xxx' not in result['diff'] and 'yyy' not in result['diff']


def test_exact_boundary_read(tmp_path):
    ctx=context(tmp_path,{'a.c':b'x'*24000})
    excerpt=sources.read_bounded_excerpt(ctx,ids(ctx,'a.c')[0],1,1)
    assert len(excerpt['text'])==24000 and sources.verify_excerpt(ctx,excerpt)
