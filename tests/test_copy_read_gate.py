import pytest
from cvevidence_core.investigation_intake import check_copy_reads
from .test_source_search_coverage import context,ids
from cvevidence_core.sources import search_sources,read_excerpt


def test_search_headers_cannot_replace_reading_second_copy_before_asking(tmp_path):
    ctx=context(tmp_path,{'current/zip.c':b'function header\npatched body\n',
                          'legacy/zip.c':b'function header\nunpatched body\n'})
    current,legacy=ids(ctx,'current/zip.c','legacy/zip.c')
    tasks=[{'action':'SEARCH','status':'COMPLETED','result':search_sources(ctx,'function',[current,legacy])},
           {'action':'READ','status':'COMPLETED','result':read_excerpt(ctx,current,1,2)}]
    with pytest.raises(ValueError,match='legacy/zip.c'):check_copy_reads(ctx,tasks)
    tasks.append({'action':'READ','status':'TOOL_ERROR','result':{'source_id':legacy}})
    with pytest.raises(ValueError,match='legacy/zip.c'):check_copy_reads(ctx,tasks)
    tasks.append({'action':'READ','status':'COMPLETED','result':read_excerpt(ctx,legacy,1,2)})
    result=check_copy_reads(ctx,tasks)
    assert result['matched_copy_count']==2 and result['unread_copy_count']==0
    assert result['semantic_sufficiency_verified'] is False


def test_single_copy_or_repeated_data_files_do_not_trigger_code_copy_gate(tmp_path):
    ctx=context(tmp_path,{'zip.c':b'target','a/notes.txt':b'target','b/notes.txt':b'target'})
    tasks=[{'action':'SEARCH','status':'COMPLETED','result':search_sources(ctx,'target')}]
    assert check_copy_reads(ctx,tasks)['matched_copy_count']==0


def test_reading_other_source_does_not_satisfy_copy_gate(tmp_path):
    ctx=context(tmp_path,{'a/source.c':b'target','b/source.c':b'target','other.c':b'other'})
    a,b,other=ids(ctx,'a/source.c','b/source.c','other.c')
    tasks=[{'action':'SEARCH','status':'COMPLETED','result':search_sources(ctx,'target',[a,b])},
           {'action':'READ','status':'COMPLETED','result':read_excerpt(ctx,other,1,1)}]
    with pytest.raises(ValueError):check_copy_reads(ctx,tasks)
