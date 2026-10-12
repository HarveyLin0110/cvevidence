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


def previous_reads(ctx,excerpts,tasks,retained=()):
    from cvevidence_core.integrity import digest
    from cvevidence_core.condition_plan import record
    from .test_condition_plan import conditions
    previous={'cve_id':'CVE-2024-1179','condition_plan':record(ctx,'CVE-2024-1179',conditions()),
              'excerpts':excerpts,'tasks':tasks,'retained_read_excerpt_ids':list(retained)}
    previous['record_hash']=digest(previous)
    return previous


@pytest.mark.parametrize('action,status,allowed',[
    ('READ','COMPLETED',True),('READ','TOOL_ERROR',False),('SEARCH','COMPLETED',False)])
def test_continuation_counts_only_verified_successful_reads(tmp_path,action,status,allowed):
    from cvevidence_core.investigation_control import continuation
    ctx=context(tmp_path,{'a/zip.c':b'target old','b/zip.c':b'target fixed'})
    a,b=ids(ctx,'a/zip.c','b/zip.c');excerpts=[read_excerpt(ctx,sid,1,1) for sid in (a,b)]
    previous=previous_reads(ctx,excerpts,[{'action':action,'status':status,'result':x} for x in excerpts])
    resumed=continuation(ctx,'CVE-2024-1179',previous)
    retained=[x for x in resumed['excerpts'] if x['excerpt_id'] in resumed['retained_read_excerpt_ids']]
    tasks=[{'action':'SEARCH','status':'COMPLETED','result':search_sources(ctx,'target',[a,b])}]
    if allowed:
        assert check_copy_reads(ctx,tasks,retained)['unread_copy_count']==0
        # Another continuation keeps provenance without requiring duplicate READs.
        again=continuation(ctx,'CVE-2024-1179',previous_reads(ctx,excerpts,[],resumed['retained_read_excerpt_ids']))
        assert again['retained_read_excerpt_ids']==resumed['retained_read_excerpt_ids']
    else:
        assert not retained
        with pytest.raises(ValueError):check_copy_reads(ctx,tasks,retained)


def test_changed_source_cannot_reuse_old_successful_read(tmp_path):
    from cvevidence_core.investigation_control import continuation
    for name in ('old','new'):(tmp_path/name).mkdir()
    old=context(tmp_path/'old',{'a/zip.c':b'target old','b/zip.c':b'target fixed'})
    excerpts=[read_excerpt(old,sid,1,1) for sid in ids(old,'a/zip.c','b/zip.c')]
    previous=previous_reads(old,excerpts,[{'action':'READ','status':'COMPLETED','result':x} for x in excerpts])
    new=context(tmp_path/'new',{'a/zip.c':b'target changed','b/zip.c':b'target fixed'})
    resumed=continuation(new,'CVE-2024-1179',previous)
    retained=[x for x in resumed['excerpts'] if x['excerpt_id'] in resumed['retained_read_excerpt_ids']]
    assert len(retained)==1
    tasks=[{'action':'SEARCH','status':'COMPLETED','result':search_sources(new,'target')}]
    with pytest.raises(ValueError,match='a/zip.c'):check_copy_reads(new,tasks,retained)


def test_forged_retained_read_is_rejected(tmp_path):
    from cvevidence_core.integrity import IntegrityError
    ctx=context(tmp_path,{'zip.c':b'target'})
    excerpt=read_excerpt(ctx,ids(ctx,'zip.c')[0],1,1)
    with pytest.raises(IntegrityError):check_copy_reads(ctx,[],[{**excerpt,'text':'forged'}])
