import json
import pytest
from cvevidence_core import sources
from cvevidence_core.integrity import ingest_package,scan,file_hash,IntegrityError


def context(tmp_path, files):
    (tmp_path/'artifact.bin').write_bytes(b'TEST_ONLY')
    for name,data in files.items():
        p=tmp_path/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
    manifest={'schema_version':'1.0','format':'cmake','package_id':'TEST_ONLY','product_id':'TEST_ONLY',
        'release_id':'test','build_id':'test','primary_artifact':{'path':'artifact.bin','sha256':file_hash(tmp_path/'artifact.bin')},
        'files':scan(tmp_path)}
    (tmp_path/'manifest.json').write_text(json.dumps(manifest))
    return ingest_package(tmp_path)


def ids(ctx,*paths):return [ctx.by_path(p)[1]['source_id'] for p in paths]


def test_many_first_file_hits_do_not_hide_second_copy(tmp_path):
    ctx=context(tmp_path,{'sdk/current/zip.c':b'target patched\n'*12,'sdk/legacy/zip.c':b'target old\n'})
    selected=ids(ctx,'sdk/current/zip.c','sdk/legacy/zip.c')
    result=sources.search_sources(ctx,'target',selected,8)
    assert [x['source_id'] for x in result['matches'][:2]]==selected
    assert len(result['matches'])==8 and result['total_matching_lines']==13
    assert result['matching_file_count']==2 and result['truncated']
    assert not result['scope_covers_all_files'] and not result['coverage_limited']
    assert all(sources.verify_excerpt(ctx,x) for x in result['matches'])


def test_more_matching_files_than_snippets_still_disclosed(tmp_path):
    ctx=context(tmp_path,{f'copy{i}.c':b'target\n' for i in range(4)})
    result=sources.search_sources(ctx,'TARGET',limit=2)
    assert result['matching_file_count']==len(result['matching_sources'])==4
    assert result['scope_covers_all_files'] and result['unsearched_file_count']==0
    assert not result['coverage_limited'] and result['truncated']


def test_scan_file_and_byte_budgets_disclose_unsearched(tmp_path,monkeypatch):
    ctx=context(tmp_path,{'a.c':b'hit\n','b.c':b'hit\n'})
    selected=ids(ctx,'a.c','b.c')
    monkeypatch.setattr(sources,'MAX_SEARCH_FILES',1)
    result=sources.search_sources(ctx,'hit',selected)
    assert result['searched_file_count']==1 and result['unsearched_file_count']==1
    assert result['coverage_limited']
    monkeypatch.setattr(sources,'MAX_SEARCH_FILES',500)
    monkeypatch.setattr(sources,'MAX_SEARCH_BYTES',5)
    result=sources.search_sources(ctx,'hit',selected)
    assert result['searched_bytes']==4 and result['unsearched_file_count']==1


def test_nontext_and_oversized_files_are_not_absence_claims(tmp_path,monkeypatch):
    ctx=context(tmp_path,{'binary.bin':b'\0target','large.c':b'target\n'*5,'small.c':b'target\n'})
    monkeypatch.setattr(sources,'MAX_TEXT_BYTES',10)
    result=sources.search_sources(ctx,'target',ids(ctx,'binary.bin','large.c','small.c'))
    assert result['skipped_nontext_or_large']==2 and result['coverage_limited']
    assert result['matching_file_count']==1 and result['unsearched_file_count']==0


def test_later_corrupt_copy_not_hidden_by_first_file_limit(tmp_path):
    ctx=context(tmp_path,{'a.c':b'target\n'*10,'b.c':b'target\n'})
    (tmp_path/'b.c').write_bytes(b'changed')
    with pytest.raises(IntegrityError):sources.search_sources(ctx,'target',ids(ctx,'a.c','b.c'),2)


def test_duplicate_ids_and_exact_match_limit_are_not_false_truncation(tmp_path):
    ctx=context(tmp_path,{'a.c':b'target\n'})
    selected=ids(ctx,'a.c')*3
    result=sources.search_sources(ctx,'target',selected,1)
    assert len(result['matches'])==1 and result['scope_file_count']==1
    assert not result['truncated']
