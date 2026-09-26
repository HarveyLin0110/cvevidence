import json
import pytest
from cvevidence_core.compilation_database import inspect
from cvevidence_core.integrity import IntegrityError
from .test_source_search_coverage import context,ids


def entry(file='sdk/legacy/zip.c',**extra):
    return {'directory':'/builder/project','file':file,'arguments':['cc','-c',file],**extra}


def setup(tmp_path,entries):
    raw=entries if isinstance(entries,bytes) else json.dumps(entries).encode()
    return context(tmp_path,{'sdk/current/zip.c':b'current','sdk/legacy/zip.c':b'legacy',
                             'build/compile_commands.json':raw})


def test_exact_suffix_selects_declared_candidate_not_executed_build(tmp_path):
    ctx=setup(tmp_path,[entry(output='obj/legacy.o')]);result=inspect(ctx)
    row=result['records'][0]['entries'][0]
    assert row['candidate_source_ids']==ids(ctx,'sdk/legacy/zip.c')
    assert row['state']=='PATH_SUFFIX_CANDIDATE' and row['declared_output']=='obj/legacy.o'
    assert not row['command_executed'] and not row['artifact_binding_verified']
    assert not row['command_file_consistency_verified']
    from cvevidence_core.catalog import discover_candidates
    from cvevidence_core.investigation_intake import prepare
    assert discover_candidates(ctx)['compilation_database']==result
    assert prepare(ctx,[])['compilation_database']==result


def test_basename_only_is_ambiguous_and_multiple_configurations_preserved(tmp_path):
    ctx=setup(tmp_path,[entry('zip.c'),entry('zip.c',output='other.o')])
    rows=inspect(ctx)['records'][0]['entries']
    assert len(rows)==2
    assert all(r['state']=='AMBIGUOUS_PATH_CANDIDATES' and r['candidate_count']==2 for r in rows)


def test_declared_commands_and_host_paths_never_executed_or_opened(tmp_path):
    marker=tmp_path/'must-not-exist'
    row={'directory':'/','file':'/etc/passwd','command':f'touch {marker}'}
    ctx=setup(tmp_path,[row]);result=inspect(ctx)['records'][0]['entries'][0]
    assert result['state']=='NOT_IN_DELIVERED_PATHS'
    assert result['command_form']=='COMMAND' and 'command' not in result
    assert not marker.exists()


@pytest.mark.parametrize('data',[b'{"bad":true}',b'[{"file":"a","file":"b"}]',b'not-json'])
def test_malformed_database_and_duplicate_keys_reported(tmp_path,data):
    assert inspect(setup(tmp_path,data))['records'][0]['status']=='MALFORMED_DATABASE'


@pytest.mark.parametrize('row',[{},entry(arguments=[]),entry(arguments=[123]),entry(file=4),entry(output=4)])
def test_bad_entries_cannot_be_mistaken_for_missing_sources(tmp_path,row):
    result=inspect(setup(tmp_path,[row]))['records'][0]
    assert result['invalid_entries']==1 and result['coverage_limited']
    assert result['entries'][0]['state']=='MALFORMED_OR_LIMITED_ENTRY'


def test_windows_path_is_explicitly_unsupported(tmp_path):
    row=entry('C:\\sdk\\zip.c',directory='C:\\build')
    result=inspect(setup(tmp_path,[row]))['records'][0]['entries'][0]
    assert result['state']=='UNSUPPORTED_PATH_STYLE' and not result['candidate_source_ids']


def test_limits_and_relevant_entries_beyond_first_page(tmp_path,monkeypatch):
    from cvevidence_core import compilation_database as module
    ctx=setup(tmp_path,[entry(f'unrelated/{i}.c') for i in range(25)]+[entry()])
    result=inspect(ctx,ids(ctx,'sdk/legacy/zip.c'))['records'][0]
    assert result['entries'][0]['entry_index']==26
    assert len(result['entries'])==20 and result['entries_omitted']==6 and result['coverage_limited']
    monkeypatch.setattr(module,'MAX_ENTRIES',2)
    limited=inspect(ctx)['records'][0]
    assert limited['entries_examined']==2 and limited['entries_omitted']==24
    monkeypatch.setattr(module,'MAX_DATABASE_BYTES',1)
    assert inspect(ctx)['records'][0]['status']=='DATABASE_TOO_LARGE'


def test_database_bytes_rechecked_before_parsing(tmp_path):
    ctx=setup(tmp_path,[entry()]);(tmp_path/'build/compile_commands.json').write_text('[]')
    with pytest.raises(IntegrityError):inspect(ctx)


def test_web_labels_declaration_without_claiming_artifact_binding(tmp_path):
    from streamlit.testing.v1 import AppTest
    def page(bundle,paths):
        import streamlit as st
        from cvevidence.compilation_view import render
        render(st,bundle,paths)
    ctx=setup(tmp_path,[entry()]);bundle=inspect(ctx)
    app=AppTest.from_function(page,args=(bundle,{s:r['path'] for s,r in ctx.sources.items()})).run()
    assert not app.exception
    assert any('僅宣告' in x.label for x in app.expander)
    table=str(app.dataframe[0].value.to_dict())
    assert 'sdk/legacy/zip.c' in table and '未認證' in table
    assert any('不證明編譯已執行' in x.value for x in app.caption)


def test_supplement_adds_database_candidates_without_rewriting_parent(tmp_path):
    from cvevidence_core.partial_intake import create
    from cvevidence.runner import Runner
    from cvevidence.storage import RunStore
    create([('sdk/current/zip.c',b'TEST_ONLY current'),('sdk/legacy/zip.c',b'TEST_ONLY legacy')],tmp_path/'base.tgz')
    runner=Runner(RunStore(tmp_path/'runtime'));parent=runner.start_file(tmp_path/'base.tgz')
    before=runner.store._run_path(parent.run_id).read_bytes()
    child=runner.supplement_partial(parent.run_id,[('build/compile_commands.json',json.dumps([entry()]).encode())])
    assert not child.error and child.parent_run_id==parent.run_id
    record=child.candidates['compilation_database']['records'][0]
    assert record['status']=='DECLARATIONS_ONLY' and record['entries'][0]['candidate_count']==1
    assert runner.store._run_path(parent.run_id).read_bytes()==before
    assert not parent.candidates['compilation_database']['records']
