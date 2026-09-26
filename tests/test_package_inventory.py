"""TEST_ONLY inventory declarations; no device or CVE impact assertions."""
import pytest
from cvevidence_core.package_inventory import parse
from cvevidence_core.partial_intake import create
from cvevidence_core.integrity import safe_extract, ingest_package
from cvevidence_core.component_discovery import discover
from cvevidence_core.catalog import discover_candidates


def test_list_preserves_vendor_version_and_lines():
    rows=parse(['','curl - 8.3.0-vendor2','libc - 1.2.4-4'])
    assert rows[0]['version']=='8.3.0-vendor2'
    assert rows[0]['start_line']==rows[0]['end_line']==2
    assert len(rows)==2


@pytest.mark.parametrize('value',[
    'curl - 8.3.0\nrun this command',
    'Package: curl\nVersion: 8.3.0\nStatus: deinstall ok not-installed',
    'Package: curl\nVersion: 8.3.0\nVersion: 9.0\nStatus: install ok installed',
    'Package: curl\nVersion: 8.3.0',
])
def test_ambiguous_or_not_installed_is_not_inventory(value):
    assert parse(value.splitlines())==[]


def test_control_stanza_and_bounded_count():
    rows=parse('Package: curl\nVersion: 8.3.0-1\nStatus: install user installed\nDescription: test\n continuation\n'.splitlines())
    assert rows[0]['end_line']==5
    assert rows[0]['inventory_format']=='INSTALLED_CONTROL_STANZA'
    assert len(parse([f'pkg{i} - 1.0' for i in range(150)]))==100


def test_partial_inventory_enters_candidates_but_is_not_sent_as_guessed_ecosystem(tmp_path):
    create([('opkg-list-installed.txt',b'curl - 8.3.0-vendor2\n')],tmp_path/'p.tgz')
    safe_extract(tmp_path/'p.tgz',tmp_path/'p'); context=ingest_package(tmp_path/'p')
    local=discover_candidates(context)
    assert not local['intake_questions']
    item=local['candidates'][0]
    assert item['assessment'] is None
    assert item['match_basis'][0]['version_hint']=='VERSION_UNRESOLVED'
    assert local['components'][0]['identity_verified'] is False
    def no_network(*args):
        pytest.fail('Package ecosystem must not be guessed')
    result=discover(context,consent=True,transport=no_network)
    assert result['status']=='NO_SUPPORTED_COMPONENT_IDENTITY'
    assert result['components'][0]['start_line']==1
    from cvevidence_core.investigation_intake import prepare,check_existing
    from cvevidence_core.general_triage import plan
    ready=prepare(context,[])
    assert ready['component_declarations'][0]['version']=='8.3.0-vendor2'
    assert ready['initial_product_excerpts'][0]['text']=='curl - 8.3.0-vendor2'
    assert ready['source_index'][0]['path']=='opkg-list-installed.txt'
    assert plan('CVE-2024-42005',context)['queries'][0]['available_source_count']==1
    # A blanket claim that this already-read inventory is missing is rejected.
    with pytest.raises(ValueError,match='已找到材料'):
        check_existing(context,[{'existing_source_ids':[],'search_terms':['opkg-list-installed.txt']}],ready['initial_product_excerpts'])


def inventory_app():
    import streamlit as st
    from cvevidence.workspace import workspace
    workspace(st,store_root=st.session_state['test_store'])


def test_inventory_web_table_preserves_versions_and_source_paths(tmp_path):
    from streamlit.testing.v1 import AppTest
    from cvevidence.runner import Runner
    from cvevidence.storage import RunStore
    create([('opkg-list-installed.txt',b'curl - 8.3.0-vendor2\n')],tmp_path/'p.tgz')
    runner=Runner(RunStore(tmp_path/'runtime'))
    run=runner.start_file(tmp_path/'p.tgz')
    app=AppTest.from_function(inventory_app,default_timeout=20)
    app.session_state['test_store']=str(tmp_path/'runtime')
    app.session_state['selected_run']=run.run_id
    app.run()
    next(b for b in app.button if b.label=='02 資料確認與缺件').click().run()
    assert not app.exception
    rows=app.dataframe[0].value.to_dict('records')
    assert rows[0]['版本聲明']=='8.3.0-vendor2'
    assert rows[0]['來源']=='opkg-list-installed.txt'
    assert rows[0]['原文行']=='1–1'
