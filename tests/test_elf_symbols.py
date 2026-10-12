"""Dynamic references are structural clues, never call-path or exclusion proof."""
import shutil
import struct
import subprocess
import pytest
from cvevidence_core.elf_metadata import inspect


def elf(bits=64,endian='<',count=1,bad_link=False):
    wide=bits==64;eh=64 if wide else 52;sh=64 if wide else 40;entry=24 if wide else 16
    strings=b'\0target_api\0own_function\0';strings_offset=eh+3*sh;symbols_offset=strings_offset+len(strings)
    ident=b'\x7fELF'+bytes([2 if wide else 1,1 if endian=='<' else 2,1])+b'\0'*9
    header=struct.pack(endian+('HHIQQQIHHHHHH' if wide else 'HHIIIIIHHHHHH'),3,8,1,0,0,eh,0,eh,0,0,sh,3,0)
    def symbol(name,section,binding=1):
        return struct.pack(endian+('IBBHQQ' if wide else 'IIIBBH'),
                           *((name,(binding<<4)|2,0,section,0,0) if wide else (name,0,0,(binding<<4)|2,0,section)))
    symbols=b'\0'*entry+symbol(1,0)*count+symbol(12,0xfff1)
    def section(kind,offset,length,link=0,entsize=0):
        return struct.pack(endian+('IIQQQQIIQQ' if wide else 'IIIIIIIIII'),0,kind,0,0,offset,length,link,0,1,entsize)
    sections=b'\0'*sh+section(3,strings_offset,len(strings))+section(11,symbols_offset,len(symbols),99 if bad_link else 1,entry)
    return ident+header+sections+strings+symbols


@pytest.mark.parametrize('bits,endian',[(32,'<'),(32,'>'),(64,'<'),(64,'>')])
def test_section_symbols_across_architectures(tmp_path,bits,endian):
    path=tmp_path/'a';path.write_bytes(elf(bits,endian));s=inspect(path)['symbols']
    assert s['imports']==[{'name':'target_api','type':2,'binding':1}]
    assert s['definitions']==[{'name':'own_function','type':2,'binding':1}]
    assert s['status']=='READ' and not s['coverage_limited']
    assert not s['runtime_binding_verified'] and not s['call_path_verified']


def test_malformed_symbol_table_preserves_other_metadata(tmp_path):
    path=tmp_path/'a';path.write_bytes(elf(bad_link=True));row=inspect(path)
    assert row['class_bits']==64 and row['symbols']['status']=='UNSUPPORTED_OR_LIMITED'
    assert row['symbols']['imports']==[] and row['symbols']['coverage_limited']


def test_symbols_truncated_with_total_count(tmp_path):
    path=tmp_path/'a';path.write_bytes(elf(count=140));s=inspect(path)['symbols']
    assert len(s['imports'])==128 and s['counts']['imports']==140 and s['coverage_limited']


def test_missing_sections_do_not_imply_absence(tmp_path):
    from tests.test_elf_metadata import example
    path=tmp_path/'a';path.write_bytes(example());row=inspect(path)
    assert row['needed']==['libtest.so.1']
    assert row['symbols']['status']=='NO_SECTION_TABLE' and row['symbols']['coverage_limited']


def compiled(tmp_path):
    if not shutil.which('cc') or not shutil.which('readelf'):pytest.skip('Compiler/readelf unavailable')
    source=tmp_path/'main.c';source.write_text('#include <stdio.h>\nint main(void){puts("TEST_ONLY");return 0;}\n')
    binary=tmp_path/'probe';subprocess.run(['cc',str(source),'-o',str(binary)],check=True,capture_output=True)
    return binary


def test_native_symbols_match_readelf_without_execution(tmp_path):
    binary=compiled(tmp_path)
    text=subprocess.run(['readelf','--dyn-syms','--wide',str(binary)],check=True,capture_output=True,text=True).stdout
    expected=set()
    for line in text.splitlines():
        fields=line.split()
        if len(fields)>=8 and fields[6]=='UND' and fields[4] in ('GLOBAL','WEAK'):
            expected.add(fields[7].split('@')[0])
    actual={s['name'] for s in inspect(binary)['symbols']['imports']}
    assert 'puts' in actual and actual==expected


def test_web_shows_function_reference_and_limitations(tmp_path):
    from cvevidence_core.partial_intake import create
    from cvevidence.runner import Runner
    from cvevidence.storage import RunStore
    from cvevidence.workflow_navigation import PAGES
    from tests.test_package_inventory import inventory_app
    from streamlit.testing.v1 import AppTest
    binary=compiled(tmp_path);create([('bin/probe',binary.read_bytes())],tmp_path/'p.tgz')
    runner=Runner(RunStore(tmp_path/'runtime'));run=runner.start_file(tmp_path/'p.tgz')
    app=AppTest.from_function(inventory_app,default_timeout=30)
    app.session_state['test_store']=str(tmp_path/'runtime');app.session_state['selected_run']=run.run_id
    app.session_state['step']=PAGES[1];app.run();assert not app.exception
    assert any('puts' in str(d.value.to_dict()) and '匯入符號' in str(d.value.to_dict()) for d in app.dataframe)
    assert any('不代表執行時已呼叫' in c.value for c in app.caption)
