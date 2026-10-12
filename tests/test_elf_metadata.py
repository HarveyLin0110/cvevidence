"""Synthetic cross-architecture ELF plus native compiler comparison; no CVE proof."""
import io
import re
import shutil
import struct
import subprocess
import pytest
from cvevidence_core.elf_metadata import inspect,inventory,ELFError
from cvevidence_core.partial_intake import create
from cvevidence_core.integrity import safe_extract,ingest_package


def example(bits=32,endian='>'):
    wide=bits==64;eh=64 if wide else 52;ph=56 if wide else 32;entry=16 if wide else 8
    dyn=eh+2*ph;string=dyn+4*entry;names=b'\0libtest.so.1\0';size=string+len(names)
    ident=b'\x7fELF'+bytes([2 if wide else 1,1 if endian=='<' else 2,1])+b'\0'*9
    header=struct.pack(endian+('HHIQQQIHHHHHH' if wide else 'HHIIIIIHHHHHH'),3,8,1,0,eh,0,0,eh,ph,2,0,0,0)
    def segment(kind,offset,address,length):
        values=(kind,4,offset,address,0,length,length,1) if wide else (kind,offset,address,0,length,length,4,1)
        return struct.pack(endian+('IIQQQQQQ' if wide else 'IIIIIIII'),*values)
    dynamic=b''.join(struct.pack(endian+('qQ' if wide else 'iI'),tag,value) for tag,value in [(5,0x1000+string),(10,len(names)),(1,1),(0,0)])
    return ident+header+segment(1,0,0x1000,size)+segment(2,dyn,0x1000+dyn,len(dynamic))+dynamic+names


@pytest.mark.parametrize('bits,endian',[(32,'>'),(32,'<'),(64,'>'),(64,'<')])
def test_both_classes_and_byte_orders(tmp_path,bits,endian):
    path=tmp_path/'test';path.write_bytes(example(bits,endian));row=inspect(path)
    assert row['class_bits']==bits and row['machine_id']==8
    assert row['byte_order']==('little' if endian=='<' else 'big')
    assert row['needed']==['libtest.so.1'] and not row['runtime_resolution_verified']


@pytest.mark.parametrize('change',['truncated','bad_index','unmapped','unterminated','too_many'])
def test_malformed_ranges_fail_without_partial_metadata(tmp_path,change):
    data=bytearray(example());dyn=52+64
    if change=='truncated':data=data[:-3]
    if change=='bad_index':struct.pack_into('>I',data,dyn+20,99999)
    if change=='unmapped':struct.pack_into('>I',data,dyn+4,99999)
    if change=='unterminated':struct.pack_into('>i',data,dyn+24,1)
    if change=='too_many':struct.pack_into('>H',data,44,65535)
    path=tmp_path/'test';path.write_bytes(data)
    with pytest.raises(ELFError):inspect(path)


def test_native_compiler_metadata_matches_readelf(tmp_path):
    if not shutil.which('cc') or not shutil.which('readelf'):pytest.skip('Native compiler/readelf not installed')
    source=tmp_path/'test.c';source.write_text('#include <stdio.h>\nint main(void){puts("TEST_ONLY");return 0;}\n')
    binary=tmp_path/'test';subprocess.run(['cc',str(source),'-o',str(binary)],check=True,capture_output=True)
    expected=subprocess.run(['readelf','-d',str(binary)],check=True,capture_output=True,text=True).stdout
    assert inspect(binary)['needed']==re.findall(r'\(NEEDED\).*?\[([^\]]+)\]',expected)
    # The target program is never executed.


def context(tmp_path):
    create([('usr/bin/test',example()),('fake.so',b'not ELF')],tmp_path/'p.tgz')
    safe_extract(tmp_path/'p.tgz',tmp_path/'p');return ingest_package(tmp_path/'p')


def test_inventory_connects_to_candidates_and_ai_with_exact_identity(tmp_path):
    from cvevidence_core.catalog import discover_candidates
    from cvevidence_core.investigation_intake import prepare
    ctx=context(tmp_path);data=inventory(ctx)
    assert len(data['files'])==1
    row=data['files'][0]
    assert row['sha256']==ctx.by_path('usr/bin/test')[1]['sha256']
    assert not row['same_build_verified'] and not row['cve_applicability_verified']
    assert discover_candidates(ctx)['binary_metadata']==data
    assert prepare(ctx,[])['binary_metadata']==data


def test_web_shows_binary_metadata_as_limited_pc2_clues(tmp_path):
    from streamlit.testing.v1 import AppTest
    from tests.test_package_inventory import inventory_app
    from cvevidence.runner import Runner
    from cvevidence.storage import RunStore
    context(tmp_path);runner=Runner(RunStore(tmp_path/'runtime'));run=runner.start_file(tmp_path/'p.tgz')
    app=AppTest.from_function(inventory_app,default_timeout=20)
    app.session_state['test_store']=str(tmp_path/'runtime')
    app.session_state['selected_run']=run.run_id
    from cvevidence.workflow_navigation import PAGES
    app.session_state['step']=PAGES[1];app.run()
    assert not app.exception
    assert any('PC2 線索' in e.label for e in app.expander)
    assert any('libtest.so.1' in str(d.value.to_dict()) for d in app.dataframe)


def test_large_metadata_does_not_flood_ai_input(tmp_path,monkeypatch):
    import cvevidence_core.elf_metadata as elf
    ctx=context(tmp_path)
    monkeypatch.setattr(elf,'inspect',lambda path:{'needed':['x'*4096]*128})
    row=inventory(ctx)['files'][0]
    assert row['status']=='METADATA_LIMIT' and row['metadata'] is None
