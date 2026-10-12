import io
import json
import struct
import zipfile
from copy import deepcopy
import pytest
from cvevidence_core.partial_intake import create
from cvevidence_core.integrity import ingest_package,safe_extract
from cvevidence_core.turnkey import inventory
from cvevidence_core.turnkey_container import inspect


def mfi(version='--license-terms', magic=0xb3c00000):
    meta=b'Date: TEST_ONLY\nBuildVersion: TEST_BUILD\nRevision: TEST\n'
    t=struct.pack('<III',4,12+len(meta),len(meta))+meta
    head=struct.pack('<IIIII',magic,0x10001,2,92,92+len(t))+b'\0'*72
    sub=b''
    for kind,text in [(1,'rootfs'),(2,version),(7,'/provenance-only/rootfs.squashfs')]:
        raw=text.encode();sub+=struct.pack('<II',kind,8+len(raw))+raw
    return head+t+struct.pack('<IIIII',0xa7b263fe,2,20+len(sub),len(sub),0)+sub


def context(tmp_path,files,**kw):
    create(files,tmp_path/'p.tgz',**kw);safe_extract(tmp_path/'p.tgz',tmp_path/'p')
    return ingest_package(tmp_path/'p')


def test_mfi_content_not_suffix_and_bad_version_retained(tmp_path):
    c=context(tmp_path,[('2506/device.rom',mfi())]);r=inventory(c)
    image=next(x for x in r['materials'] if x['observed_format']=='MFI')
    assert image['container']['metadata']['BuildVersion']=='TEST_BUILD'
    assert image['container']['rootfs'][0]['version']=='--license-terms'
    assert image['container']['rootfs'][0]['version_state']=='PRESENT_BUT_UNUSABLE'
    assert 'REC-BSP-IDENTITY' in {x['recommendation_id'] for x in r['recommendations']}
    assert not image['container']['signature_verified'] and r['assessment']=='NOT_ASSESSED'


def test_mfi_truncated_and_out_of_bounds_not_success(tmp_path):
    p=tmp_path/'x';data=mfi()
    for invalid in [data[:18],data[:-1],data[:16]+struct.pack('<I',0xffffffff)+data[20:]]:
        p.write_bytes(invalid);assert inspect(p)['status']!='PARTIAL_METADATA'
    p.write_bytes(data);assert inspect(p,enabled=False)['status']=='PARSER_UNAVAILABLE'


def test_host_inventory_never_satisfies_target_or_public_candidates(tmp_path):
    c=context(tmp_path,[('2506/host-manifest.csv',b'PACKAGE,VERSION,LICENSE\nopenssl,3.0,Apache\n')])
    r=inventory(c)
    assert r['materials'][0]['components'][0]['name']=='openssl'
    assert 'REC-COMPONENT-METADATA' in {x['recommendation_id'] for x in r['recommendations']}
    from cvevidence_core.component_discovery import components
    assert not components(c)


def test_supplement_removes_missing_not_binding_and_keeps_old(tmp_path):
    a=tmp_path/'a';b=tmp_path/'b';a.mkdir();b.mkdir()
    c=context(a,[('2506/device.mfi',mfi())]);old=c.context_hash;before=inventory(c)
    child=context(b,[('2506/sdk/gnu/xstax/manifest.csv',b'PACKAGE,VERSION,LICENSE\nzlib,1.3,zlib\n')],base=c)
    after=inventory(child)
    assert 'REC-COMPONENT-METADATA' in {x['recommendation_id'] for x in before['recommendations']}
    assert 'REC-COMPONENT-METADATA' not in {x['recommendation_id'] for x in after['recommendations']}
    assert 'REC-BUILD-ASSOCIATION' in {x['recommendation_id'] for x in after['recommendations']}
    c.assert_current();assert c.context_hash==old and child.manifest['parent_context_hash']==old


def test_txt_map_and_stage_scope_are_kept(tmp_path):
    c=context(tmp_path,[('2506/brand/a/app.txt',b'Archive member included to satisfy reference by file (symbol)\na.o (test)\n'),
        ('e5v40-01/brand/b/app.txt',b'Archive member included to satisfy reference by file (symbol)\nb.o (test)\n')])
    r=inventory(c)
    assert all(x['material_role']=='application_link_map' for x in r['materials'])
    assert len({x['scope']['family'] for x in r['materials']})==2
    assert sum(x['priority']=='NOW' for x in r['recommendations'])==1
    assert not {'REC-RUNTIME-EVIDENCE','REC-ALL-SOURCE','REC-APPLICATION-LINK-MAP'} & {x['recommendation_id'] for x in r['recommendations']}


def test_config_source_and_recipe_not_shipped_component(tmp_path):
    c=context(tmp_path,[('e5v40-01/Makefile',b'RELEASE_VERSION=TEST\n'),
        ('e5v40-01/output-mips-stage2_smb/.config',b'# BR2_PACKAGE_LIBCURL is not set\n'),
        ('2506/kernel/Makefile',b'VERSION = 6\nPATCHLEVEL = 12\nSUBLEVEL = 20\n')])
    r=inventory(c)
    kernel=next(x for x in r['materials'] if x['material_role']=='kernel_source')
    assert kernel['observations'][0]['value']=='6.12.20'
    assert all(x['build_binding']=='UNKNOWN' for x in r['materials'])
    assert r['assessment']=='NOT_ASSESSED'


def test_declared_family_guides_paths_but_is_not_observed_identity(tmp_path):
    c=context(tmp_path,[('device.bin',b'TEST_ONLY\0'),('buildroot_defconfig',b'BR2_PACKAGE_LIBCURL=y\n')],turnkey_family='2506')
    r=inventory(c)
    assert all(x['scope']['family']=='2506' for x in r['materials'])
    assert all(x['scope']['basis']=='USER_DECLARED_FAMILY_WITH_PATH_SCOPE_HINTS' for x in r['materials'])
    assert all(x['build_binding']=='UNKNOWN' for x in r['materials'])
    component=next(x for x in r['recommendations'] if x['recommendation_id']=='REC-COMPONENT-METADATA')
    assert component['candidate_paths']==['<BSP>/<ABI>/<target>/release/legal-info/manifest.csv']


def test_ui_minimal_request_collapsed_details(tmp_path):
    from streamlit.testing.v1 import AppTest
    def view(report):
        import streamlit as st
        from cvevidence.turnkey_view import render
        render(st,report)
    c=context(tmp_path,[('2506/device.mfi',mfi())]);app=AppTest.from_function(view,args=(inventory(c),)).run(timeout=15)
    assert not app.exception
    assert all(not e.proto.expanded for e in app.expander)


@pytest.mark.parametrize('refs', [None, 'not-an-array', {'path':'fake'}])
def test_malformed_test_record_is_unusable_without_crashing(tmp_path,refs):
    record={'fixture_class':'SYNTHETIC_TEST_ONLY','inputs':refs,'outputs':[]}
    c=context(tmp_path,[('test-receipt.json',json.dumps(record).encode())])
    r=inventory(c)
    assert r['materials'][0]['presence_state']=='PRESENT_BUT_UNUSABLE'
    assert not r['materials'][0]['test_association']['production_evidence_eligible']
    assert r['inventory_state']=='SOURCE_ONLY'


def test_synthetic_links_do_not_replace_overall_inventory_state(tmp_path):
    from hashlib import sha256
    content=b'TEST_ONLY bytes\0'
    record={'fixture_class':'SYNTHETIC_TEST_ONLY','inputs':[{'packaged_path':'artifact.bin','sha256':sha256(content).hexdigest()}]}
    c=context(tmp_path,[('test-receipt.json',json.dumps(record).encode()),('artifact.bin',content)])
    r=inventory(c)
    assert r['inventory_state']=='LIMITED_INVENTORY'
    receipt=next(x for x in r['materials'] if 'test_association' in x)
    assert receipt['test_association']['state']=='MATCHED_TEST_RECORD'


def test_large_txt_link_map_accepted_only_in_explicit_large_mode(tmp_path):
    from cvevidence_core.partial_intake import IntakeError
    content=b'Archive member included to satisfy reference by file (symbol)\n'+b' '* (21*1024*1024)
    with pytest.raises(IntakeError):create([('app.txt',content)],tmp_path/'rejected.tgz')
    c=context(tmp_path,[('app.txt',content)],large=True)
    row=inventory(c)['materials'][0]
    assert row['material_role']=='application_link_map' and row['text_truncated']
