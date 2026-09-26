import json
import os
import subprocess
import pytest
from cvevidence_core import firmware_inventory as fw
from cvevidence_core.elf_metadata import inventory
from cvevidence_core.partial_intake import create
from cvevidence_core.integrity import safe_extract,ingest_package,scan
from tests.test_firmware_inventory import image
from tests.test_elf_metadata import example


def material(tmp_path,image):
    root=tmp_path/'root';(root/'usr/bin').mkdir(parents=True)
    (root/'usr/bin/router').write_bytes(example(64,'<'))
    (root/'usr/bin/host-link').symlink_to('/usr/lib/x86_64-linux-gnu/libc.so.6')
    path=tmp_path/'binary.rom'
    subprocess.run(['mksquashfs',str(root),str(path),'-noappend','-processors','1','-no-progress'],
                   check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    create([('device.rom',path.read_bytes()),('sdk/router.elf',example(64,'<'))],tmp_path/'binary.tgz')
    safe_extract(tmp_path/'binary.tgz',tmp_path/'binary')
    return ingest_package(tmp_path/'binary')


def assert_reader(ctx):
    receipt=fw.reports(ctx)[0]
    if receipt['status']=='ISOLATION_UNAVAILABLE':
        if os.environ.get('CVEVIDENCE_REQUIRE_FIRMWARE_READER')=='1':pytest.fail('Isolation unavailable')
        pytest.skip('Isolation unavailable; native read not verified')
    assert receipt['status']=='PARTIAL_READ'
    return receipt


def test_native_rom_binary_matches_sdk_without_build_claim(tmp_path,image):
    ctx=material(tmp_path,image);receipt=assert_reader(ctx)
    assert receipt['binary_scan']['status']=='READ'
    assert receipt['binary_scan']['coverage_limited'] is True
    rows={r['image_path']:r for r in receipt['files']}
    assert rows['usr/bin/router']['status']=='READ'
    assert rows['usr/bin/host-link']['status']!='READ'
    binary=next(r for r in inventory(ctx)['files'] if '.rom-inventory/usr/bin/router' in r['path'])
    assert binary['metadata']['needed']==['libtest.so.1']
    assert [r['path'] for r in binary['identical_delivered_files']]==['sdk/router.elf']
    assert not binary['same_build_verified'] and not receipt['provenance_verified']


@pytest.mark.parametrize('path',['../bin/a','/bin/a','usr/bin/../../secret','usr/bin/a\nfoo','usr/bin/-x;id','etc/passwd','lib/opkg/status'])
def test_candidate_paths_are_limited(path):
    assert not fw.binary_path(path)


def test_listing_is_bounded_and_prioritizes_libraries(tmp_path,monkeypatch):
    data=('squashfs-root/lib/libssl.so.3\n'+''.join(f'squashfs-root/usr/bin/app{i}\n' for i in range(12))+'squashfs-root/../secret\n').encode()
    monkeypatch.setattr(fw,'_read',lambda *args:(data,'READ'))
    paths,info=fw._binary_candidates(tmp_path/'image',4)
    assert len(paths)==fw.MAX_BINARIES and paths[0]=='lib/libssl.so.3'
    assert info['candidate_count']==13 and info['coverage_limited']


def test_binary_size_limit_never_saves_truncated_elf(tmp_path,image):
    root=tmp_path/'root';(root/'usr/bin').mkdir(parents=True)
    (root/'usr/bin/large').write_bytes(b'\x7fELF'+b'0'*fw.MAX_BINARY)
    path=tmp_path/'large.rom'
    subprocess.run(['mksquashfs',str(root),str(path),'-noappend','-processors','1','-no-progress'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    data,status=fw._read(path,'usr/bin/large',4)
    assert data is None and status in ('NOT_READ','ISOLATION_UNAVAILABLE')


def test_web_displays_matching_delivered_path(tmp_path,image):
    from streamlit.testing.v1 import AppTest
    from tests.test_package_inventory import inventory_app
    from cvevidence.runner import Runner
    from cvevidence.storage import RunStore
    from cvevidence.workflow_navigation import PAGES
    ctx=material(tmp_path,image);assert_reader(ctx)
    runner=Runner(RunStore(tmp_path/'runtime'));run=runner.start_file(tmp_path/'binary.tgz')
    app=AppTest.from_function(inventory_app,default_timeout=30)
    app.session_state['test_store']=str(tmp_path/'runtime')
    app.session_state['selected_run']=run.run_id;app.session_state['step']=PAGES[1]
    app.run();assert not app.exception
    assert any('sdk/router.elf' in str(d.value.to_dict()) and '相同內容的交付檔案' in str(d.value.to_dict()) for d in app.dataframe)
    assert any('未認證建置來源' in c.value for c in app.caption)
