"""New TEST_ONLY SquashFS images; no old demo or CVE impact fixtures."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import pytest
from cvevidence_core import firmware_inventory as fw
from cvevidence_core.partial_intake import create
from cvevidence_core.integrity import safe_extract, ingest_package, scan
from cvevidence_core.component_discovery import components
from cvevidence_core.investigation_intake import prepare


@pytest.fixture
def image(tmp_path):
    if not all(shutil.which(x) for x in ('mksquashfs','unsquashfs','bwrap')):
        if os.environ.get('CVEVIDENCE_REQUIRE_FIRMWARE_READER')=='1':pytest.fail('Required firmware tools unavailable')
        pytest.skip('SquashFS tools unavailable; real image acceptance not performed')
    root=tmp_path/'root';(root/'usr/lib/opkg').mkdir(parents=True)
    (root/'usr/lib/opkg/status').write_text('Package: curl\nVersion: 8.3.0-vendor2\nStatus: install user installed\n')
    (root/'etc').mkdir();(root/'etc/openwrt_release').write_text("DISTRIB_DESCRIPTION='TEST_ONLY'\n")
    sentinel=tmp_path/'host-only';sentinel.write_text('TEST_ONLY_HOST_FILE_MUST_NOT_BE_READ')
    (root/'etc/os-release').symlink_to(sentinel)
    (root/'never-run.sh').write_text('exit 17\n')
    path=tmp_path/'device.rom'
    subprocess.run(['mksquashfs',str(root),str(path),'-noappend','-processors','1','-no-progress'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    return path


def test_real_rom_read_or_explicit_environment_failure(tmp_path,image):
    create([('device.rom',image.read_bytes())],tmp_path/'p.tgz')
    safe_extract(tmp_path/'p.tgz',tmp_path/'p');c=ingest_package(tmp_path/'p')
    rows=fw.reports(c)
    if rows[0]['status']=='ISOLATION_UNAVAILABLE':
        if os.environ.get('CVEVIDENCE_REQUIRE_FIRMWARE_READER')=='1':pytest.fail('Required isolation environment unavailable')
        assert not components(c)
        assert all(r['status']!='READ' for r in rows[0]['files'])
        assert c.by_path('device.rom')[0].read_bytes()==image.read_bytes()
        return
    assert rows[0]['status']=='PARTIAL_READ'
    assert rows[0]['image_sha256']==c.by_path('device.rom')[1]['sha256']
    assert rows[0]['provenance_verified'] is False
    assert rows[0]['isolation']=='BWRAP_UNSHARE_ALL_FIXED_READONLY_IMAGE'
    assert components(c)[0]['version']=='8.3.0-vendor2'
    assert 'curl' in prepare(c,[])['initial_product_excerpts'][0]['text']
    assert not (tmp_path/'p/device.rom.rom-inventory/never-run.sh').exists()
    assert next(r for r in rows[0]['files'] if r['image_path']=='etc/os-release')['status']=='NOT_READ'
    assert 'TEST_ONLY_HOST_FILE_MUST_NOT_BE_READ' not in json.dumps(rows)
    assert not (tmp_path/'p/device.rom.rom-inventory/etc/os-release').exists()


def test_receipt_cannot_bind_different_image(tmp_path,image):
    create([('device.rom',image.read_bytes())],tmp_path/'p.tgz')
    safe_extract(tmp_path/'p.tgz',tmp_path/'p')
    root=tmp_path/'p';receipt=root/'device.rom.rom-inventory/inspection.json'
    data=json.loads(receipt.read_text());data['image_sha256']='0'*64;receipt.write_text(json.dumps(data))
    manifest=json.loads((root/'manifest.json').read_text());manifest['files']=scan(root)
    (root/'manifest.json').write_text(json.dumps(manifest))
    assert fw.reports(ingest_package(root))[0]['status']=='INVALID_RECEIPT'


def test_unknown_rom_preserved_with_capability_gap(tmp_path):
    create([('device.bin',b'TEST_ONLY unsupported image')],tmp_path/'p.tgz')
    safe_extract(tmp_path/'p.tgz',tmp_path/'p');c=ingest_package(tmp_path/'p')
    assert fw.reports(c)[0]['status']=='UNSUPPORTED_FORMAT'
    assert c.by_path('device.bin')[0].read_bytes()==b'TEST_ONLY unsupported image'
    assert components(c)==[]


def test_missing_tool_and_timeout_keep_explicit_unknown(tmp_path,monkeypatch):
    image=tmp_path/'image';image.write_bytes(b'hsqsTEST_ONLY')
    monkeypatch.setattr(fw.shutil,'which',lambda *a,**k:None)
    assert fw.extract(image,tmp_path/'none',max_bytes=100)['status']=='TOOL_UNAVAILABLE'
    monkeypatch.setattr(fw.shutil,'which',lambda *a,**k:str(image))
    monkeypatch.setattr(fw,'_cat',lambda *a:(None,'TIME_LIMIT'))
    receipt=fw.extract(image,tmp_path/'timeout',max_bytes=100)
    assert receipt['status']=='NO_INVENTORY_READ'
    assert all(r['status']=='TIME_LIMIT' for r in receipt['files'])


def test_reserved_paths_and_image_count_rejected(tmp_path):
    with pytest.raises(ValueError):create([('device.rom.rom-inventory/inspection.json',b'{}')],tmp_path/'p.tgz')
    with pytest.raises(ValueError):create([(f'{i}.rom',b'x') for i in range(4)],tmp_path/'p.tgz')


def test_output_limit_does_not_publish_partial_file(tmp_path,monkeypatch):
    path=tmp_path/'image';path.write_bytes(b'hsqsTEST_ONLY')
    monkeypatch.setattr(fw.shutil,'which',lambda *a,**k:str(path))
    monkeypatch.setattr(fw,'_cat',lambda *a:(b'oversize','READ'))
    result=fw.extract(path,tmp_path/'out',max_bytes=1)
    assert result['bytes_read']==0
    assert all(r['status']=='SIZE_LIMIT' for r in result['files'])
    assert not (tmp_path/'out/usr/lib/opkg/status').exists()


def test_native_reader_enforces_output_limit(tmp_path,image):
    (tmp_path/'root/usr/lib/opkg/status').write_bytes(b'x'*(fw.MAX_TEXT+4096))
    large=tmp_path/'large.rom'
    subprocess.run(['mksquashfs',str(tmp_path/'root'),str(large),'-noappend','-processors','1','-no-progress'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    data,status=fw._cat(large,'usr/lib/opkg/status',4)
    if status=='ISOLATION_UNAVAILABLE':
        if os.environ.get('CVEVIDENCE_REQUIRE_FIRMWARE_READER')=='1':pytest.fail('Required isolation environment unavailable')
        assert data is None
        return
    assert data is None and status=='NOT_READ'


def test_isolation_failure_is_not_reported_as_missing_material(tmp_path,monkeypatch):
    image=tmp_path/'image';image.write_bytes(b'hsqsTEST_ONLY')
    monkeypatch.setattr(fw.shutil,'which',lambda *a,**k:str(image))
    monkeypatch.setattr(fw,'_cat',lambda *a:(None,'ISOLATION_UNAVAILABLE'))
    receipt=fw.extract(image,tmp_path/'out',max_bytes=100)
    assert receipt['status']=='ISOLATION_UNAVAILABLE'
    assert receipt['bytes_read']==0


def test_web_shows_unsupported_image_as_capability_limit(tmp_path):
    from streamlit.testing.v1 import AppTest
    from cvevidence.runner import Runner
    from cvevidence.storage import RunStore
    from tests.test_package_inventory import inventory_app
    create([('device.bin',b'TEST_ONLY unsupported')],tmp_path/'p.tgz')
    runner=Runner(RunStore(tmp_path/'runtime'));run=runner.start_file(tmp_path/'p.tgz')
    app=AppTest.from_function(inventory_app,default_timeout=20)
    app.session_state['test_store']=str(tmp_path/'runtime');app.session_state['selected_run']=run.run_id
    app.run();next(b for b in app.button if b.label=='02 資料確認與缺件').click().run()
    assert not app.exception
    assert any('目前不支援此映像格式' in x.value for x in app.text)


@pytest.mark.parametrize('field,value',[('status',{}),('files',None),('bytes_read',True),('schema_version','invented')])
def test_malformed_external_receipt_is_visible_failure(tmp_path,field,value):
    create([('device.bin',b'TEST_ONLY')],tmp_path/'p.tgz')
    safe_extract(tmp_path/'p.tgz',tmp_path/'p');root=tmp_path/'p'
    path=root/'device.bin.rom-inventory/inspection.json'
    row=json.loads(path.read_text());row[field]=value;path.write_text(json.dumps(row))
    manifest=json.loads((root/'manifest.json').read_text());manifest['files']=scan(root)
    (root/'manifest.json').write_text(json.dumps(manifest))
    assert fw.reports(ingest_package(root))[0]['status']=='INVALID_RECEIPT'
