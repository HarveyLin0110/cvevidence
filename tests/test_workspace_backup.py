import hashlib
import json
import os
from pathlib import Path
import zipfile
import pytest
from cvevidence import backup
from cvevidence.runner import Runner
from cvevidence.storage import RunStore
from cvevidence_core.partial_intake import create


def store(tmp_path):
    path=tmp_path/'input.tgz';create([('source.c',b'TEST_ONLY backup source\n')],path)
    runner=Runner(RunStore(tmp_path/'store'))
    request=runner.submit_request(path=path,cves=['CVE-2014-0160'])
    return runner,request


def test_restore_reopens_actual_requests_runs_and_evidence(tmp_path):
    runner,request=store(tmp_path)
    (runner.store.root/'.env.local').write_text('TEST_ONLY_SECRET_SENTINEL')
    (runner.store.root/'ai-temporary').mkdir();(runner.store.root/'ai-temporary/private').write_text('TEST_ONLY_PRIVATE')
    archive=tmp_path/'backup.zip';before={p.relative_to(runner.store.root):p.read_bytes() for p in runner.store.root.rglob('*') if p.is_file()}
    made=backup.create(runner.store.root,archive);assert backup.verify(archive)==made
    dest=tmp_path/'restored';assert backup.restore(archive,dest)==made
    restored=Runner(RunStore(dest));assert restored.read_request(request.spec.request_id)==request
    original=runner.store.read(request.runs[0].run_id);assert restored.store.read(original.run_id)==original
    assert restored.store.read_blob(original.input_package.archive_sha256)==runner.store.read_blob(original.input_package.archive_sha256)
    assert not (dest/'.env.local').exists() and not (dest/'ai-temporary').exists()
    assert archive.stat().st_mode&0o077==0
    assert all(p.stat().st_mode&0o077==0 for p in dest.rglob('*'))
    assert all((runner.store.root/p).read_bytes()==data for p,data in before.items())
    with pytest.raises(ValueError):backup.restore(archive,dest)
    with pytest.raises(ValueError):backup.create(runner.store.root,archive)


def archive(tmp_path,rows,extras=None):
    path=tmp_path/'bad.zip'
    with zipfile.ZipFile(path,'w') as z:
        manifest=[]
        for name,body in rows:
            z.writestr(name,body);manifest.append({'path':name,'size':len(body),'sha256':hashlib.sha256(body).hexdigest()})
        z.writestr(backup.MANIFEST,json.dumps({'schema_version':'1.0','scope':'ACCOUNT_STORE','files':manifest}))
        for name,body in extras or []:z.writestr(name,body)
    return path


@pytest.mark.parametrize('name',['../outside','runs/../../escape','/runs/file.json','.env.local','ai-temporary/private.json','runs/sub/file.json'])
def test_unsafe_paths_never_publish_destination(tmp_path,name):
    p=archive(tmp_path,[(name,b'{}')]);dest=tmp_path/'restored'
    with pytest.raises(ValueError):backup.restore(p,dest)
    assert not dest.exists() and not (tmp_path/'outside').exists()


def test_tampered_or_unlisted_bytes_are_rejected(tmp_path):
    p=archive(tmp_path,[('blobs/'+'0'*64,b'not this hash')])
    with pytest.raises(ValueError,match='雜湊'):backup.verify(p)
    p.unlink();p=archive(tmp_path,[('runs/a.json',b'{}')],[('unlisted',b'x')])
    with pytest.raises(ValueError,match='未列出'):backup.restore(p,tmp_path/'out')
    assert not (tmp_path/'out').exists()


def test_symlink_and_changed_source_are_rejected(tmp_path,monkeypatch):
    runner,_=store(tmp_path);root=runner.store.root
    link=root/'runs/link.json';link.symlink_to(tmp_path/'input.tgz')
    with pytest.raises(ValueError,match='連結'):backup.create(root,tmp_path/'copy.zip')
    link.unlink();original=backup._scan;calls=[]
    def scan(path):
        result=original(path);calls.append(1)
        if len(calls)==2:result['runs/new.json']=(0,0,0,0)
        return result
    monkeypatch.setattr(backup,'_scan',scan)
    with pytest.raises(ValueError,match='變動'):backup.create(root,tmp_path/'copy.zip')
    assert not (tmp_path/'copy.zip').exists()


def test_existing_incomplete_request_fence_is_preserved(tmp_path):
    runner,_=store(tmp_path);lock=runner.store.root/'requests/incomplete.lock';lock.write_bytes(b'')
    p=tmp_path/'copy.zip';backup.create(runner.store.root,p);backup.restore(p,tmp_path/'restored')
    assert (tmp_path/'restored/requests/incomplete.lock').exists()


def test_archive_entry_count_and_capacity_limits(tmp_path,monkeypatch):
    p=archive(tmp_path,[('runs/a.json',b'12345')])
    monkeypatch.setattr(backup,'MAX_BYTES',4)
    with pytest.raises(ValueError,match='容量'):backup.verify(p)


def test_zip_link_is_not_restored(tmp_path):
    p=tmp_path/'link.zip';name='runs/a.json';body=b'../outside'
    with zipfile.ZipFile(p,'w') as z:
        info=zipfile.ZipInfo(name);info.create_system=3;info.external_attr=(0o120777<<16);z.writestr(info,body)
        z.writestr(backup.MANIFEST,json.dumps({'schema_version':'1.0','scope':'ACCOUNT_STORE','files':[
            {'path':name,'size':len(body),'sha256':hashlib.sha256(body).hexdigest()}]}))
    with pytest.raises(ValueError,match='型別'):backup.restore(p,tmp_path/'restored')
    assert not (tmp_path/'restored').exists()
