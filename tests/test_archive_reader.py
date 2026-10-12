import hashlib
import shutil
import subprocess
import tracemalloc
import pytest
from cvevidence_core.archive_reader import archive_members
from cvevidence_core.integrity import IntegrityError


def header(name,size):
    return (name.ljust(16)+'0'.ljust(12)+'0'.ljust(6)+'0'.ljust(6)+'644'.ljust(8)+str(size).ljust(10)+'`\n').encode()


def member(name,body):
    return header(name,len(body))+body+(b'\n' if len(body)%2 else b'')


def write(tmp_path,data):
    p=tmp_path/'lib.a';p.write_bytes(b'!<arch>\n'+data);return p


def test_names_and_hashes_across_supported_encodings(tmp_path):
    table=b'a-long-object-name.o/\n'
    bsd=b'bsd-name.o\0\0'
    path=write(tmp_path,member('/',b'index')+member('//',table)+member('/0',b'gnu')+
               member('#1/'+str(len(bsd)),bsd+b'bsd')+member('short.o/',b''))
    assert archive_members(path)==[
        {'name':n,'sha256':hashlib.sha256(body).hexdigest(),'size':len(body)}
        for n,body in [('a-long-object-name.o',b'gnu'),('bsd-name.o',b'bsd'),('short.o',b'')]]


@pytest.mark.parametrize('data',[
    header('a.o/',8)+b'short',
    header('a.o/',1)+b'x',
    header('a.o/',1)+b'x! ',
    member('a.o/',b'a')+member('a.o/',b'b'),
    member('//',b'name.o/\n')+member('/2',b'x'),
    member('//',b'name.o/\n')+member('/99',b'x'),
    member('#1/999',b'short'),
    member('#1/2',b'\xff\xffabc'),
    member('//',b'a/\n')+member('//',b'b/\n'),
    header('a.o/',-1),
])
def test_malformed_and_ambiguous_inputs_fail(tmp_path,data):
    with pytest.raises(IntegrityError):archive_members(write(tmp_path,data))


def test_thin_archive_is_not_followed(tmp_path):
    p=tmp_path/'thin.a';p.write_bytes(b'!<thin>\n'+member('/tmp/secret',b''))
    with pytest.raises(IntegrityError,match='thin'):archive_members(p)


def test_limits_are_explicit(tmp_path,monkeypatch):
    import cvevidence_core.archive_reader as reader
    path=write(tmp_path,member('a.o/',b'a')+member('b.o/',b'b'))
    monkeypatch.setattr(reader,'MAX_MEMBERS',1)
    with pytest.raises(IntegrityError,match='member limit'):archive_members(path)
    monkeypatch.setattr(reader,'MAX_MEMBERS',10)
    monkeypatch.setattr(reader,'MAX_NAMES',2)
    with pytest.raises(IntegrityError,match='name budget'):archive_members(path)
    monkeypatch.setattr(reader,'MAX_ARCHIVE',8)
    with pytest.raises(IntegrityError,match='size limit'):archive_members(path)


def test_large_member_is_hashed_with_bounded_memory(tmp_path):
    size=16*1024*1024;path=tmp_path/'large.a'
    with path.open('wb') as f:
        f.write(b'!<arch>\n'+header('large.o/',size));f.seek(size-1,1);f.write(b'\0')
    expected=hashlib.sha256()
    for _ in range(16):expected.update(b'\0'*(1024*1024))
    tracemalloc.start()
    try:
        rows=archive_members(path);_,peak=tracemalloc.get_traced_memory()
    finally:tracemalloc.stop()
    assert rows==[{'name':'large.o','sha256':expected.hexdigest(),'size':size}]
    assert peak<4*1024*1024


def test_native_ar_members_match_original_bytes(tmp_path):
    if not shutil.which('ar'):pytest.skip('ar unavailable')
    files=[tmp_path/'short.o',tmp_path/'a_very_long_member_name.o']
    for p,data in zip(files,[b'TEST_ONLY_A',b'TEST_ONLY_B']):p.write_bytes(data)
    path=tmp_path/'native.a'
    subprocess.run(['ar','rcs',str(path),*[str(p) for p in files]],check=True,capture_output=True)
    assert archive_members(path)==[{'name':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'size':p.stat().st_size} for p in files]
