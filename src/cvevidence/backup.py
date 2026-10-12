"""Offline account-store snapshots. Integrity is not signer authentication."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import zipfile

GROUPS={'runs','blobs','requests','ai','condition-reviews','public-discovery','events'}
MAX_BYTES=8*1024**3
MAX_FILES=100000
MANIFEST='backup-manifest.json'


def allowed(name):
    p=PurePosixPath(name)
    if str(p)!=name or p.is_absolute() or any(x in ('.','..') for x in p.parts):return False
    if len(p.parts) not in (2,3) or p.parts[0] not in GROUPS:return False
    if not all(re.fullmatch(r'[A-Za-z0-9_.-]{1,150}',x) for x in p.parts):return False
    if any(x.startswith('.') for x in p.parts):return False
    if p.parts[0]=='blobs':return len(p.parts)==2 and bool(re.fullmatch('[a-f0-9]{64}',p.name))
    if p.parts[0] in ('public-discovery','events') and len(p.parts)!=3:return False
    if p.parts[0] not in ('public-discovery','events') and len(p.parts)!=2:return False
    return p.suffix=='.json' or (p.parts[0]=='requests' and p.suffix=='.lock')


def _scan(root):
    rows={};total=0
    for group in sorted(GROUPS):
        directory=root/group
        if directory.is_symlink():raise ValueError('備份目錄不可為連結')
        if not directory.exists():continue
        if not directory.is_dir():raise ValueError('備份目錄格式錯誤')
        for path in sorted(directory.rglob('*')):
            info=path.lstat()
            if stat.S_ISLNK(info.st_mode):raise ValueError('備份不接受連結')
            if stat.S_ISDIR(info.st_mode):continue
            name=path.relative_to(root).as_posix()
            if not stat.S_ISREG(info.st_mode) or not allowed(name):
                raise ValueError('資料夾含非標準檔案或進行中的寫入；請先停止工作再備份')
            rows[name]=(info.st_size,info.st_mtime_ns,info.st_ino,info.st_dev)
            total+=info.st_size
            if total>MAX_BYTES or len(rows)>MAX_FILES:raise ValueError('備份超過容量或檔案數上限')
    if not rows:raise ValueError('沒有可備份的案件資料')
    return rows


def create(root,output):
    root=Path(root);output=Path(output)
    if root.is_symlink() or not root.is_dir():raise ValueError('請指定實際工作區資料夾')
    root=root.resolve()
    if output.resolve().is_relative_to(root):raise ValueError('備份檔須放在來源工作區之外')
    if output.exists() or output.is_symlink():raise ValueError('備份檔已存在，不覆寫')
    index=_scan(root);entries=[]
    with tempfile.TemporaryDirectory(dir=output.parent) as temporary:
        target=Path(temporary)/'snapshot.zip'
        with target.open('xb') as raw:
            os.chmod(target,0o600)
            with zipfile.ZipFile(raw,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=1,allowZip64=True) as archive:
                for name,expected in index.items():
                    fd=os.open(root/name,os.O_RDONLY|os.O_NOFOLLOW)
                    with os.fdopen(fd,'rb') as source,archive.open(name,'w',force_zip64=True) as dest:
                        info=os.fstat(source.fileno())
                        if not stat.S_ISREG(info.st_mode) or (info.st_size,info.st_mtime_ns,info.st_ino,info.st_dev)!=expected:
                            raise ValueError('備份期間來源已變動')
                        digest=hashlib.sha256();size=0
                        while block:=source.read(1024*1024):
                            size+=len(block)
                            if size>expected[0]:raise ValueError('備份期間檔案增長')
                            dest.write(block);digest.update(block)
                        if size!=expected[0]:raise ValueError('備份期間檔案截短')
                    sha=digest.hexdigest()
                    if name.startswith('blobs/') and sha!=Path(name).name:raise ValueError('證據 blob 雜湊不符')
                    entries.append({'path':name,'size':size,'sha256':sha})
                if _scan(root)!=index:raise ValueError('備份期間工作區已變動，請停止工作後重試')
                manifest={'schema_version':'1.0','files':entries,'scope':'ACCOUNT_STORE','encrypted':False,
                          'excluded':['configuration','credentials','temporary','ai-progress','ai-temporary'],
                          'note':'位元組完整性快照，不認證來源；不恢復執行中的工作。'}
                data=json.dumps(manifest,ensure_ascii=False,sort_keys=True).encode()
                if len(data)>16*1024*1024:raise ValueError('備份清單超過上限')
                archive.writestr(MANIFEST,data)
            raw.flush();os.fsync(raw.fileno())
        os.link(target,output)
    return {'files':len(entries),'bytes':sum(e['size'] for e in entries),'encrypted':False}


def _validate(archive,destination=None):
    infos=archive.infolist();names=[i.filename for i in infos];name_set=set(names)
    if len(infos)>MAX_FILES+1 or len(names)!=len(name_set) or MANIFEST not in name_set:
        raise ValueError('備份清單缺失、重複或超限')
    if archive.getinfo(MANIFEST).file_size>16*1024*1024:raise ValueError('備份清單超過上限')
    manifest=json.loads(archive.read(MANIFEST))
    if not isinstance(manifest,dict) or manifest.get('schema_version')!='1.0' or manifest.get('scope')!='ACCOUNT_STORE':
        raise ValueError('不支援的備份格式')
    rows=manifest.get('files')
    if not isinstance(rows,list) or not rows or len(rows)>MAX_FILES:raise ValueError('備份清單格式錯誤')
    seen=set();total=0
    for row in rows:
        if not isinstance(row,dict) or not isinstance(row.get('path'),str) or not allowed(row['path']):raise ValueError('備份含不允許路徑')
        name=row['path'];size=row.get('size');sha=row.get('sha256')
        if name in seen or type(size) is not int or size<0 or not isinstance(sha,str) or not re.fullmatch('[a-f0-9]{64}',sha):raise ValueError('備份項目格式錯誤')
        seen.add(name);total+=size
        if total>MAX_BYTES or name not in name_set:raise ValueError('備份容量超限或檔案缺失')
        info=archive.getinfo(name)
        kind=stat.S_IFMT(info.external_attr>>16)
        if info.file_size!=size or info.is_dir() or kind not in (0,stat.S_IFREG):raise ValueError('備份檔案型別或大小不符')
        target=None
        if destination:
            target=destination/name;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with archive.open(info) as source:
            digest=hashlib.sha256();read=0
            if target:dest=target.open('xb');os.chmod(target,0o600)
            try:
                while block:=source.read(1024*1024):
                    read+=len(block)
                    if read>size:raise ValueError('備份內容超過宣告大小')
                    digest.update(block)
                    if target:dest.write(block)
            finally:
                if target:dest.close()
        if read!=size or digest.hexdigest()!=sha or (name.startswith('blobs/') and Path(name).name!=sha):
            raise ValueError('備份檔案雜湊不符')
    if name_set!=(seen|{MANIFEST}):raise ValueError('備份含未列出的內容')
    return {'files':len(rows),'bytes':total,'encrypted':False}


def verify(path):
    with zipfile.ZipFile(path) as archive:return _validate(archive)


def restore(path,destination):
    destination=Path(destination)
    if destination.exists() or destination.is_symlink():raise ValueError('只能還原到不存在的新資料夾')
    with tempfile.TemporaryDirectory(dir=destination.parent) as temporary:
        staged=Path(temporary)/'workspace';staged.mkdir(mode=0o700)
        with zipfile.ZipFile(path) as archive:result=_validate(archive,staged)
        # Reserve destination to avoid replacing an existing store, even if empty.
        destination.mkdir(mode=0o700)
        try:
            for group in staged.iterdir():os.rename(group,destination/group.name)
        except Exception:
            # Never delete a partial restore automatically; operator can inspect it.
            raise ValueError('還原搬移未完成；保留目標供檢查')
    return result
