"""Author an honest partial snapshot from bounded files, without inventing a binary."""
from pathlib import Path
import gzip,io,json,os,tarfile,tempfile,zipfile,zlib
from .integrity import relative,scan,file_hash,digest


CHUNK=1024*1024
SMALL_FILE=20*CHUNK
SMALL_TOTAL=100*CHUNK
LARGE_FILE=256*CHUNK
MAX_SNAPSHOT=384*CHUNK
MAX_FILES=5000


class IntakeError(ValueError):
    """Only curated messages may cross the upload error boundary."""
    MESSAGES={
        'UPLOAD_LIMIT':'上傳材料超過容量限制。一般入口每檔 20 MiB、合計 100 MiB；ROM／SDK 可改用大型單檔入口（256 MiB）。',
        'EXPANDED_LIMIT':'封存檔展開後超過本次剩餘容量。請只封裝相關元件、版本清單與建置資料；大型入口包含原壓縮檔合計最多 384 MiB。',
        'FILE_LIMIT':'封存檔項目或快照檔案數超過 5000。請移除不相關的快取、工具鏈或其他產品版本後重新封裝。',
        'ARCHIVE_INVALID':'封存檔損壞或不是可讀的 ZIP／tar。請確認可在本機完整解壓，再重新提供；改副檔名不會轉換格式。',
        'ARCHIVE_UNSAFE':'封存檔含不支援的路徑、連結或特殊項目。請提供只含一般檔案的材料副本，保留原始 SDK 供追溯，不要直接修改原始 SDK。',
        'LINKS':'目前部分材料入口不接受符號連結。請另製僅含相關一般檔案的材料包，並保留原始 SDK；不要將此限制解讀為產品缺件。',
        'SNAPSHOT_LIMIT':'補件後快照超過 384 MiB 或 5000 個檔案。請另建查核或縮小補件範圍；原查核與原材料未覆寫。',
        'CONFLICT':'補件包含與原材料同名但內容不同的檔案。新版本請另建查核；同版本的新增材料請使用不衝突的路徑。',
    }
    def __init__(self,code):
        self.code=code
        super().__init__(self.MESSAGES[code])


def _extract_upload(source,destination,**limits):
    from .integrity import safe_extract,IntegrityError
    try:
        safe_extract(source,destination,**limits)
    except IntegrityError as exc:
        code={'Archive expanded size limit exceeded':'EXPANDED_LIMIT',
              'Archive file limit exceeded':'FILE_LIMIT'}.get(str(exc),'ARCHIVE_UNSAFE')
        raise IntakeError(code) from exc
    except (tarfile.TarError,zipfile.BadZipFile,zlib.error,EOFError,UnicodeError,RuntimeError) as exc:
        raise IntakeError('ARCHIVE_INVALID') from exc


def _archive(root,output):
    """Deterministic bytes make retries bind the same material request."""
    def stable(info):
        info.mtime=0;info.uid=info.gid=0;info.uname=info.gname=''
        return info
    with Path(output).open('xb') as raw:
        os.fchmod(raw.fileno(),0o600)
        try:
            with gzip.GzipFile(fileobj=raw,mode='wb',filename='',mtime=0) as compressed:
                with tarfile.open(fileobj=compressed,mode='w') as archive:
                    for path in sorted(root.iterdir()):archive.add(path,arcname=path.name,filter=stable)
        except BaseException:
            Path(output).unlink(missing_ok=True)
            raise


def _copy_input(data,target,limit):
    handle=io.BytesIO(data) if isinstance(data,bytes) else data
    if not callable(getattr(handle,'read',None)):raise ValueError('Binary stream required')
    if callable(getattr(handle,'seek',None)):handle.seek(0)
    size=0
    with target.open('xb') as output:
        target.chmod(0o600)
        while True:
            block=handle.read(min(CHUNK,limit-size+1))
            if not isinstance(block,bytes):raise ValueError('Binary stream required')
            if not block:break
            size+=len(block)
            if size>limit:raise IntakeError('UPLOAD_LIMIT')
            output.write(block)
    return size


def create(files, output, *, product='未提供', release='未提供', build='未確認', base=None, large=False):
    if not files or len(files)>100:raise ValueError('請提供 1–100 個檔案')
    if type(large) is not bool:raise ValueError('Invalid intake mode')
    if large and len(files)!=1:raise ValueError('大型材料一次只接受一個檔案')
    per_file,total_limit=(LARGE_FILE,MAX_SNAPSHOT) if large else (SMALL_FILE,SMALL_TOTAL)
    if any(not isinstance(x,str) or not 1<=len(x)<=200 for x in (product,release,build)):raise ValueError('Invalid identity')
    with tempfile.TemporaryDirectory() as folder:
        root=Path(folder);total=0;seen=set()
        for name,data in files:
            p=relative(name)
            if name in seen or name in ('manifest.json','intake-identity.json') or any(part.endswith('.rom-inventory') for part in p.parts):raise ValueError('Duplicate/reserved filename')
            seen.add(name)
            target=root/p;target.parent.mkdir(parents=True,exist_ok=True)
            total+=_copy_input(data,target,min(per_file,total_limit-total))
            if large:
                from .firmware_inventory import candidate
                with target.open('rb') as stream:head=stream.read(4)
                if not candidate(name,head) and not name.lower().endswith(('.whl','.zip','.tar.gz','.tgz','.tar')):
                    raise ValueError('大型入口只接受 ROM 或 SDK 封存檔')
        # Archives remain data. Expand once through the same bounded extractor;
        # never install wheels, execute setup code, or recurse into nested archives.
        import shutil
        for name,_ in files:
            if not name.lower().endswith(('.whl','.zip','.tar.gz','.tgz','.tar')):continue
            source=root/relative(name);destination=root/relative(name+'.unpacked')
            _extract_upload(source,destination,max_bytes=total_limit-total,max_files=MAX_FILES-len(scan(root)))
            expanded=scan(destination)
            if any(r['kind']!='file' for r in expanded):raise IntakeError('LINKS')
            total+=sum(r['size'] for r in expanded)
            if total>total_limit:raise ValueError('材料展開後超過收件容量限制')
        from .firmware_inventory import candidate, extract, SUFFIX
        images=[]
        for name,_ in files:
            with (root/relative(name)).open('rb') as stream:head=stream.read(4)
            if candidate(name,head):images.append(name)
        if len(images)>3:raise ValueError('每次最多提供 3 份 ROM 映像，請分次建立查核')
        for name in images:
            extract(root/relative(name),root/relative(name+SUFFIX),max_bytes=total_limit-total)
            total=sum(r['size'] for r in scan(root))
            if total>total_limit:raise ValueError('ROM 材料展開後超過收件容量限制')
        if base:
            base.assert_current()
            if base.manifest['format']!='partial':raise ValueError('Partial supplement requires partial parent')
            combined={r['path']:r for r in base.manifest['files']}
            combined.update({r['path']:r for r in scan(root)})
            if len(combined)>MAX_FILES or sum(r['size'] for r in combined.values())>MAX_SNAPSHOT:
                raise IntakeError('SNAPSHOT_LIMIT')
            import shutil
            for row in base.manifest['files']:
                old=base.root/row['path'];new=root/row['path']
                if new.exists():
                    if file_hash(new)!=row['sha256']:raise IntakeError('CONFLICT')
                else:new.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(old,new)
            if sum(r['size'] for r in scan(root))>MAX_SNAPSHOT:raise ValueError('合併材料超過 384 MiB')
            manifest={**base.manifest,'parent_context_hash':base.context_hash}
        else:
            identity={'product':product,'release':release,'declared_build':build,
                'identity_verified':False,'artifact_role':'MATERIAL_INVENTORY_NOT_PRODUCT_BINARY'}
            (root/'intake-identity.json').write_text(json.dumps(identity,ensure_ascii=False))
            manifest={'schema_version':'1.0','format':'partial','product_id':product,'release_id':release,'build_id':build,
                'primary_artifact':{'path':'intake-identity.json','sha256':file_hash(root/'intake-identity.json')},
                'artifact_role':'MATERIAL_INVENTORY_NOT_PRODUCT_BINARY','identity_verified':False}
        manifest['files']=scan(root)
        if len(manifest['files'])>MAX_FILES:raise IntakeError('FILE_LIMIT')
        manifest['package_id']='partial-'+digest(manifest)[:24]
        (root/'manifest.json').write_text(json.dumps(manifest,sort_keys=True,ensure_ascii=False))
        _archive(root,output)
    return str(output)


def create_supplement(base,files,output,*,large=False):
    """Build an ordinary DELTA from new loose files, preserving parent identity."""
    from .integrity import safe_extract
    base.assert_current()
    if base.manifest['format']!='partial':raise ValueError('Partial parent required')
    with tempfile.TemporaryDirectory() as temporary:
        folder=Path(temporary);create(files,folder/'loose.tgz',large=large)
        root=folder/'delta';safe_extract(folder/'loose.tgz',root)
        (root/'intake-identity.json').unlink()
        manifest={k:base.manifest[k] for k in ('product_id','release_id','build_id','format','primary_artifact')}
        manifest.update(schema_version='1.0',kind='supplement',base_package_id=base.manifest['package_id'],files=scan(root))
        (root/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,sort_keys=True))
        from .supplements import validate_supplement
        validate_supplement(base,root)
        combined={r['path']:r for r in base.manifest['files']}
        combined.update({r['path']:r for r in manifest['files']})
        if len(combined)>MAX_FILES or sum(r['size'] for r in combined.values())>MAX_SNAPSHOT:
            raise IntakeError('SNAPSHOT_LIMIT')
        _archive(root,output)
    return str(output)
