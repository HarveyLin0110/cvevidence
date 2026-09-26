"""Author an honest partial snapshot from bounded files, without inventing a binary."""
from pathlib import Path
import json,tarfile,tempfile
from .integrity import relative,scan,file_hash,digest


def create(files, output, *, product='未提供', release='未提供', build='未確認', base=None):
    if not files or len(files)>100:raise ValueError('請提供 1–100 個檔案')
    if any(not isinstance(x,str) or not 1<=len(x)<=200 for x in (product,release,build)):raise ValueError('Invalid identity')
    with tempfile.TemporaryDirectory() as folder:
        root=Path(folder);total=0;seen=set()
        for name,data in files:
            p=relative(name)
            if name in seen or name in ('manifest.json','intake-identity.json'):raise ValueError('Duplicate/reserved filename')
            seen.add(name)
            if not isinstance(data,bytes) or len(data)>20*1024*1024:raise ValueError('每個材料上限 20 MiB')
            total+=len(data)
            if total>100*1024*1024:raise ValueError('材料總量上限 100 MiB')
            target=root/p;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        # Archives remain data. Expand once through the same bounded extractor;
        # never install wheels, execute setup code, or recurse into nested archives.
        import shutil
        from .integrity import safe_extract
        for name,_ in files:
            if not name.lower().endswith(('.whl','.zip','.tar.gz','.tgz','.tar')):continue
            source=root/relative(name);destination=root/relative(name+'.unpacked')
            safe_extract(source,destination,max_bytes=100*1024*1024-total,max_files=5000)
            expanded=scan(destination)
            if any(r['kind']!='file' for r in expanded):raise ValueError('部分材料壓縮包不接受連結')
            total+=sum(r['size'] for r in expanded)
            if total>100*1024*1024:raise ValueError('材料展開後超過 100 MiB')
        if base:
            base.assert_current()
            if base.manifest['format']!='partial':raise ValueError('Partial supplement requires partial parent')
            import shutil
            for row in base.manifest['files']:
                old=base.root/row['path'];new=root/row['path']
                if new.exists():
                    if file_hash(new)!=row['sha256']:raise ValueError('同一快照補件不能覆寫原材料')
                else:new.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(old,new)
            manifest={**base.manifest,'parent_context_hash':base.context_hash}
        else:
            identity={'product':product,'release':release,'declared_build':build,
                'identity_verified':False,'artifact_role':'MATERIAL_INVENTORY_NOT_PRODUCT_BINARY'}
            (root/'intake-identity.json').write_text(json.dumps(identity,ensure_ascii=False))
            manifest={'schema_version':'1.0','format':'partial','product_id':product,'release_id':release,'build_id':build,
                'primary_artifact':{'path':'intake-identity.json','sha256':file_hash(root/'intake-identity.json')},
                'artifact_role':'MATERIAL_INVENTORY_NOT_PRODUCT_BINARY','identity_verified':False}
        manifest['files']=scan(root);manifest['package_id']='partial-'+digest(manifest)[:24]
        (root/'manifest.json').write_text(json.dumps(manifest,sort_keys=True,ensure_ascii=False))
        with tarfile.open(output,'x:gz') as archive:
            for p in sorted(root.iterdir()):archive.add(p,arcname=p.name)
    return str(output)


def create_supplement(base,files,output):
    """Build an ordinary DELTA from new loose files, preserving parent identity."""
    from .integrity import safe_extract
    base.assert_current()
    if base.manifest['format']!='partial':raise ValueError('Partial parent required')
    with tempfile.TemporaryDirectory() as temporary:
        folder=Path(temporary);create(files,folder/'loose.tgz')
        root=folder/'delta';safe_extract(folder/'loose.tgz',root)
        (root/'intake-identity.json').unlink()
        manifest={k:base.manifest[k] for k in ('product_id','release_id','build_id','format','primary_artifact')}
        manifest.update(schema_version='1.0',kind='supplement',base_package_id=base.manifest['package_id'],files=scan(root))
        (root/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,sort_keys=True))
        from .supplements import validate_supplement
        validate_supplement(base,root)
        with tarfile.open(output,'x:gz') as archive:
            for p in sorted(root.iterdir()):archive.add(p,arcname=p.name)
    return str(output)
