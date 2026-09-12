"""Assemble an approved same-build OpenSSL initial package using the core delta validator."""
import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
from datetime import datetime, timezone
from cvevidence.core_worker import execute

root = Path(__file__).resolve().parents[2]
catalog = json.loads((root/'data/catalogs/fresh-pc3-runtime-v2.json').read_text())
entries = {e['package_id']: e for e in catalog['packages']}
base, delta = entries['pc3_rom_static'], entries['supplement_pc3_rom_runtime']
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
for e in (base, delta):
    assert sha(root/e['archive']['repo_path']) == e['archive']['sha256']
target = root/'demo-inputs/openssl-presentation/demo_openssl_complete.tar.gz'
target.parent.mkdir(exist_ok=True)
assert not target.exists(), 'Do not overwrite a published package'
with tempfile.TemporaryDirectory(prefix='openssl-demo-', dir=root/'var') as temp:
    execute(dict(operation='delta', archive=str(root/base['archive']['repo_path']),
                 archive_sha256=base['archive']['sha256'], supplement=str(root/delta['archive']['repo_path']),
                 supplement_sha256=delta['archive']['sha256'], temporary_root=temp,
                 output=str(target), child_package_id='demo_openssl_complete_v3'))
with tarfile.open(target) as archive:
    raw = archive.extractfile('manifest.json').read()
    manifest = json.loads(raw)
assert manifest['primary_artifact'] == base['primary_artifact']
entry = {k: manifest[k] for k in ('package_id','kind','format','product_id','release_id','build_id','primary_artifact')}
entry.update(manifest_sha256=hashlib.sha256(raw).hexdigest(), file_count=len(manifest['files']), base_package_id=None,
             archive=dict(filename=target.name, repo_path=str(target.relative_to(root)),
                          relative_path=str(target.relative_to(root)),sha256=sha(target),size_bytes=target.stat().st_size))
missing = json.loads((root/'data/catalogs/fresh-demo-two-flows-v2.json').read_text())['packages'][1]
result = dict(schema_version='1.0',dataset_version='fresh-demo-openssl-zlib-v3',
              created_at=datetime.now(timezone.utc).isoformat(),packages=[entry,missing],
              input_archive_hashes=[base['archive']['sha256'],delta['archive']['sha256']],
              notes=['Approved same-build static and runtime materials; no binary executed, no verdict supplied.'])
(root/'data/catalogs/fresh-demo-openssl-zlib-v3.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
(target.parent/'SHA256SUMS').write_text(sha(target)+'  '+target.name+'\n')
print(json.dumps(entry,ensure_ascii=False))
