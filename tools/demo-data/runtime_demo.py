"""Re-observe today's trusted factory builds; package static input + runtime delta.

This is an operator-only demo producer. The product analyzer never runs uploads.
No compilation or substitution of the delivered product takes place here.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from cvevidence_core.integrity import safe_extract, scan, ingest_package
from cvevidence_core.operational import SUBJECTS, LIBRARIES

CASES = {'rom': '01_rom', 'cmake': '04_cmake', 'curl': '07_curl'}
DATASET = 'fresh-pc3-runtime-v2'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n')


def execute(argv, **kwargs):
    result = subprocess.run([str(x) for x in argv], capture_output=True, timeout=30, **kwargs)
    if result.returncode:
        raise RuntimeError('Normal observation failed; no successful receipt will be created')
    return result.stdout


def observe(family, trusted, material, manifest):
    runtime = material / 'runtime'
    runtime.mkdir(parents=True)
    receipt = {k: manifest[k] for k in ('product_id','release_id','build_id','primary_artifact','format')}
    receipt.update(schema_version='1.0', observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   evidence_basis='CONTROLLED_LOCAL_OBSERVATION',
                   subject={'path': SUBJECTS[family], 'sha256': sha(trusted / SUBJECTS[family])},
                   libraries=[{'path': p, 'sha256': sha(trusted / p)} for p in LIBRARIES[family]])
    if family == 'cmake':
        shutil.copyfile(trusted / 'samples/normal.gz', runtime / 'normal.gz')
        output = execute([trusted / SUBJECTS[family], runtime / 'normal.gz'])
        (runtime / 'normal.log').write_bytes(output)
        receipt['command'] = {'argv': [SUBJECTS[family], 'runtime/normal.gz'], 'exit_code': 0}
        receipt['capture'] = {'path':'runtime/normal.log','sha256':sha(runtime / 'normal.log')}
        receipt['sample'] = {'path':'runtime/normal.gz','sha256':sha(runtime / 'normal.gz')}
    elif family == 'rom':
        output = execute([sys.executable, ROOT / 'tools/demo-data/factory/tcp_smoke.py',
                          trusted / 'unpacked/bin/device-management', trusted / 'observations/cert.pem',
                          trusted / 'observations/key.pem'])
        (runtime / 'tls.log').write_bytes(output)
        receipt['command'] = {'argv':['python3','tcp_smoke.py','unpacked/bin/device-management'], 'exit_code':0}
        receipt['capture'] = {'path':'runtime/tls.log','sha256':sha(runtime / 'tls.log')}
    else:
        sys.path.insert(0, str(ROOT / 'tools/demo-data/factory'))
        from curl_build import Http, Socks, Server
        import http.server

        class WireSocks(Socks):
            def recv_exact(self, n):
                data = super().recv_exact(n)
                self.wire.append(data)
                return data

            def handle(self):
                self.wire = []
                try: super().handle()
                finally: self.server.wires.append(self.wire)

        with http.server.ThreadingHTTPServer(('127.0.0.1',0), Http) as httpd, Server(('127.0.0.1',0), WireSocks) as socks:
            socks.http_port=httpd.server_port; socks.events=[]; socks.wires=[]
            config = runtime / 'download.conf'
            config.write_text(f'socks5-hostname = "127.0.0.1:{socks.server_address[1]}"\nlimit-rate = 16384\nnoproxy = ""\nlocation\nfail\nsilent\nshow-error\nmax-time = 10\n')
            threads=[threading.Thread(target=s.serve_forever,daemon=True) for s in (httpd,socks)]
            for thread in threads: thread.start()
            url=f'http://demo.test:{httpd.server_port}/update.bin'
            try:
                env={**os.environ,'LD_LIBRARY_PATH':str(trusted / 'install/lib')}
                output=execute([trusted / SUBJECTS[family], '--config', config, '--url', url], env=env)
            finally:
                httpd.shutdown(); socks.shutdown()
                for thread in threads: thread.join(timeout=3)
        if not socks.events or not socks.wires: raise RuntimeError('No actual SOCKS5 exchange captured')
        wire=socks.wires[0]
        capture={'greeting_hex':b''.join(wire[:2]).hex(), 'connect_hex':b''.join(wire[2:]).hex(),
                 'greeting_delay_seconds':socks.events[0]['greeting_delay_seconds'], 'stdout':output.decode('utf-8')}
        write(runtime / 'socks5-wire.json', capture)
        receipt['command']={'argv':[SUBJECTS[family],'--config','runtime/download.conf','--url',url], 'exit_code':0}
        receipt['capture']={'path':'runtime/socks5-wire.json','sha256':sha(runtime / 'socks5-wire.json')}
        receipt['configuration']={'path':'runtime/download.conf','sha256':sha(config)}
    write(runtime / 'observation.json', receipt)


def package(folder, manifest, name, base=None):
    value={k:manifest[k] for k in ('schema_version','product_id','release_id','build_id','format','primary_artifact')}
    value.update(package_id=name, kind='supplement' if base else 'initial', files=scan(folder),
                 created_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    if base: value['base_package_id']=base
    write(folder / 'manifest.json',value)
    archive=ROOT / 'demo-inputs/runtime-v2' / (name + '.tar.gz')
    archive.parent.mkdir(parents=True,exist_ok=True)
    if archive.exists(): raise ValueError('Runtime demo revision already exists; do not overwrite published observations')
    with tarfile.open(archive,'w:gz',dereference=False) as out:
        for p in sorted(folder.iterdir()): out.add(p,arcname=p.name)
    return {'package_id':name,'kind':value['kind'],'format':value['format'],'product_id':value['product_id'],
            'release_id':value['release_id'],'build_id':value['build_id'],'primary_artifact':value['primary_artifact'],
            'manifest_sha256':sha(folder / 'manifest.json'),'base_package_id':base,'file_count':len(value['files']),
            'archive':{'filename':archive.name,'repo_path':archive.relative_to(ROOT).as_posix(),
                       'relative_path':archive.relative_to(ROOT).as_posix(),'sha256':sha(archive),'size_bytes':archive.stat().st_size}}


def main(factory_root):
    factory_root=Path(factory_root).resolve(strict=True)
    original_catalog=json.loads((ROOT / 'demo-inputs/catalog.json').read_text())
    expected={x['archive']['repo_path']:x['archive']['sha256'] for x in original_catalog['packages']}
    entries=[]
    (ROOT / 'var').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=ROOT / 'var',prefix='runtime-demo-') as temp:
        for family,name in CASES.items():
            archive=ROOT / f'demo-inputs/{family}/{name}.tar.gz'
            if sha(archive)!=expected[archive.relative_to(ROOT).as_posix()]: raise ValueError('Approved archive hash mismatch')
            initial=Path(temp) / family / 'initial'; safe_extract(archive,initial)
            context=ingest_package(initial); manifest=context.manifest
            bid=manifest['build_id']
            if Path(bid).name!=bid: raise ValueError('Invalid build identity')
            trusted=(factory_root / bid / 'package').resolve(strict=True)
            if not trusted.is_relative_to(factory_root): raise ValueError('Factory path escape')
            completed=json.loads((trusted.parent / 'completed.json').read_text())
            if completed['artifact_sha256']!=manifest['primary_artifact']['sha256'] or completed['build_id']!=bid:
                raise ValueError('Only matching completed factory builds may be observed')
            paths=[manifest['primary_artifact']['path'], SUBJECTS[family], *LIBRARIES[family]]
            if family=='rom': paths.append('unpacked/bin/device-management')
            for path in paths:
                if not context.by_path(path) or sha(trusted / path)!=context.by_path(path)[1]['sha256']:
                    raise ValueError('Factory product differs from delivered bytes')
            supplemental=Path(temp) / family / 'supplement'
            observe(family,trusted,supplemental,manifest)
            # Remove old runtime captures. Build/source/link proof remains byte-identical.
            for row in manifest['files']:
                rel=row['path']
                if (rel.startswith(('observations/','install/etc/')) or
                    (rel.startswith('build/commands/') and any(x in rel for x in ('normal-','-normal','truncated-update','local-test-certificate')))):
                    (initial / rel).unlink(missing_ok=True)
            identifier='pc3_' + family + '_static'
            entries.append(package(initial,manifest,identifier))
            entries.append(package(supplemental,manifest,'supplement_pc3_' + family + '_runtime',identifier))
            print(f'{family}: observed same build; initial + runtime-only delta created',flush=True)
    catalog={'schema_version':'1.0','dataset_version':DATASET,'packages':entries,
             'notes':['Fresh 2026-09-12 normal observations of today-built unchanged artifacts; no exploit execution.',
                      'Initial inputs include complete PC2 proof; supplements contain runtime materials only.',
                      'Controlled localhost observations, not customer physical-device certification.']}
    write(ROOT / 'data/catalogs' / (DATASET + '.json'),catalog)
    write(ROOT / 'demo-inputs/runtime-v2/catalog.json',catalog)
    index=json.loads((ROOT / 'data/catalogs/index.json').read_text())
    index['selected_datasets']=[DATASET]
    write(ROOT / 'data/catalogs/index.json',index)
    (ROOT / 'demo-inputs/runtime-v2/SHA256SUMS').write_text(''.join(f"{e['archive']['sha256']}  {e['archive']['filename']}\n" for e in entries))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--factory-root',required=True)
    main(parser.parse_args().factory_root)
