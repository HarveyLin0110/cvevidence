"""Bounded extraction of fixed inventory paths from raw SquashFS, never mount/boot."""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

PATHS = ('usr/lib/opkg/status', 'etc/os-release', 'etc/openwrt_release')
MAX_TEXT = 2 * 1024 * 1024
SUFFIX = '.rom-inventory'
MAX_BINARY = 4 * 1024 * 1024
MAX_BINARIES = 6
LIST_TOKEN = '@list-elf-candidates'

def binary_path(member):
    if not isinstance(member,str) or len(member)>240 or not re.fullmatch(r'[A-Za-z0-9_.+/-]+',member):return False
    parts=member.split('/')
    if any(p in ('','.','..') for p in parts):return False
    return any(member.startswith(root+'/') for root in ('bin','sbin','usr/bin','usr/sbin')) or (
        any(member.startswith(root+'/') for root in ('lib','usr/lib')) and bool(re.search(r'\.so(?:\.[A-Za-z0-9_.+-]+)?$',parts[-1])))


def candidate(name, data):
    return data[:4] == b'hsqs' or name.lower().endswith(('.rom', '.img', '.bin', '.squashfs', '.sqfs'))


def _read(image, member, timeout):
    """One separate resource-limited process; file-backed output cannot grow unbounded."""
    with tempfile.TemporaryDirectory() as directory:
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            env = {'PATH': os.defpath, 'LC_ALL': 'C',
                   'PYTHONPATH': str(Path(__file__).resolve().parents[1])}
            try:
                result = subprocess.run([sys.executable, '-m', __name__, str(image.resolve()), member],
                    cwd=directory, env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
                    timeout=timeout, check=False)
            except subprocess.TimeoutExpired:
                return None, 'TIME_LIMIT'
            if result.returncode:
                errors.seek(0)
                if any(line.startswith(b'bwrap:') for line in errors.read(4096).splitlines()):
                    return None, 'ISOLATION_UNAVAILABLE'
                return None, 'NOT_READ'
            output.seek(0); limit=MAX_TEXT if member in PATHS or member==LIST_TOKEN else MAX_BINARY
            data = output.read(limit + 1)
            if member!=LIST_TOKEN and member not in PATHS:
                return (data,'READ') if len(data)<=limit and data.startswith(b'\x7fELF') else (None,'UNSUPPORTED_BINARY')
            if len(data) > MAX_TEXT or b'\0' in data:
                return None, 'UNSUPPORTED_TEXT'
            try:
                data.decode('utf-8')
            except UnicodeError:
                return None, 'UNSUPPORTED_TEXT'
            return data, 'READ'


def _cat(image, member, timeout):
    return _read(image,member,timeout)


def _binary_candidates(image,timeout):
    data,status=_read(image,LIST_TOKEN,timeout)
    if data is None:return [],{'status':status,'coverage_limited':True}
    paths=sorted({line[len('squashfs-root/'):] for line in data.decode('utf-8').splitlines()
                  if line.startswith('squashfs-root/') and binary_path(line[len('squashfs-root/'):])},
                 key=lambda p:(0 if '.so' in p else 1,p))
    return paths[:MAX_BINARIES],{'status':'READ','candidate_count':len(paths),
                                'coverage_limited':True}


def extract(image, destination, *, max_bytes, timeout=12):
    from .integrity import file_hash
    if destination.exists():
        raise ValueError('ROM inventory destination already exists')
    before = file_hash(image)
    with image.open('rb') as handle:
        magic = handle.read(4)
    receipt = {'schema_version':'1.1', 'image_sha256':before,
               'format':'RAW_SQUASHFS' if magic == b'hsqs' else 'UNSUPPORTED_IMAGE',
               'status':'UNSUPPORTED_FORMAT', 'files':[], 'bytes_read':0,
               'scope':'只讀固定套件／版本路徑及有限候選 ELF；並非完整 ROM 解包，未證明 SDK 或部署屬於同次建置。'}
    bodies = {}
    if magic == b'hsqs':
        receipt['status'] = 'TOOL_UNAVAILABLE'
        tool=shutil.which('unsquashfs', path=os.defpath)
        isolation=shutil.which('bwrap', path=os.defpath)
        if sys.platform.startswith('linux') and tool and isolation:
            receipt['reader_binary_sha256']=file_hash(Path(tool))
            receipt['isolation_binary_sha256']=file_hash(Path(isolation))
            receipt['isolation']='BWRAP_UNSHARE_ALL_FIXED_READONLY_IMAGE'
            deadline = time.monotonic() + timeout
            for member in PATHS:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    data, state = None, 'TIME_LIMIT'
                else:
                    data, state = _cat(image, member, min(4, remaining))
                row = {'image_path':member, 'status':state}
                if data is not None:
                    if receipt['bytes_read'] + len(data) > max_bytes:
                        row['status'] = 'SIZE_LIMIT'
                    else:
                        bodies[member] = data
                        row.update(sha256=hashlib.sha256(data).hexdigest(), size=len(data))
                        receipt['bytes_read'] += len(data)
                receipt['files'].append(row)
            remaining=deadline-time.monotonic()
            selected,scan_info=_binary_candidates(image,min(4,remaining)) if remaining>0 else ([],{'status':'TIME_LIMIT','coverage_limited':True})
            receipt['binary_scan']=scan_info
            for member in selected:
                remaining=deadline-time.monotonic()
                data,state=_read(image,member,min(4,remaining)) if remaining>0 else (None,'TIME_LIMIT')
                row={'image_path':member,'status':state,'kind':'ELF_CANDIDATE'}
                if data is not None:
                    if receipt['bytes_read']+len(data)>max_bytes:row['status']='SIZE_LIMIT'
                    else:
                        bodies[member]=data
                        row.update(sha256=hashlib.sha256(data).hexdigest(),size=len(data))
                        receipt['bytes_read']+=len(data)
                receipt['files'].append(row)
            receipt['status'] = ('PARTIAL_READ' if bodies else 'ISOLATION_UNAVAILABLE'
                if any(row['status']=='ISOLATION_UNAVAILABLE' for row in receipt['files']) else 'NO_INVENTORY_READ')
    if file_hash(image) != before:
        raise ValueError('ROM changed during inventory read')
    destination.mkdir(parents=True)
    for member, data in bodies.items():
        path = destination / member
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (destination/'inspection.json').write_text(json.dumps(receipt,ensure_ascii=False,sort_keys=True))
    return receipt


def reports(context):
    """Read scoped extraction records; hashes establish byte links, not attestation."""
    from .integrity import IntegrityError
    from .sources import text_lines
    output = []
    for source in context.sources.values():
        if not source['path'].endswith(SUFFIX+'/inspection.json'):
            continue
        try:
            receipt = json.loads('\n'.join(text_lines(context,source['source_id'])))
            if (not isinstance(receipt,dict) or receipt.get('schema_version') not in ('1.0','1.1')
                    or receipt.get('format') not in ('RAW_SQUASHFS','UNSUPPORTED_IMAGE')
                    or receipt.get('status') not in ('PARTIAL_READ','NO_INVENTORY_READ','TOOL_UNAVAILABLE','UNSUPPORTED_FORMAT','ISOLATION_UNAVAILABLE')
                    or not isinstance(receipt.get('files'),list) or len(receipt['files'])>len(PATHS)+MAX_BINARIES
                    or type(receipt.get('bytes_read')) is not int):
                raise ValueError('Invalid firmware receipt schema')
            image_name = source['path'][:-len(SUFFIX+'/inspection.json')]
            image = context.by_path(image_name)
            if not image or receipt['image_sha256'] != image[1]['sha256']:
                raise ValueError('ROM receipt identity mismatch')
            with image[0].open('rb') as handle:
                actual_format='RAW_SQUASHFS' if handle.read(4)==b'hsqs' else 'UNSUPPORTED_IMAGE'
            if receipt['format']!=actual_format:
                raise ValueError('ROM format mismatch')
            seen=set();counted=0
            for row in receipt['files']:
                if (not isinstance(row,dict) or (row.get('image_path') not in PATHS and not (receipt['schema_version']=='1.1' and row.get('kind')=='ELF_CANDIDATE' and binary_path(row.get('image_path'))))
                        or row.get('status') not in ('READ','NOT_READ','TIME_LIMIT','SIZE_LIMIT','UNSUPPORTED_TEXT','UNSUPPORTED_BINARY','ISOLATION_UNAVAILABLE')):
                    raise ValueError('Unexpected firmware path')
                if row['image_path'] in seen:raise ValueError('Duplicate firmware path')
                seen.add(row['image_path'])
                if row['status'] == 'READ':
                    if type(row.get('size')) is not int or not 0<=row['size']<=(MAX_TEXT if row['image_path'] in PATHS else MAX_BINARY):
                        raise ValueError('Invalid extracted size')
                    child = context.by_path(image_name+SUFFIX+'/'+row['image_path'])
                    if not child or child[1]['sha256'] != row['sha256'] or child[1]['size'] != row['size']:
                        raise ValueError('Extracted inventory mismatch')
                    counted+=row['size']
            if receipt['bytes_read']!=counted:
                raise ValueError('Firmware inventory size mismatch')
            reads=any(row['status']=='READ' for row in receipt['files'])
            if (receipt['status']=='PARTIAL_READ')!=reads:
                raise ValueError('Firmware read status mismatch')
            output.append({**receipt,'image_path':image_name,'receipt_source_id':source['source_id'],
                           'provenance_verified':False})
        except IntegrityError:
            raise
        except (ValueError,KeyError,TypeError):
            output.append({'image_path':source['path'],'status':'INVALID_RECEIPT','files':[],
                           'provenance_verified':False})
        if len(output) >= 3:
            break
    return output


def _child():
    import resource
    if len(sys.argv) != 3 or (sys.argv[2] not in PATHS and sys.argv[2]!=LIST_TOKEN and not binary_path(sys.argv[2])):
        raise SystemExit(2)
    tool = shutil.which('unsquashfs', path=os.defpath)
    isolation = shutil.which('bwrap', path=os.defpath)
    if not tool or not isolation:
        raise SystemExit(2)
    resource.setrlimit(resource.RLIMIT_CPU, (3,3))
    resource.setrlimit(resource.RLIMIT_AS, (512*1024*1024,512*1024*1024))
    limit=MAX_TEXT if sys.argv[2] in PATHS or sys.argv[2]==LIST_TOKEN else MAX_BINARY
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit,limit))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64,64))
    resource.setrlimit(resource.RLIMIT_CORE, (0,0))
    tool=str(Path(tool).resolve())
    operation=['-ls'] if sys.argv[2]==LIST_TOKEN else ['-cat']
    members=[] if sys.argv[2]==LIST_TOKEN else [sys.argv[2]]
    os.execve(isolation,[isolation,'--unshare-all','--die-with-parent','--new-session','--cap-drop','ALL',
                    '--ro-bind','/usr/lib','/usr/lib','--ro-bind','/lib','/lib','--ro-bind-try','/lib64','/lib64',
                    '--proc','/proc','--dev','/dev','--tmpfs','/tmp',
                    '--ro-bind',tool,'/reader','--ro-bind',sys.argv[1],'/firmware','--chdir','/tmp',
                    '/reader',*operation,'-no-wildcards','-no-progress','-processors','1',
                    '-data-queue','4','-frag-queue','4','/firmware',*members],
              {'PATH':os.defpath,'LC_ALL':'C'})


if __name__ == '__main__':
    _child()
