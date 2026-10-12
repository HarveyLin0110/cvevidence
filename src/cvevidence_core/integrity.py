"""Deterministic byte identities and bounded, scoped package access."""
from __future__ import annotations
import hashlib,json,os,pathlib,stat,zipfile,tarfile
from dataclasses import dataclass,field
from typing import Any
class IntegrityError(ValueError):pass
class UnsupportedError(ValueError):pass

def canonical(value:Any)->bytes:
 return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')
def digest(value:Any)->str:return hashlib.sha256(canonical(value)).hexdigest()
def file_hash(path:pathlib.Path)->str:
 h=hashlib.sha256()
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
 return h.hexdigest()
def relative(value:str)->pathlib.PurePosixPath:
 p=pathlib.PurePosixPath(value)
 if not value or '\\' in value or '\x00' in value or p.is_absolute() or any(x in ('..','.') for x in value.split('/')):raise IntegrityError('Invalid relative source path')
 return p

def scan(root:pathlib.Path)->list[dict]:
 root=root.resolve();rows=[]
 for p in sorted(root.rglob('*')):
  if p.is_dir() and not p.is_symlink():continue
  rel=p.relative_to(root).as_posix()
  if rel=='manifest.json':continue
  mode=p.lstat().st_mode
  if stat.S_ISLNK(mode):
   target=os.readlink(p)
   if pathlib.Path(target).is_absolute() or not p.resolve().is_relative_to(root) or not p.resolve().is_file():raise IntegrityError('Escaping/dangling symlink: '+rel)
   rows.append({'path':rel,'kind':'symlink','target':target,'sha256':hashlib.sha256(target.encode()).hexdigest(),'size':len(target.encode())})
  elif stat.S_ISREG(mode):rows.append({'path':rel,'kind':'file','sha256':file_hash(p),'size':p.stat().st_size})
  else:raise IntegrityError('Special file: '+rel)
 return rows

def safe_extract(archive:pathlib.Path,destination:pathlib.Path,max_bytes:int=2_000_000_000,max_files:int=40000):
 """Only create new directories; validate all names/types before extracting."""
 if destination.exists():raise IntegrityError('Extraction destination must be new')
 archive=archive.resolve();members=[];links=[];total=0
 handle=zipfile.ZipFile(archive) if zipfile.is_zipfile(archive) else tarfile.open(archive)
 with handle:
  iszip=isinstance(handle,zipfile.ZipFile)
  entries=handle.infolist() if iszip else handle.getmembers()
  if len(entries)>max_files:raise IntegrityError('Archive file limit exceeded')
  seen=set()
  for m in entries:
   name=(m.filename if iszip else m.name).rstrip('/')
   if not name:continue
   rel=relative(name)
   if name in seen:raise IntegrityError('Duplicate archive path')
   seen.add(name)
   directory=m.is_dir() if iszip else m.isdir()
   size=m.file_size if iszip else m.size;total+=size
   if total>max_bytes:raise IntegrityError('Archive expanded size limit exceeded')
   mode=(m.external_attr>>16) if iszip else m.mode
   link=stat.S_ISLNK(mode) if iszip else m.issym()
   if not iszip and not (m.isfile() or directory or link):raise IntegrityError('Unsupported archive member')
   if iszip and stat.S_IFMT(mode) not in (0,stat.S_IFREG,stat.S_IFDIR,stat.S_IFLNK):raise IntegrityError('Unsupported ZIP member')
   if link:
    target=handle.read(m).decode() if iszip else m.linkname
    resolved=(destination/rel).parent/pathlib.Path(target)
    if pathlib.Path(target).is_absolute() or not resolved.resolve().is_relative_to(destination.resolve()):raise IntegrityError('Archive symlink escape')
    links.append((rel,target))
   else:members.append((m,rel,directory,mode))
  linkpaths={str(r) for r,t in links}
  for _,rel,_,_ in members:
   if any(str(p) in linkpaths for p in rel.parents):raise IntegrityError('Archive member traverses symlink')
  for rel,_ in links:
   if any(str(p) in linkpaths for p in rel.parents):raise IntegrityError('Nested archive symlink')
  destination.mkdir(parents=True)
  for m,rel,directory,mode in members:
   dst=destination/rel
   if directory:dst.mkdir(parents=True,exist_ok=True);continue
   dst.parent.mkdir(parents=True,exist_ok=True)
   with (handle.open(m) if iszip else handle.extractfile(m)) as src,dst.open('xb') as out:
    copied=0
    for chunk in iter(lambda:src.read(1024*1024),b''):
     copied+=len(chunk)
     if copied>(m.file_size if iszip else m.size):raise IntegrityError('Archive length mismatch')
     out.write(chunk)
   dst.chmod(0o600 | (mode&0o111))
  for rel,target in links:
   dst=destination/rel;dst.parent.mkdir(parents=True,exist_ok=True);dst.symlink_to(target)
  scan(destination)

@dataclass
class InputPackage:
 root:pathlib.Path
 manifest:dict
 sources:dict[str,dict]
 context_hash:str
 missing:list[str]=field(default_factory=list)
 def public(self)->dict:
  return {'schema_version':'1.0','package_id':self.manifest['package_id'],'product_id':self.manifest['product_id'],'release_id':self.manifest['release_id'],'build_id':self.manifest['build_id'],'format':self.manifest['format'],'context_hash':self.context_hash,'primary_artifact':self.manifest['primary_artifact'],'sources':list(self.sources.values()),'missing':self.missing}
 def assert_current(self):
  try:actual=scan(self.root);current=json.loads((self.root/'manifest.json').read_text())
  except (OSError,ValueError) as e:raise IntegrityError('Input became unavailable or malformed') from e
  if actual!=self.manifest['files'] or current!=self.manifest:raise IntegrityError('STALE_INPUT: package changed after ingestion')
 def source(self,source_id:str)->tuple[pathlib.Path,dict]:
  if source_id not in self.sources:raise IntegrityError('Unknown source_id')
  item=self.sources[source_id];p=self.root/relative(item['path'])
  if item['kind']!='file' or p.is_symlink() or not p.resolve().is_relative_to(self.root):raise IntegrityError('Source is not a declared regular file')
  if not p.is_file() or p.stat().st_size!=item['size'] or file_hash(p)!=item['sha256']:raise IntegrityError('STALE_INPUT: source changed')
  return p,item
 def by_path(self,path:str)->tuple[pathlib.Path,dict]|None:
  relative(path)
  for source_id,row in self.sources.items():
   if row['path']==path:return self.source(source_id) if row['kind']=='file' else None
  return None

def ingest_package(path:str|pathlib.Path,expected_manifest_hash:str|None=None)->InputPackage:
 root=pathlib.Path(path).resolve()
 if not root.is_dir():raise UnsupportedError('Unpack ZIP/tar to a new snapshot directory before ingestion')
 try:manifest=json.loads((root/'manifest.json').read_text())
 except (OSError,ValueError) as e:raise UnsupportedError('Missing or invalid manifest; obtain artifact identity and delivery inventory') from e
 required={'schema_version','package_id','product_id','release_id','build_id','format','primary_artifact','files'}
 if not required<=manifest.keys() or manifest['schema_version']!='1.0':raise UnsupportedError('Unsupported manifest schema')
 if manifest['format'] not in ('rom','cmake','curl','partial'):raise UnsupportedError('Unsupported delivery format')
 if expected_manifest_hash and file_hash(root/'manifest.json')!=expected_manifest_hash:raise IntegrityError('Catalog manifest hash mismatch')
 actual=scan(root)
 if actual!=manifest['files']:raise IntegrityError('Delivered files do not match manifest')
 artifact=manifest['primary_artifact'];relative(artifact['path']);p=root/artifact['path']
 if not p.is_file() or p.is_symlink() or file_hash(p)!=artifact['sha256']:raise IntegrityError('Primary artifact mismatch')
 sources={}
 for row in actual:
  sid='S-'+digest({'path':row['path'],'sha256':row['sha256']})[:24];sources[sid]={**row,'source_id':sid}
 context=digest({'manifest':manifest,'sources':actual})
 return InputPackage(root,manifest,sources,context,['部分材料：產品 binary 與建置身分尚未驗證'] if manifest['format']=='partial' else [])
