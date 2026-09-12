"""Frankie v0.2 intake adapter. Real files only; does not synthesize analysis.

Set CVEVIDENCE_CORE_MODULE=cvevidence_core.frankie_adapter in the Runner.
The next contract revision must add stages/facts/assessment/AI separately.
"""
import hashlib,pathlib,tempfile
from contextlib import contextmanager
from .integrity import ingest_package,safe_extract,IntegrityError,file_hash

@contextmanager
def package_from_bytes(payload:bytes):
 if not isinstance(payload,bytes) or not payload or len(payload)>512*1024*1024:raise IntegrityError('Archive payload is empty or exceeds adapter limit')
 # Runner is responsible for its workspace; temporaries stay beneath that workspace.
 temp_root=pathlib.Path.cwd()/'var/intake-temporary';temp_root.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='core-',dir=temp_root) as temp:
  folder=pathlib.Path(temp);archive=folder/'payload.archive';archive.write_bytes(payload)
  destination=folder/'package';safe_extract(archive,destination)
  yield ingest_package(destination)

def collect_for_runner(payload:bytes)->dict:
 with package_from_bytes(payload) as context:
  records=[{'evidence_id':sid,'path':row['path'],'sha256':row['sha256'],'size':row['size'],'kind':'source_file','verification':'HASH_MATCH'} for sid,row in context.sources.items() if row['kind']=='file']
  return {'package_id':context.manifest['package_id'],'release_id':context.manifest['release_id'],'declared_build_id':context.manifest['build_id'],'archive_sha256':hashlib.sha256(payload).hexdigest(),'evidence':records,'missing':context.missing,'limitations':['Intake and file integrity only. Source IDs are not verified engineering fact IDs.','No assessment or AI output is produced by this v0.2 collection adapter.','Hash consistency does not authenticate supplier provenance.']}

def read_evidence_for_runner(payload:bytes,record:dict)->bytes:
 with package_from_bytes(payload) as context:
  path,row=context.source(record['evidence_id'])
  for field in ['path','sha256','size']:
   if record.get(field)!=row[field]:raise IntegrityError('Evidence reference differs from this archive')
  if row['size']>1024*1024:raise IntegrityError('Preview exceeds 1 MiB; add a ranged source reference in the next contract')
  return path.read_bytes()

def analyze_archive_for_runner(archive_path,options=None,*,expected_archive_sha256=None,expected_context_hash=None,
                               temporary_root=None,env_file=None,event_callback=None):
 """New stage proposal. File references/config are trusted Runner inputs, never AI tools."""
 from .workflow import analyze_package
 archive=pathlib.Path(archive_path)
 if archive.is_symlink() or not archive.is_file() or not 0<archive.stat().st_size<=512*1024*1024:raise IntegrityError('無效的工程壓縮包')
 actual=file_hash(archive)
 if expected_archive_sha256 and actual!=expected_archive_sha256:raise IntegrityError('工程壓縮包 hash 不一致')
 options=options or {}
 if set(options)-{'requested_cves','symptom','statements','claims','mode'}:raise ValueError('不支援的分析選項')
 temp=pathlib.Path(temporary_root) if temporary_root else pathlib.Path.cwd()/'var/intake-temporary'
 temp.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='analysis-',dir=temp) as folder:
  destination=pathlib.Path(folder)/'package';safe_extract(archive,destination)
  if file_hash(archive)!=actual:raise IntegrityError('收件時壓縮包發生變更')
  context=ingest_package(destination)
  if expected_context_hash and context.context_hash!=expected_context_hash:raise IntegrityError('分析快照與原 run 不一致')
  result=analyze_package(context,**options,env_file=env_file,event_callback=event_callback)
  result['archive_sha256']=actual
  return result
