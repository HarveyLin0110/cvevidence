"""Frankie v0.2 intake adapter. Real files only; does not synthesize analysis.

Set CVEVIDENCE_CORE_MODULE=cvevidence_core.frankie_adapter in the Runner.
The next contract revision must add stages/facts/assessment/AI separately.
"""
import hashlib,pathlib,tempfile
from contextlib import contextmanager
from .integrity import ingest_package,safe_extract,IntegrityError

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
