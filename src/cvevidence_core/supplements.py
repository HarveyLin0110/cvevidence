"""Pure supplement semantics; snapshot persistence belongs to Frankie's Runner."""
from __future__ import annotations
import json,pathlib
from .integrity import InputPackage,IntegrityError,scan,digest

def validate_supplement(context:InputPackage,path:str|pathlib.Path)->dict:
 context.assert_current();root=pathlib.Path(path).resolve()
 try:manifest=json.loads((root/'manifest.json').read_text())
 except (OSError,ValueError) as e:raise IntegrityError('Invalid supplement manifest') from e
 if manifest.get('schema_version')!='1.0' or manifest.get('kind')!='supplement':raise IntegrityError('Unsupported supplement schema')
 files=scan(root)
 if manifest.get('files')!=files:raise IntegrityError('Supplement inventory or hash mismatch')
 for field in ['product_id','release_id','build_id','format','primary_artifact']:
  if manifest.get(field)!=context.manifest.get(field):
   return {'status':'DIFFERENT_BUILD','reason':'Identity differs: '+field,'can_merge':False,'requires_new_release':True,'source_context_hash':context.context_hash}
 if manifest.get('base_package_id')!=context.manifest['package_id']:raise IntegrityError('Supplement targets a different package')
 original={r['path']:r for r in context.manifest['files']};added=[];duplicates=[]
 for row in files:
  if row['path'] in original:
   if row!=original[row['path']]:raise IntegrityError('Conflicting replacement in same-build supplement: '+row['path'])
   duplicates.append(row['path'])
  else:added.append(row)
 return {'status':'READY_FOR_NEW_SNAPSHOT','can_merge':True,'requires_new_release':False,'source_context_hash':context.context_hash,'supplement_hash':digest(manifest),'added_files':added,'identical_duplicates':duplicates,'primary_artifact':context.manifest['primary_artifact'],'instructions':'Runner must create a new immutable snapshot and run, retain parent_run_id, then re-ingest, collect, verify and assess. This validation itself is not an assessment.'}

def interpret_statement(text:str,source_context_hash:str)->dict:
 if not isinstance(text,str) or not text.strip() or len(text)>16000:raise ValueError('Statement must contain 1 to 16000 characters')
 value={'text':text,'source_context_hash':source_context_hash,'kind':'USER_STATEMENT','verified_engineering_fact':False}
 return {'material_id':'M-'+digest(value)[:24],**value,'review_required':True,'effect':'Investigation context only; do not change formal conditions without verified original evidence.'}
