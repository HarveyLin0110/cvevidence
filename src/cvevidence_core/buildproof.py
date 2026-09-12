"""Check recorded source -> object -> archive -> linked artifact relationships.

These checks establish internal consistency of delivered build records. They do
not authenticate the supplier or prove an arbitrary compiler log is truthful.
"""
from __future__ import annotations
import hashlib,json,pathlib,subprocess
from .integrity import InputPackage,IntegrityError,file_hash

def archive_members(path:pathlib.Path)->list[dict]:
 data=path.read_bytes()
 if not data.startswith(b'!<arch>\n'):raise IntegrityError('Unsupported or thin archive')
 offset=8;names=b'';result=[]
 while offset<len(data):
  header=data[offset:offset+60]
  if len(header)!=60 or header[58:60]!=b'`\n':raise IntegrityError('Malformed ar member')
  try:size=int(header[48:58].decode().strip())
  except ValueError as e:raise IntegrityError('Malformed ar size') from e
  name=header[:16].decode('ascii').strip();body=data[offset+60:offset+60+size]
  if size<0 or len(body)!=size:raise IntegrityError('Truncated ar member')
  if name=='//':names=body
  elif name not in ('/','/SYM64/'):
   if name.startswith('/') and name[1:].isdigit():
    start=int(name[1:]);end=names.find(b'/\n',start)
    if end<0:raise IntegrityError('Invalid ar long name')
    name=names[start:end].decode('utf-8')
   elif name.startswith('#1/'):
    length=int(name[3:]);name=body[:length].decode('utf-8');body=body[length:]
   else:name=name.rstrip('/')
   result.append({'name':name,'sha256':hashlib.sha256(body).hexdigest(),'size':len(body)})
  offset+=60+size+(size%2)
 if len({x['name'] for x in result})!=len(result):raise IntegrityError('Ambiguous duplicate archive member')
 return result

def elf_needed(context:InputPackage,path:str)->list[str]:
 item=context.by_path(path)
 if not item:raise IntegrityError('ELF source missing')
 p,_=item
 if p.open('rb').read(4)!=b'\x7fELF':raise IntegrityError('Expected ELF artifact')
 proc=subprocess.run(['/usr/bin/readelf','-d','--',str(p)],capture_output=True,text=True,timeout=5)
 if proc.returncode:raise IntegrityError('ELF dynamic section unreadable')
 import re
 return re.findall(r'\(NEEDED\).*?\[([^\]]+)\]',proc.stdout)

def read_json(context,path):
 item=context.by_path(path)
 if not item:return None
 p,row=item
 if row['size']>3_000_000:raise IntegrityError('Record size limit exceeded')
 try:return json.loads(p.read_text())
 except (UnicodeDecodeError,ValueError) as e:raise IntegrityError('Malformed build record') from e

class BuildProof:
 def __init__(self,context:InputPackage):
  self.context=context;self.record=read_json(context,'build/build-record.json')
  self.compilations=[];self.missing=[];self.conflicts=[]
  if not self.record:
   self.missing.append('same-build build-record.json');return
  for key in ['build_id','product_id','release_id','format','primary_artifact']:
   if self.record.get(key)!=context.manifest.get(key):self.conflicts.append('build-record identity differs: '+key)
  for row in context.sources.values():
   if not row['path'].startswith('build/compiler/') or not row['path'].endswith('.json'):continue
   record=read_json(context,row['path'])
   if not isinstance(record,dict) or record.get('returncode')!=0:continue
   record={**record,'source_id':row['source_id'],'record_path':row['path']}
   self.compilations.append(record)
 def identity_matches(self,item)->bool:
  if item.get('external') or pathlib.PurePosixPath(item['path']).is_absolute():return False
  pair=self.context.by_path(item['path'])
  if not pair:return False
  return pair[1]['sha256']==item['sha256'] and pair[1]['size']==item['size']
 def check_record(self,record)->dict:
  missing=[];conflicts=[];checked=[]
  for item in record.get('inputs',[])+record.get('outputs',[]):
   if item.get('external'):continue
   pair=self.context.by_path(item['path'])
   if not pair:missing.append(item['path']);continue
   if pair[1]['sha256']!=item['sha256'] or pair[1]['size']!=item['size']:conflicts.append(item['path'])
   checked.append(pair[1]['source_id'])
  return {'valid':not missing and not conflicts,'missing':missing,'conflicts':conflicts,'source_ids':[record['source_id'],*checked]}
 def output_records(self,path=None,sha256=None):
  return [r for r in self.compilations if any((path is None or o['path']==path) and (sha256 is None or o['sha256']==sha256) for o in r.get('outputs',[]))]
 def source_records(self,path):
  return [r for r in self.compilations if '-c' in r.get('argv',[]) and any(i['path']==path for i in r.get('inputs',[]))]
 def archive_proof(self,path)->dict:
  pair=self.context.by_path(path)
  if not pair:return {'valid':False,'missing':[path],'conflicts':[],'source_ids':[],'members':[],'records':[]}
  members=archive_members(pair[0]);missing=[];conflicts=[];source_ids=[pair[1]['source_id']];records=[]
  for member in members:
   candidates=[r for r in self.compilations if any(pathlib.PurePosixPath(o['path']).name==member['name'] and o['sha256']==member['sha256'] for o in r.get('outputs',[]))]
   if not candidates:missing.append('compile record for archive member '+member['name']);continue
   # A record must independently validate; conflicting present records remain visible.
   checked=[(r,self.check_record(r)) for r in candidates]
   valid=[(r,c) for r,c in checked if c['valid']]
   for _,c in checked:conflicts.extend(c['conflicts'])
   if not valid:missing.extend(x for _,c in checked for x in c['missing']);continue
   r,c=valid[0];records.append(r);source_ids.extend(c['source_ids'])
  return {'valid':bool(members) and not missing and not conflicts,'missing':missing,'conflicts':conflicts,'source_ids':list(dict.fromkeys(source_ids)),'members':members,'records':records}
 def shared_proof(self,library_path,archive_path)->dict:
  library=self.context.by_path(library_path);archive=self.context.by_path(archive_path)
  if not library or not archive:return {'valid':False,'missing':[p for p,pair in [(library_path,library),(archive_path,archive)] if not pair],'conflicts':[],'source_ids':[],'records':[]}
  proof=self.archive_proof(archive_path)
  links=[r for r in self.output_records(sha256=library[1]['sha256']) if any(i['sha256']==archive[1]['sha256'] for i in r.get('inputs',[])) and '-shared' in r.get('argv',[])]
  if not links:proof['valid']=False;proof['missing'].append('link record from archive to '+library_path)
  else:
   check=self.check_record(links[0]);proof['missing']+=check['missing'];proof['conflicts']+=check['conflicts'];proof['source_ids']+=check['source_ids'];proof['valid'] &= check['valid']
  proof['source_ids'].append(library[1]['source_id']);return proof

 def direct_shared_proof(self,library_path):
  pair=self.context.by_path(library_path)
  empty={'valid':False,'missing':[],'conflicts':[],'source_ids':[],'records':[]}
  if not pair:return {**empty,'missing':[library_path]}
  candidates=[r for r in self.output_records(sha256=pair[1]['sha256']) if '-shared' in r.get('argv',[])]
  if not candidates:return {**empty,'missing':['shared link record for '+library_path]}
  link=candidates[0];checked=self.check_record(link)
  result={**checked,'source_ids':[pair[1]['source_id'],*checked['source_ids']],'records':[]}
  objects=[i for i in link.get('inputs',[]) if i['path'].endswith('.o') and not i.get('external')]
  if not objects:result['missing'].append('linked object inventory')
  for item in objects:
   records=self.output_records(path=item['path'],sha256=item['sha256'])
   if not records:result['missing'].append('compiler record for '+item['path']);continue
   check=self.check_record(records[0]);result['records'].append(records[0]);result['source_ids']+=check['source_ids'];result['missing']+=check['missing'];result['conflicts']+=check['conflicts']
   if not records[0].get('dependency_capture',False):result['missing'].append('compiler header capture for '+item['path'])
  result['valid']=bool(objects) and not result['missing'] and not result['conflicts']
  result['source_ids']=list(dict.fromkeys(result['source_ids']));return result

 def product_proof(self,product_path,source_path,library_path,library_needed=None):
  result={'valid':False,'missing':[],'conflicts':[],'source_ids':[],'records':[]}
  product=self.context.by_path(product_path);source=self.context.by_path(source_path);library=self.context.by_path(library_path)
  for path,pair in [(product_path,product),(source_path,source),(library_path,library)]:
   if not pair:result['missing'].append(path)
  if result['missing']:return result
  result['source_ids']=[product[1]['source_id'],source[1]['source_id'],library[1]['source_id']]
  compiles=self.source_records(source_path);links=self.output_records(sha256=product[1]['sha256'])
  matching=[]
  for comp in compiles:
   for link in links:
    if any(o['sha256']==i['sha256'] for o in comp.get('outputs',[]) for i in link.get('inputs',[])):matching.append((comp,link))
  if not matching:result['missing'].append('product source/object/link correspondence');return result
  comp,link=matching[0]
  for r in [comp,link]:
   check=self.check_record(r);result['missing']+=check['missing'];result['conflicts']+=check['conflicts'];result['source_ids']+=check['source_ids']
  if library_needed:
   if library_needed not in elf_needed(self.context,product_path):result['conflicts'].append('product DT_NEEDED does not include '+library_needed)
   if not any(i['sha256']==library[1]['sha256'] for i in link.get('inputs',[])):
    # GCC -l resolution is corroborated by the actual linker map, not guessed.
    map_pair=self.context.by_path('build/product.map')
    if not map_pair:result['missing'].append('resolved product link map')
    else:
     text=map_pair[0].read_text(errors='replace');build_root=self.record.get('build_root','')
     soname=pathlib.PurePosixPath(library_path).name
     short=soname.split('.so')[0]+'.so'
     expected=str(pathlib.PurePosixPath(build_root)/pathlib.PurePosixPath(library_path).parent/short)
     if 'LOAD '+expected not in text:result['missing'].append('library resolution in product map')
     result['source_ids'].append(map_pair[1]['source_id'])
  elif not any(i['sha256']==library[1]['sha256'] for i in link.get('inputs',[])):result['conflicts'].append('static archive differs from actual product link input')
  result['records']=[comp,link];result['valid']=not result['missing'] and not result['conflicts'];result['source_ids']=list(dict.fromkeys(result['source_ids']));return result
