"""Publish new immutable demo data revisions from completed builds only."""
import argparse,datetime,json,pathlib,shutil,sys,tarfile,uuid
from build import ROOT,write,sha
sys.path.insert(0,str(ROOT/'src'))
from cvevidence_core.integrity import scan,digest

def omitted(family,relative):
 if family=='rom':
  return relative.startswith(('source/openssl/','build/compiler/','build/t1_lib.i','build/s3_pkt.i')) or (relative.startswith('build/commands/') and ('openssl-' in relative or 'preprocess-' in relative))
 if family=='cmake':
  return relative=='source/update_reader.c' or relative=='source/CMakeLists.txt' or relative.startswith(('build/compiler/','build/cmake/','build/product.map')) or (relative.startswith('build/commands/') and 'cmake-' in relative)
 if family=='curl':return relative.startswith(('install/download-update.sh','install/etc/','observations/')) or (relative.startswith('build/commands/') and 'normal-socks5-' in relative)
 raise ValueError('Unknown format')

def copy_selected(source,target,predicate):
 target.mkdir(parents=True,exist_ok=False)
 for row in scan(source):
  rel=row['path']
  # The private key is exclusively a short-lived local smoke-test fixture.
  if rel=='observations/key.pem' or not predicate(rel):continue
  dst=target/rel;dst.parent.mkdir(parents=True,exist_ok=True)
  if row['kind']=='symlink':dst.symlink_to(row['target'])
  else:shutil.copy2(source/rel,dst)

def manifest(path,package_id,record,kind='initial',base_package_id=None):
 value={k:record[k] for k in ['schema_version','product_id','release_id','build_id','format','primary_artifact']}
 value.update(package_id=package_id,kind=kind,files=scan(path),created_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
 if base_package_id:value['base_package_id']=base_package_id
 write(path/'manifest.json',value)
 return value

def export(family,first,second,revision):
 src=[pathlib.Path(first).resolve(),pathlib.Path(second).resolve()]
 for p in src:
  if not p.is_relative_to(ROOT/'var/build') or not (p.parent/'completed.json').is_file():raise ValueError('Only today completed builds may be packaged')
 records=[json.loads((p/'build/build-record.json').read_text()) for p in src]
 if any(r['format']!=family for r in records):raise ValueError('Format mismatch')
 dest=ROOT/'var/artifacts/datasets'/revision
 if dest.exists():raise ValueError('Dataset revision already exists')
 start={'rom':1,'cmake':4,'curl':7}[family];ids=[f'{start+i:02d}_{family}' for i in range(3)]
 dest.mkdir(parents=True);(dest/'packages').mkdir();(dest/'supplements').mkdir()
 for i in range(2):
  target=dest/'packages'/ids[i];copy_selected(src[i],target,lambda _:True);manifest(target,ids[i],records[i])
 origin=1 if family=='rom' else 0;partial=dest/'packages'/ids[2]
 copy_selected(src[origin],partial,lambda p:not omitted(family,p));pm=manifest(partial,ids[2],records[origin])
 supplement=dest/'supplements'/('supplement_'+ids[2]);copy_selected(src[origin],supplement,lambda p:omitted(family,p))
 # Supplement identity anchors refer to the initial primary artifact; no fake replacement binary.
 sm={k:records[origin][k] for k in ['schema_version','product_id','release_id','build_id','format','primary_artifact']}
 sm.update(package_id='supplement_'+ids[2],kind='supplement',base_package_id=ids[2],files=scan(supplement),created_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
 write(supplement/'manifest.json',sm)
 archives=ROOT/'var/artifacts/archives'/revision;archives.mkdir(parents=True,exist_ok=False)
 entries=[]
 for folder in [*sorted((dest/'packages').iterdir()),supplement]:
  archive=archives/(folder.name+'.tar.gz')
  with tarfile.open(archive,'w:gz',dereference=False) as t:
   for p in sorted(folder.iterdir()):t.add(p,arcname=p.name)
  m=json.loads((folder/'manifest.json').read_text())
  entries.append({'package_id':folder.name,'kind':m['kind'],'format':family,'product_id':m['product_id'],'release_id':m['release_id'],'build_id':m['build_id'],'primary_artifact':m['primary_artifact'],'manifest_sha256':sha(folder/'manifest.json'),'archive':{'filename':archive.name,'sha256':sha(archive),'size_bytes':archive.stat().st_size,'relative_path':archive.relative_to(ROOT).as_posix(),'download_url':None},'base_package_id':m.get('base_package_id'),'file_count':len(m['files'])})
 catalog={'schema_version':'1.0','dataset_version':revision,'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'packages':entries,'notes':['Fresh 2026-09-12 builds; expected verdicts are not distributed in this catalog.','Download location pending team artifact delivery.','Official OSS license files included in source trees.']}
 write(ROOT/'data/catalogs'/(revision+'.json'),catalog)
 print('DATASET COMPLETE',dest,flush=True)
 return catalog
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('family',choices=['rom','cmake','curl']);p.add_argument('first');p.add_argument('second');p.add_argument('--revision',required=True);a=p.parse_args();export(a.family,a.first,a.second,a.revision)
