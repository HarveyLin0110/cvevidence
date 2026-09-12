"""Data integrity/lineage acceptance only. Does not score CVE verdicts or AI."""
import argparse,datetime,json,pathlib,shutil,sys,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from cvevidence_core.integrity import ingest_package,scan,file_hash,safe_extract
from cvevidence_core.supplements import validate_supplement

def validate(catalog_path):
 catalog=json.loads(catalog_path.read_text());base=ROOT/'var/artifacts/datasets'/catalog['dataset_version'];cases=[]
 for entry in catalog['packages']:
  archive=ROOT/entry['archive']['relative_path']
  assert file_hash(archive)==entry['archive']['sha256'];assert archive.stat().st_size==entry['archive']['size_bytes']
  source=base/('packages' if entry['kind']=='initial' else 'supplements')/entry['package_id']
  assert file_hash(source/'manifest.json')==entry['manifest_sha256']
  with tempfile.TemporaryDirectory(prefix='cvevidence-acceptance-',dir=ROOT/'var/validation') as temp:
   target=pathlib.Path(temp)/'extracted';safe_extract(archive,target)
   if entry['kind']=='initial':
    context=ingest_package(target,entry['manifest_sha256']);context.assert_current()
    cases.append({'package_id':entry['package_id'],'archive_roundtrip':'PASS','source_count':len(context.sources),'primary_artifact':context.manifest['primary_artifact']})
   else:
    initial=ingest_package(base/'packages'/entry['base_package_id']);plan=validate_supplement(initial,target)
    assert plan['can_merge']
    merged=pathlib.Path(temp)/'merged';shutil.copytree(initial.root,merged,symlinks=True)
    for row in plan['added_files']:
     src=target/row['path'];dst=merged/row['path'];dst.parent.mkdir(parents=True,exist_ok=True)
     if src.is_symlink():dst.symlink_to(src.readlink())
     else:shutil.copy2(src,dst)
    manifest={**initial.manifest,'package_id':initial.manifest['package_id']+'-supplemented','files':scan(merged)}
    (merged/'manifest.json').write_text(json.dumps(manifest,indent=2))
    completed=ingest_package(merged)
    assert completed.manifest['primary_artifact']==initial.manifest['primary_artifact']
    cases.append({'package_id':entry['package_id'],'archive_roundtrip':'PASS','same_build_merge':'PASS','added_files':len(plan['added_files']),'before_file_count':len(initial.sources),'after_file_count':len(completed.sources),'engineering_assessment':'NOT_RUN'})
 return {'dataset_version':catalog['dataset_version'],'cases':cases,'data_gate':'PASS','engineering_gate':'NOT_RUN','live_ai_gate':'NOT_RUN'}
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('catalogs',nargs='+');args=parser.parse_args();started=time.monotonic()
 report={'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'datasets':[validate(pathlib.Path(p)) for p in args.catalogs]};report['elapsed_seconds']=round(time.monotonic()-started,3)
 output=ROOT/'var/validation'/('data-acceptance-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'.json');output.write_text(json.dumps(report,indent=2)+'\n');print(output);print(json.dumps(report,indent=2))
