"""Horace's development verifier CLI; production orchestration belongs to Runner."""
import argparse,json,sys
from .integrity import ingest_package,IntegrityError,UnsupportedError
from .sources import read_excerpt,list_sources
from .supplements import validate_supplement

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 sub=parser.add_subparsers(dest='command',required=True)
 for name in ['inspect','sources','read','validate-supplement','analyze']:
  p=sub.add_parser(name);p.add_argument('package');p.add_argument('--manifest-sha256')
  if name=='sources':p.add_argument('--contains',default='');p.add_argument('--limit',type=int,default=100)
  if name=='read':p.add_argument('source_id');p.add_argument('--start',type=int,default=1);p.add_argument('--end',type=int,default=60)
  if name=='validate-supplement':p.add_argument('supplement')
  if name=='analyze':
   p.add_argument('--cve',action='append');p.add_argument('--symptom',default='');p.add_argument('--mode',choices=['OFFLINE','LIVE'],default='OFFLINE');p.add_argument('--env-file');p.add_argument('--output')
 args=parser.parse_args()
 try:
  if args.command=='analyze':
   from .workflow import analyze_package
   from pathlib import Path
   context=ingest_package(args.package,args.manifest_sha256)
   result=analyze_package(context,args.cve,args.symptom,mode=args.mode,env_file=args.env_file)
   body=json.dumps(result,ensure_ascii=False,indent=2)
   if args.output:
    path=Path(args.output);path.parent.mkdir(parents=True,exist_ok=True);path.write_text(body+'\n');print(json.dumps({'status':result['status'],'output':str(path),'ai_status':result['ai_status']},ensure_ascii=False))
   else:print(body)
   return 0
  context=ingest_package(args.package,args.manifest_sha256)
  if args.command=='inspect':
   result=context.public();result['source_count']=len(result.pop('sources'));result['status']='INTEGRITY_CHECKED';result['assessment']=None
  elif args.command=='sources':result=list_sources(context,args.contains,args.limit)
  elif args.command=='read':result=read_excerpt(context,args.source_id,args.start,args.end)
  else:result=validate_supplement(context,args.supplement)
  print(json.dumps(result,ensure_ascii=False,indent=2));return 0
 except (IntegrityError,UnsupportedError,ValueError,OSError) as e:
  print(json.dumps({'status':'INPUT_ERROR','error':str(e),'assessment':None},ensure_ascii=False),file=sys.stderr);return 2
if __name__=='__main__':sys.exit(main())
