#!/usr/bin/env python3
"""Compiler observer for today's builds. Records actual exit status and bytes."""
import datetime,hashlib,json,os,pathlib,shlex,subprocess,sys,tempfile,uuid
args=sys.argv[1:]; root=pathlib.Path(os.environ['CVEVIDENCE_BUILD_ROOT']).resolve()
audit=root/'build/compiler'; audit.mkdir(parents=True,exist_ok=True)
def identity(p):
 p=pathlib.Path(p).resolve()
 if not p.is_file():return None
 return {'path':p.relative_to(root).as_posix() if p.is_relative_to(root) else str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'size':p.stat().st_size,'external':not p.is_relative_to(root)}
inputs=[identity(x) for x in args if not x.startswith('-') and pathlib.Path(x).is_file()]
inputs=[x for x in inputs if x]
dep=None; actual=list(args)
if '-c' in args and any(x.endswith('.c') for x in args):
 fd,dep=tempfile.mkstemp(prefix='cvevidence-deps-');os.close(fd);actual+=['-MD','-MF',dep]
started=datetime.datetime.now(datetime.timezone.utc).isoformat()
proc=subprocess.run(['/usr/bin/gcc',*actual])
outputs=[]
if '-o' in args:
 value=identity(args[args.index('-o')+1]);outputs=[value] if value else []
elif '-c' in args:
 outputs=[identity(pathlib.Path(x).stem+'.o') for x in args if x.endswith(('.c','.s','.S'))];outputs=[x for x in outputs if x]
if dep:
 try:
  s=pathlib.Path(dep).read_text().replace('\\\n',' ')
  inputs.extend(x for x in (identity(x) for x in shlex.split(s.split(':',1)[1])) if x)
 except (OSError,IndexError):pass
 pathlib.Path(dep).unlink(missing_ok=True)
record={'started_at':started,'cwd':str(pathlib.Path.cwd()),'argv':['/usr/bin/gcc',*actual],'returncode':proc.returncode,'inputs':list({x['path']:x for x in inputs}.values()),'outputs':outputs}
(audit/(uuid.uuid4().hex+'.json')).write_text(json.dumps(record,sort_keys=True)+'\n')
sys.exit(proc.returncode)
