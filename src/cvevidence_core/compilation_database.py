"""Compilation recipe declarations, not executed builds or authenticated provenance."""
import json
import posixpath
from collections import defaultdict

MAX_DATABASE_BYTES=2_000_000
MAX_ENTRIES=2000
MAX_VISIBLE_ENTRIES=20
NOTE='編譯資料庫只宣告編譯方式；未執行命令、不開啟宣告的主機路徑，路徑候選不證明編譯已執行、物件已連結、同 build 或成品採用。請 READ 原文核對需要引用的欄位；未列出的副本不能推論未使用。'


def _object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('Duplicate JSON key')
        result[key]=value
    return result


def _entry(row,index,by_name):
    if not isinstance(row,dict):raise ValueError('Entry must be an object')
    directory=row.get('directory');file=row.get('file');output=row.get('output')
    for text in (directory,file):
        if not isinstance(text,str) or not text or len(text)>1024 or any(ord(c)<32 for c in text):raise ValueError('Invalid path declaration')
    if output is not None and (not isinstance(output,str) or len(output)>1024 or any(ord(c)<32 for c in output)):
        raise ValueError('Invalid output declaration')
    args=row.get('arguments');command=row.get('command')
    if args is not None:
        if (not isinstance(args,list) or not args or len(args)>512
                or any(not isinstance(a,str) or len(a)>4096 or '\0' in a for a in args)):
            raise ValueError('Invalid arguments')
        kind='ARGUMENTS'
    elif isinstance(command,str) and command and len(command)<=16384 and '\0' not in command:kind='COMMAND'
    else:raise ValueError('Compile command missing or limited')
    result={'entry_index':index,'declared_directory':directory,'declared_file':file,'declared_output':output,
            'command_form':kind,'candidate_source_ids':[],'candidate_count':0,'candidates_truncated':False,
            'command_executed':False,'command_file_consistency_verified':False,'artifact_binding_verified':False}
    if not directory.startswith('/') or '\\' in directory+file:
        return {**result,'state':'UNSUPPORTED_PATH_STYLE'}
    normalized=posixpath.normpath(posixpath.join(directory,file))
    candidates=by_name.get(posixpath.basename(normalized),[])
    suffix=[r for r in candidates if normalized.endswith('/'+r['path'])]
    candidates=suffix or candidates
    state='PATH_SUFFIX_CANDIDATE' if suffix else 'BASENAME_CANDIDATE' if candidates else 'NOT_IN_DELIVERED_PATHS'
    if len(candidates)>1:state='AMBIGUOUS_PATH_CANDIDATES'
    return {**result,'state':state,'normalized_declared_file':normalized,
            'candidate_source_ids':[r['source_id'] for r in candidates[:8]],
            'candidate_count':len(candidates),'candidates_truncated':len(candidates)>8}


def inspect(context,preferred_source_ids=()):
    files=[r for r in context.sources.values() if r['kind']=='file']
    by_name=defaultdict(list)
    for row in files:by_name[posixpath.basename(row['path'])].append(row)
    candidates=sorted((r for r in files if posixpath.basename(r['path'])=='compile_commands.json'),key=lambda r:r['path'])
    results=[];preferred=set(preferred_source_ids)
    for row in candidates[:4]:
        record={'source_id':row['source_id'],'path':row['path'],'sha256':row['sha256'],
                'entries':[],'command_executed':False,'artifact_binding_verified':False}
        if row['size']>MAX_DATABASE_BYTES:
            results.append({**record,'status':'DATABASE_TOO_LARGE','coverage_limited':True});continue
        path,_=context.source(row['source_id'])
        try:
            data=json.loads(path.read_text(),object_pairs_hook=_object)
            if not isinstance(data,list):raise ValueError('Database must be an array')
        except (ValueError,UnicodeError,RecursionError):
            results.append({**record,'status':'MALFORMED_DATABASE','coverage_limited':True});continue
        entries=[];invalid=0
        for index,item in enumerate(data[:MAX_ENTRIES],1):
            try:entry=_entry(item,index,by_name)
            except ValueError:entry={'entry_index':index,'state':'MALFORMED_OR_LIMITED_ENTRY'};invalid+=1
            entries.append(entry)
        entries.sort(key=lambda r:(not preferred.intersection(r.get('candidate_source_ids',[])),
                                   not r.get('candidate_source_ids'),r['entry_index']))
        results.append({**record,'status':'DECLARATIONS_ONLY','entries':entries[:MAX_VISIBLE_ENTRIES],
                        'entries_total':len(data),'entries_examined':len(entries),'invalid_entries':invalid,
                        'entries_omitted':len(data)-min(len(entries),MAX_VISIBLE_ENTRIES),
                        'coverage_limited':len(data)>MAX_VISIBLE_ENTRIES or bool(invalid)})
    return {'records':results,'database_count':len(candidates),'databases_omitted':max(0,len(candidates)-4),'note':NOTE}
