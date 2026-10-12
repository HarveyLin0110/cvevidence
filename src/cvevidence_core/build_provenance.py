"""Compare declared in-toto/SLSA digests with delivered bytes, not trust/signatures."""
import json
import re
from collections import defaultdict
from .integrity import IntegrityError

NOTE='僅核對建置聲明中的 SHA256 與已交付檔案；未驗簽、未認證 builder、未證明真實建置或完整輸入。不能直接作為同 build 或漏洞排除證據。'


def _object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('Duplicate JSON key')
        result[key]=value
    return result


def inspect(context):
    files=[r for r in context.sources.values() if r['kind']=='file']
    by_hash=defaultdict(list);by_path={r['path']:r for r in files}
    for row in files:by_hash[row['sha256']].append(row)
    candidates=sorted((r for r in files if r['path'].lower().endswith('.json')),key=lambda r:(
        0 if any(s in r['path'].lower() for s in ('provenance','attestation','build')) else 1,r['path']))
    results=[];read=0
    for row in candidates[:32]:
        if len(results)>=4:break
        if row['size']>256*1024:continue
        path,record=context.source(row['source_id']);read+=1
        try:data=json.loads(path.read_text(),object_pairs_hook=_object)
        except (ValueError,UnicodeError,RecursionError):continue
        if not isinstance(data,dict):continue
        result={'source_id':row['source_id'],'path':row['path'],'sha256':record['sha256'],
                'signature_verified':False,'builder_authenticated':False,'same_build_verified':False,'references':[]}
        if data.get('payloadType')=='application/vnd.in-toto+json':
            results.append({**result,'status':'ENVELOPE_NOT_SUPPORTED'});continue
        if data.get('_type')!='https://in-toto.io/Statement/v1' or data.get('predicateType')!='https://slsa.dev/provenance/v1':continue
        try:
            predicate=data['predicate']
            if not isinstance(predicate,dict):raise ValueError()
            definition=predicate['buildDefinition']
            if not isinstance(definition,dict):raise ValueError()
            subjects=data['subject'];dependencies=definition.get('resolvedDependencies') or []
            if not isinstance(subjects,list) or not subjects or not isinstance(dependencies,list):raise ValueError()
            if len(subjects)+len(dependencies)>32:
                results.append({**result,'status':'REFERENCE_LIMIT'});continue
            refs=[]
            for role,entries in (('subject',subjects),('dependency',dependencies)):
                for entry in entries:
                    if not isinstance(entry,dict):raise ValueError()
                    name=entry.get('name') or entry.get('uri') or ''
                    if not isinstance(name,str) or len(name)>500:raise ValueError()
                    digests=entry.get('digest') or {}
                    if not isinstance(digests,dict):raise ValueError()
                    value=digests.get('sha256')
                    ref={'role':role,'declared_name':name,'declared_sha256':None,'matched_source_ids':[],
                         'named_source_conflict':False,'state':'NO_SUPPORTED_DIGEST'}
                    if value is not None:
                        if not isinstance(value,str) or not re.fullmatch(r'[0-9a-fA-F]{64}',value):raise ValueError()
                        value=value.lower();ref['declared_sha256']=value
                        matches=by_hash.get(value,[])
                        ref['state']='MATCHES_DELIVERED_BYTES' if matches else 'NOT_IN_SNAPSHOT'
                        for match in matches[:8]:context.source(match['source_id'])
                        ref['matched_source_ids']=[r['source_id'] for r in matches[:8]]
                        ref['matches_truncated']=len(matches)>8
                        if name in by_path and by_path[name]['sha256']!=value:
                            context.source(by_path[name]['source_id'])
                            ref['named_source_conflict']=True
                    refs.append(ref)
            state='DECLARED_DIGESTS_MATCH' if dependencies and all(r['state']=='MATCHES_DELIVERED_BYTES' for r in refs) else 'PARTIAL_DIGEST_COVERAGE'
            if any(r['named_source_conflict'] for r in refs):state='NAMED_SOURCE_CONFLICT'
            result.update(status=state,references=refs)
        except IntegrityError:raise
        except (KeyError,TypeError,ValueError):
            result.update(status='MALFORMED_DECLARATION',references=[])
        results.append(result)
    return {'records':results,'json_files_read':read,'json_files_total':len(candidates),
            'coverage_limited':read<len(candidates),'note':NOTE}
