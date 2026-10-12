"""Bounded initial reading of supporting materials, never evidence inference.

Path hints choose what to read, not whether a build or CVE condition is true.
Large supporting files stay in the catalogue for targeted model reads.
"""
from pathlib import PurePosixPath
from .sources import read_bounded_excerpt, text_lines
from .integrity import IntegrityError

ROLE_BYTES=8000
ROLE_ATTEMPTS=16
ROLE_FILES={'COMPONENT_DECLARATION':2,'BUILD_CONTEXT':2,'RUNTIME_CONTEXT':3}
TEXT_SUFFIXES={'.json','.jsonl','.txt','.log','.csv','.yaml','.yml','.toml','.xml','.conf'}
NOTE='初始閱讀只提供當次快照原文；角色來自路徑／元件解析線索，不認證 builder、同次建置、部署、語意或漏洞條件。未預讀或截短不表示缺件；可由 READ／SEARCH 繼續讀取。'


def role(path):
    p=PurePosixPath(path.casefold());parts=set(p.parts[:-1]);name=p.name
    if p.suffix not in TEXT_SUFFIXES:return None
    if parts.intersection({'runtime','observations'}) or name in {'runtime-record.json','runtime-receipt.json'}:
        return 'RUNTIME_CONTEXT'
    if (parts.intersection({'build','provenance','attestation'})
            or name in {'build-record.json','build-receipt.json','build-info.json','provenance.json','attestation.json'}):
        return 'BUILD_CONTEXT'
    return None


def prepare(context, identity_candidates):
    identities={r['source_id'] for r in identity_candidates}
    groups={'COMPONENT_DECLARATION':list(identity_candidates),'BUILD_CONTEXT':[],'RUNTIME_CONTEXT':[]}
    for row in sorted(context.sources.values(),key=lambda r:r['path']):
        if row['kind']!='file' or row['source_id'] in identities:continue
        hint=role(row['path'])
        if hint:groups[hint].append(row)
    excerpts=[];records=[];deferred=[];deferred_count=0;errors=[]
    def defer(row,hint,reason):
        nonlocal deferred_count
        deferred_count+=1
        if len(deferred)<20:deferred.append({'source_id':row['source_id'],'path':row['path'],
            'role_hint':hint,'reason':reason,'user_material_missing':False})
    for hint,candidates in groups.items():
        used=0;accepted=0;attempted=0
        for row in candidates:
            if accepted>=ROLE_FILES[hint]:defer(row,hint,'ROLE_FILE_LIMIT');continue
            # Preserve the existing first-page inventory fallback for large
            # component declarations; other roles are offered only when small.
            if row['size']>ROLE_BYTES and hint!='COMPONENT_DECLARATION':
                defer(row,hint,'LARGE_FILE_NEEDS_TARGETED_READ');continue
            if attempted>=ROLE_ATTEMPTS:defer(row,hint,'ROLE_READ_ATTEMPT_LIMIT');continue
            attempted+=1
            try:
                if row['size']<=ROLE_BYTES:
                    lines=text_lines(context,row['source_id'])
                    if len(lines)>200 and hint!='COMPONENT_DECLARATION':
                        defer(row,hint,'LONG_FILE_NEEDS_TARGETED_READ');continue
                    last=min(200,len(lines));complete=len(lines)<=200
                else:last=60;complete=False
                excerpt=read_bounded_excerpt(context,row['source_id'],1,last)
            except IntegrityError:raise
            except (ValueError,OSError):
                errors.append({'source_id':row['source_id'],'gap_kind':'CAPABILITY_GAP'})
                defer(row,hint,'TEXT_READ_UNAVAILABLE');continue
            size=len(excerpt['text'].encode('utf-8'))
            if used+size>ROLE_BYTES:defer(row,hint,'ROLE_BYTE_LIMIT');continue
            used+=size;accepted+=1;excerpts.append(excerpt)
            records.append({'source_id':row['source_id'],'path':row['path'],'excerpt_id':excerpt['excerpt_id'],
                'role_hint':hint,'selection_basis':'NAVIGATION_HINT_ONLY','complete_text':complete,
                'start_line':1,'end_line':excerpt['end_line'],'utf8_bytes':size,
                'semantic_verification':False,'same_build_verified':False})
    return {'excerpts':excerpts,'errors':errors,'reading':{'records':records,
        'deferred':deferred,'deferred_count':deferred_count,'deferred_list_truncated':deferred_count>len(deferred),
        'candidate_count':sum(map(len,groups.values())),'utf8_bytes':sum(r['utf8_bytes'] for r in records),
        'limits':{'bytes_per_role':ROLE_BYTES,'total_bytes':ROLE_BYTES*len(ROLE_FILES),
            'read_attempts_per_role':ROLE_ATTEMPTS,'files_per_role':ROLE_FILES.copy()},
        'note':NOTE}}
