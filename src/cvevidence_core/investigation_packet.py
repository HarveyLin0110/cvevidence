"""Lossless sharing of repeated model input, separate from immutable records."""
from copy import deepcopy
import json
from .integrity import IntegrityError
from .sources import verify_excerpt

EXCERPT_FIELDS=('excerpt_id','source_id','file_sha256','start_line','end_line','text','context_hash')


def compact(context, packet):
    """Keep one copy of each exact excerpt and condition set in this packet.

    No truncation, semantic summary, range merging, or provider history editing.
    References are fixed application fields; external text never chooses them.
    """
    size=lambda value:len(json.dumps(value,ensure_ascii=False,allow_nan=False).encode('utf-8'))
    before=size(packet)
    output=deepcopy(packet)
    conditions_removed=0
    plan=(output.get('condition_plan') or {}).get('conditions')
    for name in ('rule_library','continuation'):
        entry=output.get(name)
        if isinstance(entry,dict) and plan is not None and entry.get('conditions')==plan:
            entry.pop('conditions')
            entry['conditions_ref']='condition_plan.conditions'
            conditions_removed+=1

    canonical={};occurrences=0
    def include(excerpt):
        nonlocal occurrences
        if (not isinstance(excerpt,dict) or not set(EXCERPT_FIELDS)<=set(excerpt)
                or set(excerpt)-set(EXCERPT_FIELDS)-{'path'}):
            raise IntegrityError('Incomplete model input excerpt')
        raw={k:excerpt[k] for k in EXCERPT_FIELDS}
        xid=raw['excerpt_id'];occurrences+=1
        if xid in canonical:
            if {k:canonical[xid][k] for k in EXCERPT_FIELDS}!=raw:
                raise IntegrityError('Conflicting model input excerpt ID')
        else:
            if not verify_excerpt(context,raw):raise IntegrityError('Model input excerpt changed')
            canonical[xid]=raw
        if 'path' in excerpt:
            if excerpt['path']!=context.sources[raw['source_id']]['path']:
                raise IntegrityError('Model input excerpt path changed')
            canonical[xid]['path']=excerpt['path']
        return xid

    for excerpt in output.get('initial_product_excerpts',[]):include(excerpt)
    for row in output.get('pc_evidence_packet',[]):
        originals=row.pop('excerpts',[])
        row['excerpt_ids']=list(dict.fromkeys(include(x) for x in originals))
    resumed=output.get('continuation')
    if isinstance(resumed,dict) and 'excerpts' in resumed:
        resumed['excerpt_ids']=list(dict.fromkeys(include(x) for x in resumed.pop('excerpts')))
    if canonical or 'initial_product_excerpts' in output:
        output['initial_product_excerpts']=list(canonical.values())
    after=size(output)
    return output,{'scope':'INITIAL_MODEL_PACKET_ONLY','original_bytes':before,'transmitted_bytes':after,
        'bytes_removed':before-after,'duplicate_condition_sets_removed':conditions_removed,
        'excerpt_occurrences_before':occurrences,'unique_excerpts_after':len(canonical),
        'duplicate_excerpt_occurrences_removed':occurrences-len(canonical),
        'content_truncated_by_compaction':False,
        'note':'本步僅共用逐字相同的條件與片段，不新增截短；既有來源／索引截短標記保留。byte 差值不是 token 或費用節省，完整保存紀錄不變。'}
