"""Deterministic explanation of investigation progress, not an AI verdict."""
from .integrity import digest

LABELS={'NOT_ANALYZED':'尚未完成條件分析','INCOMPLETE':'調查尚未完成，可接續現有材料',
    'CONFLICT':'材料有矛盾，須先釐清適用範圍','CAPABILITY_GAP':'工具／公告能力不足，交由分析端處理',
    'NEEDS_MATERIAL':'已有分析，僅需補關鍵缺口','EXCLUSION_OBSERVED':'找到排除線索，待覆核涵蓋範圍',
    'SUPPORT_OBSERVED':'必要條件均有支持線索，待工程覆核','PARTIAL_OBSERVATIONS':'已取得部分線索，尚不能作產品結論'}


def summarize(ai):
    plan=ai.get('condition_plan') or {};rows=plan.get('conditions',[])
    valid=(rows and plan.get('plan_hash')==digest(rows) and plan.get('context_hash')==ai.get('context_hash')
           and plan.get('cve_id')==ai.get('cve_id'))
    if not valid:rows=[]
    states={r['state'] for r in rows}
    if not rows:status='NOT_ANALYZED'
    elif ai.get('status') not in ('COMPLETED','NEEDS_USER_INPUT'):status='INCOMPLETE'
    elif 'CONFLICT' in states:status='CONFLICT'
    elif 'NOT_REVIEWED' in states:status='INCOMPLETE'
    elif 'CAPABILITY_GAP' in states:status='CAPABILITY_GAP'
    elif 'USER_MATERIAL_MISSING' in states:status='NEEDS_MATERIAL'
    elif 'OBSERVED_EXCLUSION' in states:status='EXCLUSION_OBSERVED'
    elif states=={'OBSERVED_SUPPORT'}:status='SUPPORT_OBSERVED'
    else:status='PARTIAL_OBSERVATIONS'
    dossier={r['condition_id']:r for r in (ai.get('condition_dossier') or {}).get('conditions',[])}
    details=[]
    for r in rows:
        d=dossier.get(r['condition_id'],{})
        details.append({'condition_id':r['condition_id'],'layer':r['layer'],'requirement':r['requirement'],
            'state':r['state'],'finding':r['explanation'],'next_check':r['check'],
            'hits':[{'source_id':x['source_id'],'path':x['path'],'start_line':x['start_line'],
                     'end_line':x['end_line'],'excerpt_id':x['excerpt_id'],
                     'location_kind':'EXACT_QUOTE' if d.get('focus') else 'READ_RANGE'}
                    for x in (d.get('focus') or d.get('evidence',[]))],
            'gap_owner':'analysis_team' if r['state'] in ('NOT_REVIEWED','CAPABILITY_GAP') else
                        'material_owner' if r['state']=='USER_MATERIAL_MISSING' else 'reviewer'})
    return {'status':status,'title':LABELS[status],'conditions':details,'formal_verdict_unchanged':True,
        'scope':'本次產品材料與 CVE 條件的調查結果；原文命中不等於實際出貨、可觸發、已遭利用或異常原因。'}
