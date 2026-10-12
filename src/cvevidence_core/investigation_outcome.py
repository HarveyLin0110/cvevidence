"""Deterministic explanation of investigation progress, not an AI verdict."""
from .integrity import digest
from .condition_plan import required_exclusions,logic_unresolved,required_support

LABELS={'NOT_ANALYZED':'尚未完成條件分析','INCOMPLETE':'調查尚未完成，可接續現有材料',
    'LOGIC_REVIEW_REQUIRED':'須先釐清必要條件與替代路徑',
    'CONFLICT':'材料有矛盾，須先釐清適用範圍','CAPABILITY_GAP':'工具／公告能力不足，交由分析端處理',
    'NEEDS_MATERIAL':'已有分析，僅需補關鍵缺口','EXCLUSION_OBSERVED':'找到排除線索，待覆核涵蓋範圍',
    'SUPPORT_OBSERVED':'必要條件均有支持線索，待工程覆核','PARTIAL_OBSERVATIONS':'已取得部分線索，尚不能作產品結論'}

NEXT_STEPS={
    'LOGIC_REVIEW_REQUIRED':'由分析端依公告釐清哪些是共同必要條件、哪些是替代路徑；局部路徑缺席不能排除整體 CVE，不因此向使用者追加材料。舊紀錄沒有分類時須建立新計畫或規則版本，原紀錄保留。',
    'NOT_ANALYZED':'先根據公告建立條件並查閱現有材料。',
    'INCOMPLETE':'先接續尚未完成的查核；未查完不等於使用者缺件。',
    'CONFLICT':'先釐清互相矛盾的材料及其產品／建置範圍。',
    'CAPABILITY_GAP':'由分析端處理工具或公開來源缺口，不要求使用者補整套資料。',
    'NEEDS_MATERIAL':'只補本輪最小補件卡所列的關鍵材料，其餘先保留。',
    'EXCLUSION_OBSERVED':'先覆核排除線索是否涵蓋本次目標成品及全部相關副本；其餘未解條件保留，不因它們仍未知就繼續補件。',
    'SUPPORT_OBSERVED':'逐項覆核公告適用性、證據語意及成品關聯；這些支持線索尚未成為正式受影響判定。',
    'PARTIAL_OBSERVATIONS':'先覆核已有觀察並確認最有價值的下一項查核。',
}


def summarize(ai):
    plan=ai.get('condition_plan') or {};rows=plan.get('conditions',[])
    valid=(rows and plan.get('plan_hash')==digest(rows) and plan.get('context_hash')==ai.get('context_hash')
           and plan.get('cve_id')==ai.get('cve_id'))
    if not valid:rows=[]
    states={r['state'] for r in rows}
    exclusions=required_exclusions(rows)
    if not rows:status='NOT_ANALYZED'
    elif ai.get('status') not in ('COMPLETED','NEEDS_USER_INPUT'):status='INCOMPLETE'
    elif 'CONFLICT' in states:status='CONFLICT'
    elif logic_unresolved(rows):status='LOGIC_REVIEW_REQUIRED'
    # A necessary-condition exclusion is a reason to review its scope first,
    # even when other conditions remain unknown. Keep those gaps in the rows;
    # do not turn this observation into a formal Not Affected verdict.
    elif exclusions:status='EXCLUSION_OBSERVED'
    # Once a supported common condition establishes at least one applicable
    # route, unread alternatives are not additional mandatory prerequisites.
    # Their states remain visible and are not silently marked reviewed.
    elif required_support(rows):status='SUPPORT_OBSERVED'
    elif 'NOT_REVIEWED' in states:status='INCOMPLETE'
    elif 'CAPABILITY_GAP' in states:status='CAPABILITY_GAP'
    elif 'USER_MATERIAL_MISSING' in states:status='NEEDS_MATERIAL'
    else:status='PARTIAL_OBSERVATIONS'
    dossier={r['condition_id']:r for r in (ai.get('condition_dossier') or {}).get('conditions',[])}
    details=[]
    for r in rows:
        d=dossier.get(r['condition_id'],{})
        details.append({'condition_id':r['condition_id'],'layer':r['layer'],'requirement':r['requirement'],
            'necessity':r.get('necessity','UNDETERMINED'),
            'state':r['state'],'finding':r['explanation'],'next_check':r['check'],
            'hits':[{'source_id':x['source_id'],'path':x['path'],'start_line':x['start_line'],
                     'end_line':x['end_line'],'excerpt_id':x['excerpt_id'],
                     'location_kind':'EXACT_QUOTE' if d.get('focus') else 'READ_RANGE'}
                    for x in (d.get('focus') or d.get('evidence',[]))],
            'gap_owner':'analysis_team' if r['state'] in ('NOT_REVIEWED','CAPABILITY_GAP') else
                        'material_owner' if r['state']=='USER_MATERIAL_MISSING' else 'reviewer'})
    return {'status':status,'title':LABELS[status],'next_step':NEXT_STEPS[status],
        'decisive_condition_ids':[r['condition_id'] for r in rows if (status=='CONFLICT' or r.get('necessity')=='REQUIRED') and r['state']==
            ('CONFLICT' if status=='CONFLICT' else 'OBSERVED_EXCLUSION' if status=='EXCLUSION_OBSERVED' else 'OBSERVED_SUPPORT')]
            if status in ('CONFLICT','EXCLUSION_OBSERVED','SUPPORT_OBSERVED') else [],
        'conditions':details,'formal_verdict_unchanged':True,
        'scope':'本次產品材料與 CVE 條件的調查結果；原文命中不等於實際出貨、可觸發、已遭利用或異常原因。'}
