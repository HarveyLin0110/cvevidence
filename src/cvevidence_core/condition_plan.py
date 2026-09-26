"""CVE-specific, source-grounded AI proposals. Never formal condition facts."""
from copy import deepcopy
import re
from .integrity import digest

STATES = ['NOT_REVIEWED', 'OBSERVED_SUPPORT', 'OBSERVED_EXCLUSION', 'CONFLICT',
          'USER_MATERIAL_MISSING', 'CAPABILITY_GAP']
FIELDS = {'condition_id', 'layer', 'requirement', 'exclusion', 'check', 'public_source_id',
          'public_quote', 'state', 'citations', 'explanation'}
SCHEMA = {'type': 'array', 'items': {'type': 'object', 'properties': {
    'condition_id': {'type':'string'}, 'layer': {'type':'string','enum':['PC1','PC2','PC3']},
    **{k:{'type':'string'} for k in ('requirement','exclusion','check','public_source_id','public_quote','explanation')},
    'state': {'type':'string','enum':STATES}, 'citations': {'type':'array','items':{'type':'string'}}},
    'required': sorted(FIELDS), 'additionalProperties': False}}


def validate(rows, public_sources, *, previous=None):
    if not isinstance(rows,list) or not 3 <= len(rows) <= 8:
        raise ValueError('條件計畫須有 3–8 項、涵蓋 PC1/PC2/PC3；不是固定五項材料清單。')
    public = {r['source_id']:r for r in public_sources}
    ids=set()
    for row in rows:
        if not isinstance(row,dict) or set(row)!=FIELDS: raise ValueError('條件欄位不完整')
        for k in FIELDS-{'citations'}:
            if not isinstance(row[k],str) or len(row[k])>700: raise ValueError('條件文字過長或格式不符')
        if (not re.fullmatch(r'C[1-8]',row['condition_id']) or row['condition_id'] in ids
                or row['layer'] not in ('PC1','PC2','PC3') or row['state'] not in STATES):
            raise ValueError('條件 ID、面向或狀態不符')
        ids.add(row['condition_id'])
        if any(not row[k].strip() for k in ('requirement','exclusion','check','explanation')):
            raise ValueError('逐項說明必要條件、排除條件、驗證方法與理由')
        source=public.get(row['public_source_id'])
        if not source or len(row['public_quote'].strip())<8 or row['public_quote'] not in source['text']:
            raise ValueError('每個條件須引用 public_sources 中 P-ID 與逐字原文 public_quote；語意仍待覆核')
        if (not isinstance(row['citations'],list) or len(row['citations'])>8
                or any(not isinstance(x,str) for x in row['citations'])):
            raise ValueError('條件引用格式不符')
        if row['state'] in ('OBSERVED_SUPPORT','OBSERVED_EXCLUSION','CONFLICT') and not any(x.startswith('X-') for x in row['citations']):
            raise ValueError('支持、反證或衝突須引用已讀的產品原文 X-ID，不能只靠公告或材料盤點')
    if {r['layer'] for r in rows} != {'PC1','PC2','PC3'}: raise ValueError('須涵蓋 PC1、PC2、PC3')
    if previous is None:
        if any(r['state']!='NOT_REVIEWED' or r['citations'] for r in rows):
            raise ValueError('PLAN 只建立待查條件；讀證據後用 REVIEW 更新觀察')
    else:
        old={r['condition_id']:r for r in previous}
        if ids!=set(old): raise ValueError('REVIEW 不得刪除或新增條件；保留完整未完成清單')
        for row in rows:
            if any(row[k]!=old[row['condition_id']][k] for k in FIELDS-{'state','citations','explanation'}):
                raise ValueError('REVIEW 不得改寫已建立條件與依據')
    return deepcopy(rows)


def record(context, cve, rows):
    return {'schema_version':'1.0','cve_id':cve,'context_hash':context.context_hash,
            'origin':'AI_PROPOSAL','review_required':True,'formal_verdict_unchanged':True,
            'conditions':deepcopy(rows),'plan_hash':digest(rows)}
