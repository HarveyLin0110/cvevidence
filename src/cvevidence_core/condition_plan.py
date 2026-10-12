"""CVE-specific, source-grounded AI proposals. Never formal condition facts."""
from copy import deepcopy
import re
from .integrity import digest
from .evidence_quotes import SCHEMA as QUOTE_SCHEMA, validate as validate_quotes

STATES = ['NOT_REVIEWED', 'OBSERVED_SUPPORT', 'OBSERVED_EXCLUSION', 'CONFLICT',
          'USER_MATERIAL_MISSING', 'CAPABILITY_GAP']
NECESSITIES = ['REQUIRED', 'ALTERNATIVE_PATH', 'UNDETERMINED']
FIELDS = {'condition_id', 'layer', 'requirement', 'exclusion', 'check', 'public_source_id',
          'public_quote', 'state', 'citations', 'explanation'}
SCHEMA = {'type': 'array', 'maxItems': 8, 'items': {'type': 'object', 'properties': {
    'condition_id': {'type':'string'}, 'layer': {'type':'string','enum':['PC1','PC2','PC3']},
    'necessity': {'type':'string','enum':NECESSITIES},
    **{k:{'type':'string','pattern':r'^[\s\S]{0,700}$'} for k in ('requirement','exclusion','check','public_source_id','public_quote','explanation')},
    'state': {'type':'string','enum':STATES}, 'citations': {'type':'array','maxItems':8,'items':{'type':'string'}},
    'evidence_quotes':QUOTE_SCHEMA},
    'required': sorted(FIELDS|{'evidence_quotes','necessity'}), 'additionalProperties': False}}


def submitted_quote_citations(rows):
    """Treat explicitly selected quote IDs as citations in new submissions.

    No text repair or source lookup. The caller must still validate every ID,
    exact quote, scope and condition. Preserve the raw provider decision for
    history/receipts; never apply this normalization to old saved records.
    """
    output=deepcopy(rows); additions={}
    for row in output:
        if not isinstance(row,dict) or not isinstance(row.get('citations'),list):continue
        quotes=row.get('evidence_quotes',[])
        if not isinstance(quotes,list):continue
        added=[]
        for quote in quotes:
            xid=quote.get('excerpt_id') if isinstance(quote,dict) else None
            if isinstance(xid,str) and xid.startswith('X-') and xid not in row['citations']:
                row['citations'].append(xid);added.append(xid)
        if added:additions[str(row.get('condition_id',''))]=added
    return output,additions


def required_exclusions(rows):
    """Classified proposals only; necessity itself still needs semantic review."""
    return [r for r in rows if r.get('necessity')=='REQUIRED' and r['state']=='OBSERVED_EXCLUSION']


def logic_unresolved(rows):
    # Historical records were flat lists without AND/OR scope. Do not silently
    # classify them as necessary conditions or rewrite their saved hashes.
    return any(r.get('necessity','UNDETERMINED')=='UNDETERMINED' for r in rows)


def required_support(rows):
    necessary=[r for r in rows if r.get('necessity')=='REQUIRED']
    return bool(necessary) and not logic_unresolved(rows) and all(r['state']=='OBSERVED_SUPPORT' for r in necessary)


class QuoteMismatch(ValueError):
    """Exact-source hints remain data; never silently repair a condition."""
    def __init__(self,row,source):
        super().__init__('每個條件須引用 public_sources 中 P-ID 與逐字原文 public_quote；語意仍待覆核')
        self.feedback={'condition_id':row['condition_id'],'source_id':row['public_source_id'],
            'source_known':source is not None,'accepted':False,'candidate_quotes':[],
            'note':'下列是該來源的原文片段，不表示支持此條件。重新核對語意後逐字引用；若沒有支持原文，修正條件或改用已提供的其他來源。不得把摘要當作原文。'}
        if source is None:return
        text=source['text']
        terms=set(re.findall(r'[a-zA-Z_]{3,}',row['public_quote'].lower()))
        pieces=[];offset=0
        # Bounded lexical hints only. No model call and no semantic acceptance.
        for line in text[:120000].splitlines(keepends=True):
            for start in range(0,len(line),600):
                excerpt=line[start:start+600]
                if len(excerpt.strip())<8:continue
                words=set(re.findall(r'[a-zA-Z_]{3,}',excerpt.lower()))
                pieces.append((len(terms & words),offset+start,excerpt))
            offset+=len(line)
        for _,start,quote in sorted(pieces,key=lambda p:(-p[0],p[1]))[:3]:
            self.feedback['candidate_quotes'].append({'start_char':start,'text':quote})


def validate(rows, public_sources, *, previous=None):
    if not isinstance(rows,list) or not 3 <= len(rows) <= 8:
        raise ValueError('條件計畫須有 3–8 項、涵蓋 PC1/PC2/PC3；不是固定五項材料清單。')
    public = {r['source_id']:r for r in public_sources}
    ids=set()
    for row in rows:
        # Older immutable records/rules have no quotation field. Reading them
        # does not fabricate precise quotations or rewrite their hashes.
        if not isinstance(row,dict) or set(row)-{'evidence_quotes','necessity'}!=FIELDS: raise ValueError('條件欄位不完整')
        if 'necessity' in row and row['necessity'] not in NECESSITIES:raise ValueError('條件必要性分類不符')
        for k in FIELDS-{'citations'}:
            if not isinstance(row[k],str) or len(row[k])>700:
                raise ValueError(f"條件 {row.get('condition_id','?')} 的 {k} 須為最多 700 字的文字；公告摘錄須保留逐字一致，不可用省略號拼接")
        if (not re.fullmatch(r'C[1-8]',row['condition_id']) or row['condition_id'] in ids
                or row['layer'] not in ('PC1','PC2','PC3') or row['state'] not in STATES):
            raise ValueError('條件 ID、面向或狀態不符')
        ids.add(row['condition_id'])
        if any(not row[k].strip() for k in ('requirement','exclusion','check','explanation')):
            raise ValueError('逐項說明必要條件、排除條件、驗證方法與理由')
        source=public.get(row['public_source_id'])
        if not source or len(row['public_quote'].strip())<8 or row['public_quote'] not in source['text']:
            raise QuoteMismatch(row,source)
        if (not isinstance(row['citations'],list) or len(row['citations'])>8
                or any(not isinstance(x,str) for x in row['citations'])):
            raise ValueError('條件引用格式不符')
        if row['state'] in ('OBSERVED_SUPPORT','OBSERVED_EXCLUSION','CONFLICT') and not any(x.startswith('X-') for x in row['citations']):
            raise ValueError('支持、反證或衝突須引用已讀的產品原文 X-ID，不能只靠公告或材料盤點')
        validate_quotes(row.get('evidence_quotes',[]),row['citations'])
    if {r['layer'] for r in rows} != {'PC1','PC2','PC3'}: raise ValueError('須涵蓋 PC1、PC2、PC3')
    if previous is None:
        if any(r['state']!='NOT_REVIEWED' or r['citations'] or r.get('evidence_quotes') for r in rows):
            raise ValueError('PLAN 只建立待查條件；讀證據後用 REVIEW 更新觀察')
    else:
        old={r['condition_id']:r for r in previous}
        if ids!=set(old): raise ValueError('REVIEW 不得刪除或新增條件；保留完整未完成清單')
        for row in rows:
            if any(row[k]!=old[row['condition_id']][k] for k in FIELDS-{'state','citations','explanation'}):
                raise ValueError('REVIEW 不得改寫已建立條件與依據')
            if row.get('necessity')!=old[row['condition_id']].get('necessity'):
                raise ValueError('REVIEW 不得改寫條件必要性；須由新的計畫或規則版本釐清')
    return deepcopy(rows)


def record(context, cve, rows):
    return {'schema_version':'1.0','cve_id':cve,'context_hash':context.context_hash,
            'origin':'AI_PROPOSAL','review_required':True,'formal_verdict_unchanged':True,
            'conditions':deepcopy(rows),'plan_hash':digest(rows)}
