"""Exact product quotations and derived locations, never semantic verdicts."""
import re
from .sources import read_excerpt, verify_excerpt, text_lines
from .integrity import IntegrityError


class ProductQuoteMismatch(ValueError):
    """Point to one rejected quotation, without accepting or rewriting it."""
    def __init__(self,condition,parent,quote):
        super().__init__('evidence_quotes 原文不一致；請逐字摘錄，不省略中間文字、不加行號前綴')
        # Find one bounded raw-text hint using shared words only. No inferred
        # correction or semantic claim; the next REVIEW must pass exact checks.
        terms=set(re.findall(r'[A-Za-z_][A-Za-z_0-9]{2,}',quote))
        lines=parent['text'].splitlines(keepends=True)
        scored=[(len(terms & set(re.findall(r'[A-Za-z_][A-Za-z_0-9]{2,}',line))),i)
                for i,line in enumerate(lines)]
        position=max(scored,key=lambda p:(p[0],-p[1]))[1] if scored else 0
        hint=''.join(lines[max(0,position-1):position+5])[:1200]
        self.feedback={'condition_id':condition['condition_id'],'excerpt_id':parent['excerpt_id'],
            'accepted':False,'original_text_hint':hint,
            'note':'只指出這條件的引文錯誤及同一片段的部分原文，不代表建議摘錄足以支持條件。請核對已讀全文後重新提交 REVIEW；不要為修字重新索取材料。'}

SCHEMA = {'type':'array','maxItems':4,'items':{'type':'object','properties':{
    'excerpt_id':{'type':'string','pattern':r'^X-.+$'},
    'quote':{'type':'string','pattern':r'^[\s\S]{1,1200}$'}},
    'required':['excerpt_id','quote'],'additionalProperties':False}}


def validate(quotes, citations):
    if not isinstance(quotes,list) or len(quotes)>4:
        raise ValueError('evidence_quotes 每條條件最多四段關鍵原文')
    for q in quotes:
        if (not isinstance(q,dict) or set(q)!={'excerpt_id','quote'}
                or not isinstance(q['excerpt_id'],str) or q['excerpt_id'] not in citations
                or not q['excerpt_id'].startswith('X-') or not isinstance(q['quote'],str)
                or not 1<=len(q['quote'].strip())<=1200 or len(q['quote'])>1600):
            raise ValueError('evidence_quotes 須提供 citations 中的 X-ID 與 1–1200 字關鍵原文；少於 8 字只能引用完整短檔案，不得提供行號')


def resolve(context, condition, excerpts, *, require=False):
    quotes=condition.get('evidence_quotes',[])
    validate(quotes,condition['citations'])
    if require and condition['state'] in ('OBSERVED_SUPPORT','OBSERVED_EXCLUSION','CONFLICT') and not quotes:
        raise ValueError('支持／反證／衝突須在 evidence_quotes 摘錄已引用 X-ID 的關鍵原文，由工具計算位置；不能自行估算行號')
    focused=[]
    for q in quotes:
        parent=excerpts.get(q['excerpt_id'])
        if parent is None:
            raise ValueError('evidence_quotes 只能使用本輪已讀的 X-ID')
        if not verify_excerpt(context,parent):raise IntegrityError('Quoted source changed')
        if len(q['quote'].strip())<8:
            full='\n'.join(text_lines(context,parent['source_id']))
            if q['quote']!=parent['text'] or q['quote']!=full:
                raise ValueError('少於 8 字的 evidence_quotes 必須是該短檔案的完整原文；一般片段請增加關鍵上下文')
        offset=parent['text'].find(q['quote'])
        if offset<0:raise ProductQuoteMismatch(condition,parent,q['quote'])
        if parent['text'].find(q['quote'],offset+1)>=0:
            raise ValueError('evidence_quotes 在此片段出現多次；請增加前後原文使位置唯一，或先 READ 較小範圍')
        start=parent['start_line']+parent['text'][:offset].count('\n')
        end=start+q['quote'].count('\n')
        # Keep original line text and independently recheck source bytes.
        x=read_excerpt(context,parent['source_id'],start,end)
        focused.append({**x,'path':context.sources[x['source_id']]['path'],
            'parent_excerpt_id':parent['excerpt_id'],'quote':q['quote'],
            'verification':'EXACT_QUOTE_AND_DERIVED_LOCATOR','meaning_verified':False})
    return focused


# Only generated prose is checked. Uploaded text and exact quotes are data and
# may legitimately describe line numbers. This is a syntax guard, not semantics.
_LINE_REFERENCE=re.compile(
    r'第\s*\d+\s*(?:(?:[-–—~～至到]|、)\s*\d+\s*)*(?:行|列)'
    r'|(?<!\w)\d+\s*[-–—~～至到]\s*\d+\s*(?:行|列)'
    r'|\blines?\s*[:#]?\s*\d+(?:\s*[-–—:]\s*\d+)?'
    r'|\bL\d+(?:[-–—]L?\d+)?\b'
    r'|\.(?:c|h|cc|cpp|py|js|ts|json|conf|txt|csv|log|md|yaml|yml):\d+',re.I)


def reject_prose_locations(value):
    if not isinstance(value,str):raise ValueError('說明須為文字')
    if _LINE_REFERENCE.search(value):
        raise ValueError('說明文字不要自行填數字行號。請以函式／設定名稱及 X-ID 說明，REVIEW 在 evidence_quotes 逐字摘錄，由工具計算並顯示位置。')


def numbered_text(excerpt):
    """Display-only: never replace the canonical text in saved evidence."""
    return '\n'.join(f'{n:>5} | {line}' for n,line in
        enumerate(excerpt['text'].split('\n'),excerpt['start_line']))
