"""Small actionable evidence requests; distinct from the inventory or wish list."""
import re
from copy import deepcopy

TEXT_FIELDS = {'condition_id','material','why','owner','how','alternative','insufficiency','expected_resolution'}
FIELDS = TEXT_FIELDS | {'search_terms','existing_source_ids'}
SCHEMA = {'type':'array','items':{'type':'object','properties':{
    **{k:{'type':'string'} for k in TEXT_FIELDS},
    'search_terms':{'type':'array','items':{'type':'string'}},
    'existing_source_ids':{'type':'array','items':{'type':'string'}}},
    'required':sorted(FIELDS),'additionalProperties':False}}


def validate(rows, conditions, *, generic=False):
    if not isinstance(rows,list) or not 1<=len(rows)<=3:
        raise ValueError('每輪只列 1–3 項最小材料；不得用一項包入整份 SDK／所有日誌等清單。')
    ids={r.get('condition_id') for r in rows if isinstance(r,dict)}
    if len(ids)!=1:raise ValueError('本輪只能解除一個最關鍵條件，其他缺口保留在調查進度')
    lookup={r['condition_id']:r for r in conditions}
    seen=set()
    for row in rows:
        if not isinstance(row,dict) or set(row)!=FIELDS:raise ValueError('補件欄位不完整')
        for k in TEXT_FIELDS:
            if not isinstance(row[k],str) or len(row[k])>(180 if k=='material' else 600):raise ValueError('補件文字格式或長度不符')
            if k!='alternative' and not row[k].strip():raise ValueError('每項須說明用途、取得方式、現有材料不足原因與預期結果')
        for k,limit in [('search_terms',3),('existing_source_ids',8)]:
            if not isinstance(row[k],list) or len(row[k])>limit or any(not isinstance(x,str) or not x.strip() or len(x)>150 for x in row[k]):
                raise ValueError('補件查找範圍格式不符')
        if not row['search_terms']:raise ValueError('須提供 1–3 個精確檔名／路徑搜尋詞，讓工具先查既有資料')
        key=re.sub(r'\W','',row['material']).casefold()
        if key in seen:raise ValueError('重複材料請合併，不要重複要求')
        seen.add(key)
        condition=lookup.get(row['condition_id'])
        if not condition:raise ValueError('補件必須指向已知條件')
        if generic and condition['state']!='USER_MATERIAL_MISSING':raise ValueError('只能為使用者材料缺口補件，不能為工具限制或未讀完補件')
    if generic and any(r['state']=='OBSERVED_EXCLUSION' for r in conditions) and not any(r['state']=='CONFLICT' for r in conditions):
        raise ValueError('已有必要條件的排除線索；先 COMPLETE 說明範圍並交工程覆核，不再為其餘條件要求補件。')
    return [dict(deepcopy(row),priority=i+1) for i,row in enumerate(rows)]


def display(row):
    return row['material']+'；向'+row['owner']+'取得：'+row['how']+'；用途：'+row['why']


def validate_legacy(files):
    if not 1<=len(files)<=3 or any(not s.strip() for s in files):raise ValueError('每輪補件限制 1–3 項，請按重要性縮減')
    if len({re.sub(r'\W','',s).casefold() for s in files})!=len(files):raise ValueError('補件不可重複')


def require_actionable_completion(conditions):
    """Unresolved user gaps need an actionable card, not prose-only completion."""
    states={row['state'] for row in conditions}
    if ('USER_MATERIAL_MISSING' in states and not states.intersection(
            {'OBSERVED_EXCLUSION','CONFLICT','CAPABILITY_GAP'})):
        raise ValueError('仍有使用者材料缺口；請 ASK_USER 提出一個最關鍵條件的最小結構化補件，不可只在 COMPLETE 摘要索取。工具限制或證據衝突須在 REVIEW 如實說明，不得為通過檢查改狀態。')
