"""Bounded reading of related files in one model step; never execute inputs."""
from .sources import read_bounded_excerpt
from .integrity import IntegrityError

MAX_BATCH_BYTES=48000
RANGES_SCHEMA={'type':'array','maxItems':3,'items':{'type':'object','properties':{
    'source_id':{'type':'string'},'start_line':{'type':'integer','minimum':1},
    'end_line':{'type':'integer','minimum':1}},
    'required':['source_id','start_line','end_line'],'additionalProperties':False},
    'description':'只供 READ_BATCH：2–3 段產品原文，各指定 source_id/start_line/end_line，source_ids=[] 且外層行號=1。其餘 action 用 []；READ_BATCH 也可用 [] 沿用 source_ids 共同行範圍。'}


def read_batch(context, source_ids, start_line, end_line, *, read_ranges=None):
    if read_ranges is not None and not isinstance(read_ranges,list):
        raise ValueError('read_ranges 須為陣列')
    if read_ranges:
        if source_ids!=[] or type(start_line) is not int or type(end_line) is not int or (start_line,end_line)!=(1,1):
            raise ValueError('指定 read_ranges 時，source_ids 留 []、外層行號填 1；不要混用兩種範圍')
        if not 2<=len(read_ranges)<=3:raise ValueError('read_ranges 需要 2–3 段產品原文')
        ranges=[]
        for row in read_ranges:
            if (not isinstance(row,dict) or set(row)!={'source_id','start_line','end_line'}
                    or not isinstance(row['source_id'],str)):
                raise ValueError('read_ranges 欄位不符')
            ranges.append((row['source_id'],row['start_line'],row['end_line']))
    else:
        if (not isinstance(source_ids,list) or not 2<=len(source_ids)<=3
                or any(not isinstance(s,str) for s in source_ids)
                or len(set(source_ids))!=len(source_ids)):
            raise ValueError('READ_BATCH 需要 2–3 個不同產品 source_id，共用行範圍；不同範圍請用 read_ranges')
        ranges=[(sid,start_line,end_line) for sid in source_ids]
    # Validate every range before reading anything. IDs are resolved only by
    # the scoped reader; a later integrity failure still invalidates the batch.
    for _,first,last in ranges:
        if (type(first) is not int or type(last) is not int or first<1
                or last<first or last-first>=200):raise ValueError('Invalid line range')
    if len(set(ranges))!=len(ranges):raise ValueError('read_ranges 不可重複同一來源與行範圍')
    excerpts=[];failures=[];size=0
    for sid,first,last in ranges:
        try:
            excerpt=read_bounded_excerpt(context,sid,first,last)
        except IntegrityError:
            # A changed/out-of-scope input invalidates the operation, not just
            # one optional read. Never downgrade integrity failures to capacity.
            raise
        except ValueError as exc:
            failures.append({'source_id':sid,'start_line':first,'end_line':last,
                'error':str(exc),'read_completed':False})
            continue
        length=len(excerpt['text'].encode('utf-8'))
        if size+length>MAX_BATCH_BYTES:
            failures.append({'source_id':sid,'start_line':first,'end_line':last,
                'error':'本檔超過批次原文合計 48000 bytes；請另外 READ 此檔或縮小範圍。',
                'read_completed':False})
            continue
        size+=length
        excerpts.append(excerpt)
    return {'matches':excerpts,'failures':failures,'coverage_limited':bool(failures),
        'read_kind':'BOUNDED_BATCH',
        'note':'只有 matches 內的 X-ID 已成功閱讀；failures 尚未讀成，不代表缺件。成功片段可直接引用，不必重讀。大檔可先 SEARCH 定位，再 READ 較小範圍；各檔仍不是全文、語意或同建置驗證。'}


def completed_reads(task):
    """Only successful explicit reads satisfy reading/continuation gates."""
    if task.get('status')!='COMPLETED':return []
    result=task.get('result') or {}
    if task.get('action')=='READ':return [result]
    if task.get('action')=='READ_BATCH':return result.get('matches',[])
    return []
