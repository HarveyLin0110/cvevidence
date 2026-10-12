"""Bounded reading of related files in one model step; never execute inputs."""
from .sources import read_bounded_excerpt
from .integrity import IntegrityError

MAX_BATCH_BYTES=48000


def read_batch(context, source_ids, start_line, end_line):
    if (not isinstance(source_ids,list) or not 2<=len(source_ids)<=3
            or any(not isinstance(s,str) for s in source_ids)
            or len(set(source_ids))!=len(source_ids)):
        raise ValueError('READ_BATCH 需要 2–3 個不同產品 source_id，共用同一段行範圍')
    if (type(start_line) is not int or type(end_line) is not int or start_line<1
            or end_line<start_line or end_line-start_line>=200):
        raise ValueError('Invalid line range')
    excerpts=[];failures=[];size=0
    for sid in source_ids:
        try:
            excerpt=read_bounded_excerpt(context,sid,start_line,end_line)
        except IntegrityError:
            # A changed/out-of-scope input invalidates the operation, not just
            # one optional read. Never downgrade integrity failures to capacity.
            raise
        except ValueError as exc:
            failures.append({'source_id':sid,'start_line':start_line,'end_line':end_line,
                'error':str(exc),'read_completed':False})
            continue
        length=len(excerpt['text'].encode('utf-8'))
        if size+length>MAX_BATCH_BYTES:
            failures.append({'source_id':sid,'start_line':start_line,'end_line':end_line,
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
