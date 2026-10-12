"""Bounded reading of related files in one model step; never execute inputs."""
from .sources import read_bounded_excerpt

MAX_BATCH_BYTES=48000


def read_batch(context, source_ids, start_line, end_line):
    if (not isinstance(source_ids,list) or not 2<=len(source_ids)<=3
            or any(not isinstance(s,str) for s in source_ids)
            or len(set(source_ids))!=len(source_ids)):
        raise ValueError('READ_BATCH 需要 2–3 個不同產品 source_id，共用同一段行範圍')
    excerpts=[];size=0
    for sid in source_ids:
        excerpt=read_bounded_excerpt(context,sid,start_line,end_line)
        size+=len(excerpt['text'].encode('utf-8'))
        if size>MAX_BATCH_BYTES:
            raise ValueError('READ_BATCH 原文合計超過 48000 bytes；請縮小行範圍或減少檔案，這批尚未完成閱讀')
        excerpts.append(excerpt)
    return {'matches':excerpts,'read_kind':'BOUNDED_BATCH',
        'note':'各檔使用相同行範圍且逐份核對；不是全文、語意或同建置驗證。'}


def completed_reads(task):
    """Only successful explicit reads satisfy reading/continuation gates."""
    if task.get('status')!='COMPLETED':return []
    result=task.get('result') or {}
    if task.get('action')=='READ':return [result]
    if task.get('action')=='READ_BATCH':return result.get('matches',[])
    return []
