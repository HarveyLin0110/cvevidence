"""Select offered, exact public text without asking the model to retype diffs.

These are public-reference selections, never product evidence or semantic proof.
Only new submissions are expanded; immutable plans retain the original text.
"""
from bisect import bisect_right
from copy import deepcopy
import re
from .public_reader import _source

MAX_QUOTE_CHARS=600


def options(source, *, start_line=1, end_line=None, character_budget=None, skip_long_lines=False):
    text=source['text'];lines=text.splitlines(keepends=True);offsets=[];offset=0
    for line in lines:offsets.append(offset);offset+=len(line)
    last=len(lines) if end_line is None else min(end_line,len(lines))
    output=[];buffer='';buffer_start=0;used=0;omitted=0
    def flush():
        nonlocal buffer
        quote=buffer.strip()
        if len(quote)>=8:
            start=buffer_start+buffer.index(quote);end=start+len(quote)
            output.append({'quote_id':f'Q{start}-{end}','start_line':bisect_right(offsets,start),
                'end_line':bisect_right(offsets,end-1),'text':quote})
        buffer=''
    for index in range(start_line-1,last):
        line=lines[index]
        if ((skip_long_lines and len(line)>1000)
                or character_budget is not None and used+len(line)>character_budget):
            flush();omitted+=1;continue
        used+=len(line);position=offsets[index]
        # Keep normal source lines together; only oversized single lines need
        # character chunks (for example one long CNA description paragraph).
        if buffer and len(line)<=MAX_QUOTE_CHARS and len(buffer)+len(line)>MAX_QUOTE_CHARS:flush()
        while line:
            if not buffer:buffer_start=position
            take=min(len(line),MAX_QUOTE_CHARS-len(buffer))
            buffer+=line[:take];line=line[take:];position+=take
            if len(buffer)==MAX_QUOTE_CHARS:flush()
    flush()
    return {'quote_options':output,'omitted_lines':omitted,'total_saved_lines':len(lines)}


def offered_ids(sources):
    return {(source['source_id'],q['quote_id']) for source in sources for q in source.get('quote_options',[])}


def resolve_submissions(rows, bundle, offered):
    output=deepcopy(rows);selected=[]
    for row in output:
        if not isinstance(row,dict) or 'public_quote_id' not in row:continue
        qid=row.pop('public_quote_id')
        if qid=='':continue  # Existing literal-quote submission remains supported.
        sid=row.get('public_source_id')
        if (not isinstance(sid,str) or not isinstance(qid,str)
                or not re.fullmatch(r'Q[0-9]+-[0-9]+',qid) or (sid,qid) not in offered):
            raise ValueError(f"條件 {row.get('condition_id','?')} 須選本輪該 P-ID 已提供的 public_quote_id；不可猜編號")
        source=_source(bundle,sid)  # Independently recheck saved text/hash.
        start,end=map(int,qid[1:].split('-'));quote=source['text'][start:end]
        if not 0<=start<end<=len(source['text']) or not 8<=len(quote)<=MAX_QUOTE_CHARS:
            raise ValueError('公告引文選項範圍不符')
        if row.get('public_quote') not in ('',quote):
            raise ValueError('public_quote_id 已選原文時，public_quote 留空或與該選項逐字相同；不可混入另一段文字')
        row['public_quote']=quote
        selected.append({'condition_id':row.get('condition_id'),'public_source_id':sid,
            'quote_id':qid,'start_char':start,'end_char':end,'text_sha256':source['text_sha256'],
            'meaning_verified':False})
    return output,selected
