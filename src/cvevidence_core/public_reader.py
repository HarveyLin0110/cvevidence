"""Read only already collected public snapshots; never fetch model-supplied URLs."""
import hashlib
from .integrity import IntegrityError


def _source(bundle, source_id):
    rows=[s for s in bundle.get('sources',[]) if s.get('source_id')==source_id]
    if len(rows)!=1:raise ValueError('本輪沒有唯一對應的公告 P-ID')
    source=rows[0];text=source.get('text')
    if (not isinstance(text,str) or len(text.encode())>512000
            or hashlib.sha256(text.encode()).hexdigest()!=source.get('text_sha256')):
        raise IntegrityError('保存公告內容完整性不符')
    return source


def read(bundle, source_id, start, end):
    source=_source(bundle,source_id)
    if type(start) is not int or type(end) is not int or not 1<=start<=end or end-start>=200:
        raise ValueError('公告 READ 最多 200 行，行號從 1 開始')
    lines=source['text'].splitlines()
    if start>len(lines):raise ValueError('公告行號超出保存範圍')
    end=min(end,len(lines));text='\n'.join(lines[start-1:end])
    if len(text.encode())>8000:raise ValueError('公告片段超過 8000 bytes，請縮小行數；單行超限屬工具限制')
    return {'public_source_id':source_id,'url':source['url'],'start_line':start,'end_line':end,
            'total_lines':len(lines),'text':text,'text_sha256':source['text_sha256'],
            'snapshot_truncated':source.get('truncated',False),
            'role':'PUBLIC_REFERENCE_NOT_PRODUCT_EVIDENCE',
            'note':'保存文字的行號，不是上游網頁／原碼行號。P-ID 只作公告引用，不產生產品 X-ID 或受影響判定。'}


def search(bundle, source_ids, term):
    if not isinstance(term,str) or not term.strip() or len(term)>200:
        raise ValueError('公告 SEARCH 需要 1–200 字元的字面關鍵字')
    ids=list(dict.fromkeys(source_ids or [s['source_id'] for s in bundle.get('sources',[])]))
    matches=[];limited=False
    for sid in ids:
        source=_source(bundle,sid)
        for number,line in enumerate(source['text'].splitlines(),1):
            if term.casefold() not in line.casefold():continue
            if len(matches)>=8:limited=True;continue
            matches.append({'public_source_id':sid,'line':number,'text':line[:700],
                            'line_truncated':len(line)>700})
    return {'public_matches':matches,'matches_limited':limited,
            'role':'PUBLIC_REFERENCE_NOT_PRODUCT_EVIDENCE',
            'note':'僅搜尋本輪保存公告；未命中不表示上游沒有，使用 READ_PUBLIC 讀附近保存行。'}
