"""Bounded, explainable retrieval. Scores are navigation hints, never evidence."""
import re
from .sources import text_lines


def signals(text):
    paths=set(re.findall(r'(?:[\w.-]+/)*[\w.-]+\.(?:c|h|cc|cpp|py|rs|conf|cmake)\b',text))
    symbols=set(re.findall(r'\b([A-Za-z_]\w{3,80})\s*\(',text))
    symbols.update(re.findall(r'\b(?:CURL|OPENSSL|CONFIG|ENABLE|USE)_[A-Z0-9_]+\b',text))
    return paths, symbols-{'while','switch','return','sizeof'}


def rank(context, text, *, limit=60, scan_limit=200, byte_limit=2_000_000):
    paths,symbols=signals(text); names={p.rsplit('/',1)[-1].casefold() for p in paths}
    terms=sorted(symbols)[:30]
    rows=[]
    for row in context.sources.values():
        if row['kind']!='file':continue
        path=row['path']; lower=path.casefold(); reasons=[]; score=0
        if lower.rsplit('/',1)[-1] in names:score+=100;reasons.append('公告／修補提及檔名')
        if any(lower.endswith(p.casefold()) for p in paths):score+=40;reasons.append('修補路徑相符')
        if lower.endswith(('sbom.cdx.json','build-record.json','compile_commands.json')):score+=80;reasons.append('元件／建置索引')
        if lower.endswith(('.conf','.config','.cmake','.map')):score+=10;reasons.append('設定／連結資料')
        if lower.startswith(('runtime/','observations/')):score+=10;reasons.append('運作觀測')
        rows.append({**row,'relevance_score':score,'relevance_reasons':reasons})
    rows.sort(key=lambda r:(-r['relevance_score'],r['path']))
    scanned=0;total_bytes=0;skipped=0
    for row in rows:
        if scanned>=scan_limit or total_bytes+row['size']>byte_limit:skipped+=1;continue
        if not terms:break
        if row['size']>200000:skipped+=1;continue
        scanned+=1;total_bytes+=row['size']
        try:body='\n'.join(text_lines(context,row['source_id']))
        except ValueError as exc:
            from .integrity import IntegrityError
            if isinstance(exc,IntegrityError):raise
            continue
        hits=[term for term in terms if re.search(r'(?<!\w)'+re.escape(term)+r'(?!\w)',body)]
        if hits:
            row['relevance_score']+=min(90,len(hits)*30)
            row['relevance_reasons'].append('符號／設定：'+', '.join(hits[:5]))
        if row['path'].startswith('build/') and any(p in body for p in paths):
            row['relevance_score']+=70;row['relevance_reasons'].append('建置紀錄提及修補來源（尚待 hash 核對）')
    rows.sort(key=lambda r:(-r['relevance_score'],r['path']))
    return {'sources':[{k:r[k] for k in ('source_id','path','relevance_score','relevance_reasons')} for r in rows[:limit]],
            'total':len(rows),'scanned_files':scanned,'scanned_bytes':total_bytes,'unscanned_files':len(rows)-scanned,
            'truncated':len(rows)>limit,'semantic_verification':False}
