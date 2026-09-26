"""Read existing identity material and enforce discovery before evidence requests."""
import re
from .sources import read_excerpt
from .integrity import IntegrityError


def prepare(context, public_sources):
    text='\n'.join(s['text'] for s in public_sources)
    names=set(re.findall(r'\b[\w-]+\.(?:c|h|cpp|conf|json)\b',text))
    files=[r for r in context.sources.values() if r['kind']=='file']
    from .component_discovery import components
    declarations=components(context)
    identity_ids={row['source_id'] for row in declarations}
    def score(r):
        path=r['path'].lower(); name=path.rsplit('/',1)[-1]
        if name in ('sbom.cdx.json','build-record.json') or r['source_id'] in identity_ids:return 100
        if name in names and path.startswith('source/'):return 90
        if path.startswith('runtime/'):return 80
        if path.startswith(('install/etc/','observations/')) or path.endswith(('.conf','.config')):return 70
        if name.endswith(('.sh','.patch','.diff')):return 60
        return 0
    ranked=sorted(files,key=lambda r:(-score(r),r['path']))
    from .relevance import rank
    ranking=rank(context,text)
    identity_index=[{'source_id':r['source_id'],'path':r['path'],
                    'relevance_score':80,'relevance_reasons':['已解析元件聲明；尚未驗證建置歸屬']}
                    for r in ranked if r['source_id'] in identity_ids][:20]
    priority_ids={r['source_id'] for r in identity_index}
    index=(identity_index+[r for r in ranking['sources'] if r['source_id'] not in priority_ids])[:60]
    excerpts=[]; errors=[]; remaining=8000
    # Identity facts are read once before asking the model to plan. Code bodies
    # still need targeted searches; the first lines are not treated as absence.
    candidates=[r for r in ranked if score(r)==100][:2]
    for row in candidates:
        try:
            excerpt=read_excerpt(context,row['source_id'],1,60)
            if len(excerpt['text'])>remaining:continue
            remaining-=len(excerpt['text']);excerpts.append({**excerpt})
        except IntegrityError:raise
        except (ValueError,OSError):errors.append({'source_id':row['source_id'],'gap_kind':'CAPABILITY_GAP'})
    from .firmware_inventory import reports
    return {'firmware_inventory':reports(context),'component_declarations':declarations[:20],'component_declarations_total':len(declarations),
            'component_declarations_truncated':len(declarations)>20,
            'retrieval_coverage':{k:v for k,v in ranking.items() if k!='sources'},'source_index':index,'source_index_total':len(files),'initial_product_excerpts':excerpts,
            'read_errors':errors,'note':'已讀片段只支持其中可見內容；排序與檔案存在不是證據，不完整片段不能證明功能不存在。'}


def check_existing(context, requests, visible_excerpts):
    """Exact source reading + full path discovery, not semantic sufficiency."""
    inspected={x['source_id'] for x in visible_excerpts}
    receipt=[]
    for row in requests:
        declared=set(row['existing_source_ids'])
        if not declared<=inspected:raise ValueError('existing_source_ids 含尚未讀取的來源，先 READ 再說明不足')
        matches=[r for r in context.sources.values() if r['kind']=='file' and
                 any(term.casefold() in r['path'].casefold() for term in row['search_terms'])]
        unread=[r for r in matches if r['source_id'] not in inspected]
        if unread:
            hints=[{'source_id':r['source_id'],'path':r['path']} for r in unread[:6]]
            raise ValueError('補件前已找到未讀材料，先 READ；若搜尋詞太廣請縮小到本條件：'+str(hints))
        related={r['source_id'] for r in matches}
        if related and not declared.intersection(related):
            raise ValueError('已找到材料；existing_source_ids 須引用已讀相關來源，insufficiency 說明仍缺哪個內容，不能聲稱整份不存在')
        if not inspected:raise ValueError('尚未讀取任何产品原文；先 READ/SEARCH，不能直接要求補件')
        receipt.append({'condition_id':row['condition_id'],'search_terms':row['search_terms'],
                        'matched_sources':len(matches),'unread_matches':0,
                        'inspected_source_ids':sorted(declared),'semantic_sufficiency_verified':False})
    return receipt
