"""Bound outgoing advisory text while retaining the original local snapshots."""
def compact(bundle):
    from .public_quotes import options
    rows=[]
    for source in bundle.get('sources',[]):
        chosen=options(source,character_budget=6000,skip_long_lines=not source['source_id'].startswith('P-CNA-'))
        rows.append({**{k:v for k,v in source.items() if k!='text'},**chosen,'text_selection':True,
            'selection_note':'原文在 quote_options[].text，每段逐字來自保存公告。PLAN／REVIEW／REPORT 可用 public_quote_id 選編號並讓 public_quote 留空，工具還原原文；選項非語意認證。hash 屬完整保存來源。未顯示部分用 SEARCH_PUBLIC／READ_PUBLIC 查保存行，不能推定不存在。'})
    return {**bundle,'sources':rows}
