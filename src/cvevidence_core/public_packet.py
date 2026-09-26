"""Bound outgoing advisory text while retaining the original local snapshots."""
def compact(bundle):
    rows=[]
    for source in bundle.get('sources',[]):
        selected=[];used=0;omitted=0
        for line in source['text'].splitlines():
            # Giant regex/test-fixture lines dominate token costs without helping
            # establish the nearby patch control flow. The full snapshot stays saved.
            if len(line)>1000 or used+len(line)+1>6000:omitted+=1;continue
            selected.append(line);used+=len(line)+1
        rows.append({**{k:v for k,v in source.items() if k!='text'},'text':'\n'.join(selected),
            'text_selection':True,'omitted_lines':omitted,
            'total_saved_lines':len(source['text'].splitlines()),
            'selection_note':'傳送的是受限逐行原文選段；hash 屬完整保存來源。可用 SEARCH_PUBLIC 搜尋 P-ID 保存公告、READ_PUBLIC 讀保存行。未顯示部分不能推定不存在；保存內容本身若截短，工具無法補回。'})
    return {**bundle,'sources':rows}
