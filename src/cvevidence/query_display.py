"""Describe saved queries without fixing their number or executing them."""
LEGACY_TITLES = {
    'Q1_COMPONENT': '元件與版本', 'Q2_BUILD': '建置身分',
    'Q3_IMPLEMENTATION': '受影響實作', 'Q4_BINDING': '成品綁定與範圍',
    'Q5_PATH': '輸入路徑與必要條件',
}
V2_PURPOSES = {
    'Q1_COMPONENT': '核對實際元件與版本，以及是否屬於本次 CVE 的查核範圍。',
    'Q2_BUILD': '核對成品身分、編譯紀錄與功能設定是否屬於同一次建置。',
    'Q3_IMPLEMENTATION': '檢查脆弱實作、修補或功能排除的工程證據。',
    'Q4_BINDING': '核對原碼、object、library 與成品綁定，以及靜態輸入路徑。',
    'Q5_PATH': '核對同成品運作收據、正常操作原始輸出、樣本與配置；缺件則追加問題。',
}

def query_ids(entry):
    values = entry.get('queries')
    if not isinstance(values, list): return []
    return list(dict.fromkeys(q['query_id'] for q in values if isinstance(q, dict)
                and isinstance(q.get('query_id'), str) and q['query_id']))

def query_title(query, query_id):
    metadata = query.get('metadata')
    metadata = metadata if isinstance(metadata, dict) else {}
    for value in (query.get('title'), metadata.get('title')):
        if isinstance(value, str) and value.strip(): return value
    return LEGACY_TITLES.get(query_id, query_id)

def query_description(query):
    metadata = query.get('metadata')
    metadata = metadata if isinstance(metadata, dict) else {}
    for value in (query.get('description'), metadata.get('description')):
        if isinstance(value, str) and value.strip(): return value
    if query.get('query_plan_version') == '2.0':
        return V2_PURPOSES.get(query.get('query_id'), '此 Query 尚未提供用途說明；請核對保存的發現與來源。')
    return '此保存紀錄沒有用途說明；以下依原始標題、查核發現與引用呈現，不套用新版語意。'
