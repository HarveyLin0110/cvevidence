"""Human-readable progress for AI proposals, separate from formal assessment."""
from .private_downloads import download_button
from cvevidence_core.evidence_quotes import numbered_text
LABELS = {'NOT_REVIEWED':'尚未查閱完成', 'OBSERVED_SUPPORT':'原文支持線索（待覆核）',
          'OBSERVED_EXCLUSION':'原文反證／排除線索（待覆核）', 'CONFLICT':'證據矛盾（待覆核）',
          'USER_MATERIAL_MISSING':'使用者材料缺口（AI 提案）', 'CAPABILITY_GAP':'工具能力／公開來源缺口'}
NECESSITY_LABELS={'REQUIRED':'共同必要條件（AI 分類，待覆核）',
    'ALTERNATIVE_PATH':'替代路徑（此路徑缺席不能單獨排除 CVE）',
    'UNDETERMINED':'必要性尚未分類，交分析端釐清'}


def narrative_sections(value):
    """Break explicit PC headings into paragraphs without changing their wording."""
    import re
    return [part.strip() for part in re.split(r'(?<!\S)(?=PC[123][｜:：])', value) if part.strip()]


def render_overview(st, ai):
    plan = ai.get('condition_plan') or {}
    if plan.get('context_hash') != ai.get('context_hash') or plan.get('cve_id') != ai.get('cve_id'):
        return
    conditions = plan.get('conditions', [])
    from cvevidence_core.investigation_outcome import summarize
    outcome=summarize(ai)
    st.info(outcome['title'])
    st.text('下一步：'+outcome['next_step'])
    if outcome['decisive_condition_ids']:
        st.caption('優先覆核條件：'+'、'.join(outcome['decisive_condition_ids']))
    st.caption(outcome['scope'])
    st.caption('目前查到哪裡：以下是 AI 證據觀察，並非產品受影響判定。')
    for column, layer, title in zip(st.columns(3), ('PC1', 'PC2', 'PC3'),
                                    ('元件與版本', '實作與路徑', '部署與運作')):
        group = [r for r in conditions if r['layer'] == layer]
        column.metric(layer + ' · ' + title, str(len(group)) + ' 個條件')
        counts = {}
        for row in group:
            label = LABELS.get(row['state'], row['state'])
            counts[label] = counts.get(label, 0) + 1
        column.caption('；'.join(label + '：' + str(count) for label, count in counts.items()) or '尚未建立條件')
    if ai.get('status') in ('BUDGET_EXHAUSTED', 'TIMED_OUT', 'CANCELLED'):
        st.info('本輪尚未完成。可展開「開始或接續 AI 調查」，選擇此紀錄接續；已查原文會重新核對，不代表需要先補檔。')


def lines(ai):
    plan=ai.get('condition_plan') or {}
    if plan.get('context_hash')!=ai.get('context_hash') or plan.get('cve_id')!=ai.get('cve_id'): return []
    from cvevidence_core.investigation_outcome import summarize
    outcome=summarize(ai)
    output=[outcome['title'],outcome['scope'],'下一步：'+outcome['next_step'],
            '本次 CVE 專屬條件與調查進度（AI 提案，非正式判定）']
    for row in plan.get('conditions',[]):
        output += [row['condition_id']+' · '+row['layer']+' · '+LABELS.get(row['state'],row['state']),
            '條件類型：'+NECESSITY_LABELS.get(row.get('necessity','UNDETERMINED'),'必要性待覆核'),
            '查核條件：'+row['requirement'], '本條件反證依據：'+row['exclusion'], '查法：'+row['check'],
            '目前觀察：'+row['explanation'], '產品引用：'+', '.join(row['citations']),
            '公告依據：'+row['public_source_id']+' · '+row['public_quote']]
    for row in (ai.get('condition_dossier') or {}).get('conditions',[]):
        for evidence in row.get('focus',[]):
            output += [row['condition_id']+' 關鍵原文位置：'+evidence['path']+':'+str(evidence['start_line'])+'–'+str(evidence['end_line']),numbered_text(evidence)]
        for evidence in row.get('evidence',[]):
            output += [row['condition_id']+' 已讀引用範圍：'+evidence['path']+':'+str(evidence['start_line'])+'–'+str(evidence['end_line']),numbered_text(evidence)]
        output.append(row['condition_id']+' 尚未確認：'+row['unconfirmed'])
    return output


def render(st, ai):
    plan=ai.get('condition_plan') or {}
    if not lines(ai): return
    st.subheader('本次 CVE 專屬條件與調查進度')
    st.caption('以下為有來源的 AI 判讀，仍待工程覆核；不改變原工程判定。未讀完、工具限制與使用者缺件分開處理。')
    dossiers={r['condition_id']:r for r in (ai.get('condition_dossier') or {}).get('conditions',[])}
    for row in plan['conditions']:
        st.text(row['condition_id']+' · '+row['layer']+' · '+LABELS.get(row['state'],row['state']))
        st.caption('條件類型：'+NECESSITY_LABELS.get(row.get('necessity','UNDETERMINED'),'必要性待覆核'))
        st.text(row['requirement'])
        st.text(row['explanation'])
        detail=dossiers.get(row['condition_id'],{})
        for evidence in detail.get('focus',[]):
            st.text('關鍵原文位置：'+evidence['path']+':'+str(evidence['start_line'])+'–'+str(evidence['end_line']))
            st.code(numbered_text(evidence),language=None)
        if detail.get('evidence') and not detail.get('focus'):
            st.caption('此紀錄只有已讀引用範圍，未保存可精確定位的關鍵摘錄；AI 文字中的細部行號未經獨立核對。')
        for number, evidence in enumerate(detail.get('evidence',[]), 1):
            with st.expander(row['condition_id']+' 已讀引用範圍 '+str(number)+' · '+evidence['path']+'（'+str(evidence['start_line'])+'–'+str(evidence['end_line'])+' 行）',expanded=False):
                st.code(numbered_text(evidence),language=None)
        if detail:st.caption('尚未確認：'+detail['unconfirmed'])
        with st.expander(row['condition_id']+'：排除條件、查法與引用',expanded=False):
            st.text('排除依據：'+row['exclusion']); st.text('查法：'+row['check'])
            st.text('公告原文：'+row['public_quote']); st.caption(row['public_source_id'])
            st.text('產品原文引用：'+', '.join(row['citations']))
    if any(r['state']=='CAPABILITY_GAP' for r in plan['conditions']):
        st.info('工具能力不足的項目由開發端／工程覆核處理，不要求使用者反覆補檔。')
    if any(r['state']=='NOT_REVIEWED' for r in plan['conditions']):
        st.info('尚未查閱完成的項目是調查待辦，不代表使用者缺件。')
    if ai.get('condition_dossier'):
        import json
        download_button(st, '下載條件與證據覆核包',json.dumps(ai['condition_dossier'],ensure_ascii=False,indent=2),file_name=ai['cve_id']+'-review.json',mime='application/json')
    from cvevidence_core.rule_library import draft
    try:
        rule=draft(ai)
    except (ValueError,KeyError,TypeError):
        rule=None
    if rule:
        import json
        with st.expander('將這個 CVE 的查核方法加入規則庫'):
            st.caption('只匯出公告與條件草稿，不附本產品原文片段或引用。條件文字仍須檢查是否含敏感資訊。需由規則維護者逐條覆核、保存測試依據後啟用；不會因為 AI 產生草稿就自動發布。')
            download_button(st, '下載 CVE 規則草稿',json.dumps(rule,ensure_ascii=False,indent=2),
                file_name=ai['cve_id']+'-rule-draft.json',mime='application/json')
            st.text('維護者使用 scripts/rule_library.py：review 保存覆核版本，activate 指定啟用版本。公告變更時自動退回重新規劃；舊版本可回復。')
            if ai.get('rule_library'):st.json(ai['rule_library'])
    with st.expander('本次保存的官方公告與修補內容',expanded=False):
        for row in (ai.get('public_sources') or {}).get('sources',[]):
            st.text(row['source_id']+' · '+row['url'])
            if row.get('reference_origins'):
                st.caption('CVE 參考連結出處：'+'、'.join(r['container']+(' / '+r['provider'] if r.get('provider') else '') for r in row['reference_origins']))
            if row.get('publisher_scope')=='DOWNSTREAM_DISTRIBUTION':
                st.info('這是下游發行版公告；修補版本及受影響範圍不能直接套用到你的產品。')
            st.caption('SHA256：'+row['raw_sha256']+(' · 內容有截斷' if row.get('truncated') else ''))
            st.text(row['text'])
        for row in (ai.get('public_sources') or {}).get('failures',[]): st.text('工具未取得：'+row['url'])
        for url in (ai.get('public_sources') or {}).get('unsupported_references',[]):st.text('來源政策尚未支援：'+url)
        for url in (ai.get('public_sources') or {}).get('unvisited_references',[]):st.text('本輪達時間或數量上限，尚未讀取：'+url)
        if (ai.get('public_sources') or {}).get('references_truncated'):st.caption('CVE 參考連結清單有截短，這不是完整來源查核。')


def render_requests(st, ai):
    final=next((t for t in reversed(ai.get('tasks',[])) if t.get('status')=='COMPLETED' and t.get('action')=='ASK_USER'),None)
    rows=(final or {}).get('evidence_requests',[])
    if not rows:return False
    st.subheader('本輪最小補件：只解除一個關鍵缺口')
    for row in rows:
        st.text(str(row['priority'])+'. '+row['material'])
        st.text('取得方式：向'+row['owner']+'取得；'+row['how'])
        st.caption('用途：'+row['why'])
        if row['alternative']:st.text('替代方式（擇一）：'+row['alternative'])
        with st.expander('詳細要求：'+row['material'],expanded=False):
            st.text('條件：'+row['condition_id'])
            st.text('現有材料為何不足：'+row['insufficiency'])
            st.text('取得後能確認：'+row['expected_resolution'])
    return True
