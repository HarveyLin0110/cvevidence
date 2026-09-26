"""Human-readable progress for AI proposals, separate from formal assessment."""
LABELS = {'NOT_REVIEWED':'尚未查閱完成', 'OBSERVED_SUPPORT':'原文支持線索（待覆核）',
          'OBSERVED_EXCLUSION':'原文反證／排除線索（待覆核）', 'CONFLICT':'證據矛盾（待覆核）',
          'USER_MATERIAL_MISSING':'使用者材料缺口（AI 提案）', 'CAPABILITY_GAP':'工具能力／公開來源缺口'}


def lines(ai):
    plan=ai.get('condition_plan') or {}
    if plan.get('context_hash')!=ai.get('context_hash') or plan.get('cve_id')!=ai.get('cve_id'): return []
    output=['本次 CVE 專屬條件與調查進度（AI 提案，非正式判定）']
    for row in plan.get('conditions',[]):
        output += [row['condition_id']+' · '+row['layer']+' · '+LABELS.get(row['state'],row['state']),
            '必要條件：'+row['requirement'], '排除依據：'+row['exclusion'], '查法：'+row['check'],
            '目前觀察：'+row['explanation'], '產品引用：'+', '.join(row['citations']),
            '公告依據：'+row['public_source_id']+' · '+row['public_quote']]
    for row in (ai.get('condition_dossier') or {}).get('conditions',[]):
        for evidence in row.get('evidence',[]):
            output += [row['condition_id']+' 命中：'+evidence['path']+':'+str(evidence['start_line'])+'–'+str(evidence['end_line']),evidence['text']]
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
        st.text(row['requirement'])
        st.text(row['explanation'])
        detail=dossiers.get(row['condition_id'],{})
        for evidence in detail.get('evidence',[]):
            st.text('命中位置：'+evidence['path']+':'+str(evidence['start_line'])+'–'+str(evidence['end_line']))
            st.code(evidence['text'],language=None)
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
        st.download_button('下載條件與證據覆核包',json.dumps(ai['condition_dossier'],ensure_ascii=False,indent=2),file_name=ai['cve_id']+'-review.json',mime='application/json')
    with st.expander('本次保存的官方公告與修補內容',expanded=False):
        for row in (ai.get('public_sources') or {}).get('sources',[]):
            st.text(row['source_id']+' · '+row['url'])
            st.caption('SHA256：'+row['raw_sha256']+(' · 內容有截斷' if row.get('truncated') else ''))
            st.text(row['text'])
        for row in (ai.get('public_sources') or {}).get('failures',[]): st.text('工具未取得：'+row['url'])


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
