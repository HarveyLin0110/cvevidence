"""Turnkey intake observations; separate availability from proven association."""
from cvevidence_core.turnkey import STATE_LABELS


def render(st, report):
    if not report:return
    st.subheader('Turnkey 材料盤點與下一步')
    st.caption(report['note'])
    if report.get('coverage_limited'):st.warning('本輪盤點有容量限制；未列出不代表不存在。')
    rows=report['recommendations']
    def request(r):
        st.text(r['title']+' · '+STATE_LABELS.get(r['presence_state'],r['presence_state']))
        st.text(r['why'])
        st.text('向'+r['request_owner']+'取得：'+'；'.join(r['candidate_paths']))
        st.caption('解除條件：'+r['completion_condition'])
        st.caption('範圍：'+' / '.join(str(r['scope'][k]) for k in ('family','brand','stage','purpose','abi','host_target')))
    for r in rows:
        if r['priority']=='NOW':request(r)
    with st.expander('後續可選材料與其他 scope（不必一次全部提供）'):
        for r in rows:
            if r['priority']!='NOW':request(r)
    with st.expander('已交材料：內容、角色與綁定狀態'):
        st.dataframe([{'路徑':r['path'],'角色':r['material_role'],'內容格式':r['observed_format'],
            '狀態':STATE_LABELS.get(r['presence_state'],r['presence_state']),
            'scope':' / '.join(r['scope'][k] for k in ('family','stage','purpose','abi','host_target'))}
            for r in report['materials']],hide_index=True)
        for r in report['materials']:
            if r['observations']:
                st.text(r['path']);st.json(r['observations'])
            if r.get('container'):
                st.text('內嵌版本／BSP 欄位（不是已驗建置）');st.json(r['container']['rootfs'])
    import json
    st.download_button('下載 Turnkey 盤點與補件清單',json.dumps(report,ensure_ascii=False,indent=2),
        file_name='turnkey-inventory.json',mime='application/json')
