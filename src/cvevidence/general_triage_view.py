"""Presentation for a completed inventory with unverified CVE conditions."""
import json
from cvevidence_core.public_cve import brief

STATES = {'PLANNED': '待開始', 'MATERIALS_AVAILABLE': '可先查閱已提交材料',
          'WAITING_EVIDENCE': '待定位或補充材料'}


def summary_lines(entry):
    assessment = entry.get('assessment') or {}
    if assessment.get('assessment_kind') != 'GENERAL_TRIAGE':
        return []
    info = brief(entry['public_cve_record'])
    output = ['需要進一步調查', '已完成：交付材料盤點。尚未執行：此 CVE 的漏洞條件驗證。',
              assessment['reason'], '公開 CVE 資料狀態：' + info['status'],
              '來源：' + info['source_url']]
    if info['status'] == 'PUBLISHED':
        output += [info.get('title', ''), info.get('description', ''),
                   '公告涉及產品與版本：' + json.dumps(info.get('affected', []), ensure_ascii=False)]
    else:
        output.append('公開公告尚不可用、未公開或已撤回，請核對公告與編號；不代表產品安全。')
    output.append('本次查核計畫（材料存在不代表內容已驗證）')
    for q in (entry.get('query_plan') or {}).get('queries', []):
        output += [q['query_id'] + ' · ' + q['pc_layer'] + ' · ' + STATES.get(q['status'], q['status']),
                   q['description'], '所需材料：' + q['materials'], q['reason'],
                   '已定位材料：' + str(q['available_source_count']) + '；僅為檔案盤點。']
    return output


def render(st, entry):
    st.warning('需要進一步調查')
    st.text('已完成：交付材料盤點。尚未執行：此 CVE 的漏洞條件驗證。')
    st.text(entry['assessment']['reason'])
    info = brief(entry['public_cve_record'])
    st.subheader('本次 CVE 的公開資料')
    st.text('公開資料狀態：' + info['status'])
    st.text('來源：' + info['source_url'])
    if info['status'] == 'PUBLISHED':
        st.text(info.get('title', ''))
        for item in info.get('affected', []):
            st.text('公告涉及：' + item['vendor'] + ' / ' + item['product'])
            st.text('公告版本資料：' + json.dumps(item['versions'], ensure_ascii=False))
        with st.expander('公告摘要與來源紀錄'):
            st.text(info.get('description', ''))
            st.caption('公開公告只提供調查線索；未證明本次成品受影響。')
            st.text('保存紀錄 SHA256：' + info['record_sha256'])
    else:
        st.info('公告尚不可用、未公開或已撤回；請核對公告與編號，不能據此判安全。')
    st.subheader('PC1／PC2／PC3：目前都待驗證')
    st.text('PC1：公告目標是否屬於本成品。PC2：實作、修補、功能與靜態路徑。PC3：同成品實際部署與運作。')
    st.subheader('本次查核計畫')
    for q in entry['query_plan']['queries']:
        with st.expander(q['query_id'] + ' · ' + q['pc_layer'] + ' · ' + STATES.get(q['status'], q['status']), expanded=True):
            st.text(q['description'])
            st.text('為何需要：' + q['reason'])
            st.text('所需材料：' + q['materials'])
            if q['available_source_count']:
                st.text('已定位 ' + str(q['available_source_count']) + ' 份可能相關材料；內容仍待查閱。')
                for source in q['available_sources']:
                    st.text(source['path'])
                if q['source_list_truncated']: st.caption('此處顯示部分清單；AI 可查閱本次完整來源索引。')
            else:
                st.text('尚未依檔案分類定位材料；可提供現有檔案路徑，或補充同成品資料。')
    st.info('下一步：啟動 AI 查閱本次材料，依公告提出具體問題與最小補件需求。AI 提案須覆核，不能直接改判受影響或不受影響。')
    st.caption(entry['assessment']['scope'])
