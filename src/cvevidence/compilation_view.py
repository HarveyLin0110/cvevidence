"""Show compilation intent separately from evidence of a completed build."""
def render(st,bundle,source_paths):
    if not bundle or not bundle.get('records'):return
    labels={'PATH_SUFFIX_CANDIDATE':'路徑尾段相符的候選（未認證）',
            'BASENAME_CANDIDATE':'只有檔名相同（不足以對應）',
            'AMBIGUOUS_PATH_CANDIDATES':'多份候選，不能選定副本',
            'NOT_IN_DELIVERED_PATHS':'交付路徑中未找到候選',
            'UNSUPPORTED_PATH_STYLE':'路徑格式尚未支援',
            'MALFORMED_OR_LIMITED_ENTRY':'項目格式錯誤或超過上限'}
    states={'DECLARATIONS_ONLY':'已解析編譯宣告，未驗證實際建置',
            'MALFORMED_DATABASE':'資料庫格式錯誤，未解析',
            'DATABASE_TOO_LARGE':'超過讀取大小上限，未解析'}
    with st.expander('編譯資料庫與原碼候選（僅宣告）'):
        st.caption(bundle['note'])
        for record in bundle['records']:
            st.text(record['path']+' · '+states.get(record['status'],'未知狀態'))
            if record.get('entries'):
                st.dataframe([{'第幾筆（非行號）':e['entry_index'],'宣告原碼':e.get('declared_file','未解析'),
                    '候選交付檔案':'、'.join(source_paths.get(s,s) for s in e.get('candidate_source_ids',[])) or '無',
                    '對應狀態':labels.get(e['state'],'未知'),
                    '宣告輸出':e.get('declared_output') or '未提供（不代表沒有輸出）',
                    '候選是否截短':'是' if e.get('candidates_truncated') else '否'} for e in record['entries']],hide_index=True)
            if record.get('coverage_limited'):
                st.caption('顯示／解析範圍有限或有無效項目；未列出不代表未使用。資料庫共 '+str(record.get('entries_total','未知'))+' 筆，已檢查 '+str(record.get('entries_examined',0))+' 筆。')
        if bundle.get('databases_omitted'):st.caption('另有 '+str(bundle['databases_omitted'])+' 份資料庫未納入。')
