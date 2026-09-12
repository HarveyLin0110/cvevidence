"""Distinguish the selected run scope from passive component associations."""
def partition_candidates(candidates, selected_cve):
    selected = [item for item in candidates if item.get("cve_id") == selected_cve] if selected_cve else []
    others = [item for item in candidates if item.get("cve_id") != selected_cve]
    return selected, others

def render_candidates(st, candidates, selected_cve):
    def row(item):
        st.text(item["cve_id"] + " · " + item.get("status", "未提供"))
        hints = {entry.get("version_hint") for entry in item.get("match_basis", [])}
        if "FIX_RELEASE_VERSION" in hints:
            st.info("版本線索包含修正版本；這不是產品不受影響的判定，仍須核對實際成品與工程證據。")
        elif "VERSION_OUTSIDE_REVIEWED_AFFECTED_RANGE" in hints:
            st.info("版本線索位於目前審查的受影響範圍外；尚未完成產品適用性判定。")
        with st.expander("查看資料來源 " + item["cve_id"]):
            st.json(item)
    selected, others = partition_candidates(candidates, selected_cve)
    if selected_cve:
        st.subheader("本次指定 CVE")
        st.caption("本次查核範圍：" + selected_cve)
        if selected:
            for item in selected:
                row(item)
        else:
            st.info("尚未取得此 CVE 的候選資料，不代表已確認安全。")
        if others:
            with st.expander("其他元件關聯（未選入本次分析） · " + str(len(others))):
                st.caption("這些項目來自工程包的元件資料，僅供後續調查；未自動建立或加入本次分析。")
                for item in others:
                    row(item)
    else:
        st.subheader("待選擇的候選 CVE")
        st.caption("目前未指定 CVE；以下是元件關聯線索，尚未執行工程分析。")
        for item in others:
            row(item)
        if not others:
            st.info("目前三項 profile 沒有候選命中，不代表沒有漏洞。")
    st.caption("元件關聯 ≠ 產品受影響 ≠ 異常原因。")
