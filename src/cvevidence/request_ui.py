"""Request controls keep request selection distinct from immutable child runs."""
from uuid import uuid4
from .requests import RequestStore

def reset_request(st):
    st.session_state.request_token=str(uuid4())
    st.session_state.follow_parent=None

def request_sidebar(st, runner):
    st.session_state.setdefault("selected_request",None)
    requests,rejected=RequestStore(runner.store).history()
    if rejected: st.sidebar.warning(f"{len(rejected)} 筆請求無法核對，原檔保留。")
    if requests:
        records={r.spec.request_id:r for r in requests}
        selected=st.sidebar.selectbox("請求歷史",["—"]+list(records),
            format_func=lambda value:("—" if value=="—" else records[value].status+" · "+value[:8]))
        if selected!="—" and st.sidebar.button("載入請求"):
            result=records[selected]
            st.session_state.selected_request=selected
            st.session_state.selected_run=result.runs[0].run_id if result.runs else None
    current=st.session_state.selected_request
    if not current: return None
    try: result=runner.read_request(current)
    except (ValueError,OSError):
        st.sidebar.error("此請求無法核對，請重新選擇。")
        st.session_state.selected_request=None
        return None
    st.sidebar.caption("目前請求："+current[:8]+" · "+result.status)
    if result.runs:
        rows={r.run_id:r for r in result.runs}
        child=st.sidebar.selectbox("此請求的 CVE 紀錄",list(rows),
            format_func=lambda value:(rows[value].cve_id or "元件候選探索")+" · "+rows[value].status,
            key="request-child-"+current)
        if st.sidebar.button("開啟所選 CVE"):
            st.session_state.selected_run=child
    return result

def request_summary(st, result):
    st.subheader("目前請求")
    st.caption(result.spec.request_id+" · "+result.status)
    if result.status=="DRAFT":
        st.info("已保存情境草稿；尚未取得工程包，沒有產生分析 run 或漏洞判定。")
        st.subheader("資料需求引導（不是 AI 分析）")
        for item in result.discovery.get("intake_questions",[]):
            st.text(item["question"])
            st.caption(item["purpose"])
        if result.discovery.get("candidates"):
            st.json(result.discovery["candidates"])
        if st.button("為此草稿補上工程包"):
            st.session_state.follow_parent=result.spec.request_id
            st.success("接著選擇工程包並提交，會建立連到此草稿的新請求。")
    else:
        st.dataframe([{"CVE":r.cve_id or "候選探索","執行狀態":r.status,"Run":r.run_id} for r in result.runs],
            hide_index=True)
        st.caption("從側邊「此請求的 CVE 紀錄」切換；不同 CVE 的結果不互相覆寫。")
    st.download_button("下載請求紀錄",result.model_dump_json(indent=2),
        file_name=result.spec.request_id+".json",mime="application/json")
