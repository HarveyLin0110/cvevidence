"""Request controls keep request selection distinct from immutable child runs."""
from uuid import uuid4
from .requests import RequestStore
from .workflow_navigation import PAGES


def request_lineage(root, runs):
    """Explicit parents only: never pick another request by matching CVE alone."""
    by_id = {run.run_id: run for run in runs}
    descendants = []
    for run in runs:
        current, seen = run, set()
        while current and current.run_id not in seen:
            seen.add(current.run_id)
            if root.cve_id and current.cve_id != root.cve_id: break
            if current.run_id == root.run_id:
                descendants.append(run)
                break
            current = by_id.get(current.parent_run_id)
    return sorted(descendants, key=lambda r: (r.created_at, r.run_id), reverse=True)


def open_run(st, run):
    st.session_state.selected_run = run.run_id
    st.session_state.step = PAGES[4] if run.error else PAGES[2] if run.engineering_payload_sha256 else PAGES[1]

def symptom_for_run(request, run_id):
    """A selected request is not necessarily the owner of a history-selected run."""
    if request and any(child.run_id == run_id for child in request.runs):
        return request.spec.symptom
    return ""

def reset_request(st):
    st.session_state.request_token=str(uuid4())
    st.session_state.follow_parent=None
    st.session_state.selected_request=None
    st.session_state.selected_run=None
    st.session_state.step=PAGES[0]

def request_sidebar(st, runner):
    panel=st.sidebar.expander("請求與 CVE 切換", expanded=True)
    st.session_state.setdefault("selected_request",None)
    requests,rejected=RequestStore(runner.store).history()
    saved, invalid = runner.store.inspect_history()
    saved_by_id = {run.run_id: run for run in saved}
    def request_label(value):
        if value == "—": return "—"
        item = records[value]
        root = saved_by_id.get(item.runs[0].run_id) if item.runs else None
        package = root.input_package.package_id if root and root.input_package else "情境草稿"
        subject = item.spec.symptom[:32].replace("\n", " ") or "、".join(item.spec.cves) or "候選探索"
        return package + " · " + subject + " · " + value[:8]
    if rejected: panel.warning(f"{len(rejected)} 筆請求無法核對，原檔保留。")
    if requests:
        records={r.spec.request_id:r for r in requests}
        selected=panel.selectbox("請求歷史",["—"]+list(records),
            format_func=request_label)
        if selected!="—" and panel.button("載入請求"):
            result=records[selected]
            st.session_state.selected_request=selected
            st.session_state.selected_run=result.runs[0].run_id if result.runs else None
            st.session_state.step=PAGES[0] if not result.runs else PAGES[1]
    current=st.session_state.selected_request
    if not current: return None
    try: result=runner.read_request(current)
    except (ValueError,OSError):
        panel.error("此請求無法核對，請重新選擇。")
        st.session_state.selected_request=None
        return None
    panel.caption("目前請求："+current[:8]+" · "+result.status)
    if result.runs:
        rows={r.run_id:r for r in result.runs}
        if invalid: panel.warning("部分查核歷史無法核對，已排除；原檔保留。")
        histories = {rid: request_lineage(row, saved) for rid, row in rows.items()}
        child=panel.selectbox("此請求的 CVE 紀錄",list(rows),
            format_func=lambda value:(rows[value].cve_id or "元件候選探索")+" · "+
                ("已有工程結果" if histories[value] and histories[value][0].engineering_payload_sha256 else "待分析／查看紀錄"),
            key="request-child-"+current)
        history = histories[child]
        panel.caption("開啟此 CVE 最新紀錄（包含補件與失敗）；原紀錄仍保留在查核歷程。")
        if panel.button("開啟所選 CVE"):
            if history: open_run(st, history[0])
            else: panel.error("此 CVE 的查核紀錄無法核對，未切換。")
        active = st.session_state.get("selected_run")
        active_root = next((rid for rid, runs in histories.items() if any(r.run_id == active for r in runs)), None)
        if active_root:
            panel.caption("正在檢視：" + (rows[active_root].cve_id or "元件候選探索") + " · " + active[:8])
        else:
            panel.info("目前主畫面不屬於此請求；請按「開啟所選 CVE」切換。")
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
