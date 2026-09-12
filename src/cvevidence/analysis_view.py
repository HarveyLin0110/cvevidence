"""Read-only rendering of saved core output; never executes or verifies analysis.

The caller must read a validated, user-scoped saved result. Scope checks here are
defence against displaying the wrong selection, not proof of evidence integrity.
"""
import json

QUERIES = {
    "Q1_COMPONENT": "元件與版本",
    "Q2_BUILD": "建置身分",
    "Q3_IMPLEMENTATION": "受影響實作",
    "Q4_BINDING": "成品綁定與範圍",
    "Q5_PATH": "輸入路徑與必要條件",
}
VERDICTS = {
    "AFFECTED": "受影響（工程初判）",
    "NOT_AFFECTED": "不受影響（限本次成品與 CVE）",
    "NEEDS_INVESTIGATION": "需要進一步調查",
}


def text(value):
    if value is None:
        return "未提供"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, indent=2)
    return str(value)


def rows(value):
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def lines(st, value):
    if isinstance(value, list):
        for item in value:
            st.text(text(item))


def select_analysis(payload, *, context_hash, cve_id):
    """Reject ambiguous or cross-scope selection before showing any contents."""
    if not isinstance(payload, dict) or not context_hash or payload.get("context_hash") != context_hash:
        raise ValueError("Result context does not match selection")
    matches = [item for item in rows(payload.get("analyses")) if item.get("cve_id") == cve_id]
    if len(matches) != 1:
        raise ValueError("Expected exactly one CVE result")
    entry = matches[0]
    assessment = entry.get("assessment")
    if assessment is not None:
        if not isinstance(assessment, dict) or assessment.get("context_hash") != context_hash or assessment.get("cve_id") != cve_id:
            raise ValueError("Assessment scope does not match selection")
    return entry


def render_engineering(st, entry, *, package=None):
    st.subheader("工程分析結果")
    st.caption("CVE：" + text(entry.get("cve_id")) + " · 執行狀態：" + text(entry.get("status")))
    assessment = entry.get("assessment")
    if not isinstance(assessment, dict):
        st.info("尚未產生工程判定；未知 CVE 或未完成分析不能視為安全。")
        return
    if package:
        with st.expander("本次建置與輸入材料", expanded=True):
            left, right = st.columns(2)
            with left:
                st.caption("產品 / Release")
                st.text(text(package.get("product_id")) + " / " + text(package.get("release_id")))
                st.caption("查核目標")
                st.text(text(entry.get("cve_id")))
            with right:
                st.caption("資料包 / Build")
                st.text(text(package.get("package_id")) + " / " + text(package.get("build_id")))
                st.caption("輸入材料")
                st.text(str(len(rows(package.get("sources")))) + " 個已收件來源；來源數不等於有效證據數。")
    verdict = assessment.get("verdict")
    with st.container(border=True):
        st.text(VERDICTS.get(verdict, "未提供有效工程判定"))
        st.text(text(assessment.get("reason")))
        st.caption("工程初判須覆核；不代表異常已歸因，也不是部署安全認證。")
    conditions = rows(assessment.get("conditions"))
    metrics = st.columns(3)
    metrics[0].metric("有證據支持的條件", sum(c.get("state") == "SUPPORTED" for c in conditions))
    metrics[1].metric("有證據阻斷的條件", sum(c.get("state") == "BLOCKED" for c in conditions))
    metrics[2].metric("尚待確認的條件", sum(c.get("state") == "UNKNOWN" for c in conditions))
    overview, queries_tab, evidence_tab, gaps_tab = st.tabs(["結果摘要", "五項工程查核", "證據與引用", "待補資料與覆核"])
    with overview:
        st.subheader("下一步可以做什麼")
        if assessment.get("gaps") or assessment.get("statement_reviews") or assessment.get("conflicts"):
            st.info("先看「待補資料與覆核」，再從側邊第 04 步提供同 build 材料；補件後回第 03 步重新分析。")
        else:
            st.info("先核對本次成品範圍與關鍵證據，再從側邊第 05 步下載報告供工程師覆核。")
        lines(st, assessment.get("next_steps"))
        st.subheader("適用範圍")
        st.text(text(assessment.get("scope")))
        st.subheader("條件摘要")
        states = {"SUPPORTED": "有證據支持", "BLOCKED": "有證據阻斷", "UNKNOWN": "尚待確認"}
        if conditions:
            st.dataframe([{"條件": text(c.get("title")),
                           "狀態": states.get(c.get("state"), "未提供"),
                           "說明": text(c.get("explanation"))} for c in conditions],
                         hide_index=True, use_container_width=True)
        else:
            st.info("未提供條件明細。")
    with queries_tab:
        st.caption("每項查核顯示當次保存的狀態；查核完成不代表產品不受影響。")
        query_rows = rows(entry.get("queries"))
        evidence_by_id = {e.get("evidence_id"): e for e in rows(entry.get("evidence"))}
        status_names = {"COMPLETED": "已完成", "COMPLETED_WITH_GAPS": "已執行・有缺件", "CONFLICT": "有矛盾待覆核"}
        for qid, label in QUERIES.items():
            matches = [q for q in query_rows if q.get("query_id") == qid]
            query = matches[0] if len(matches) == 1 else {}
            status = status_names.get(query.get("status"), text(query.get("status")))
            with st.expander(qid + " · " + label + " ｜ " + status):
                st.text("狀態：" + text(query.get("status")))
                if len(matches) > 1:
                    st.warning("重複的查核結果，需重新核對；未選取其中任何一筆。")
                if query.get("missing"):
                    st.text("需補齊的資料")
                    lines(st, query["missing"])
                if query.get("conflicts"):
                    st.text("需覆核的矛盾")
                    lines(st, query["conflicts"])
                st.text("查核發現")
                for eid in query.get("evidence_ids", []):
                    evidence = evidence_by_id.get(eid)
                    if evidence:
                        st.text(text(evidence.get("reason")))
                        for witness in rows(evidence.get("witnesses")):
                            st.caption("來源：" + text(witness.get("path")))
                with st.expander("追溯識別碼與查核原始資料"):
                    st.json(query)
    with evidence_tab:
        st.caption("以下為保存的工程證據；如需重新核對原文，可使用本頁下方的來源檢視。")
        with st.expander("條件明細與引用"):
            for condition in conditions:
                st.text(text(condition.get("title")) + " · " + text(condition.get("state")))
                st.text(text(condition.get("explanation")))
                lines(st, condition.get("evidence_ids"))
        with st.expander("證據原值與來源"):
            for evidence in rows(entry.get("evidence")):
                st.text(text(evidence.get("evidence_id")))
                st.code(text(evidence.get("value")), language=None)
                st.text(text(evidence.get("reason")))
                for witness in rows(evidence.get("witnesses")):
                    st.text(text(witness.get("source_id")) + " · " + text(witness.get("path")))
                    st.text("SHA256：" + text(witness.get("sha256")))
    with gaps_tab:
        any_pending = False
        for field, title in (("conflicts", "矛盾待覆核"), ("statement_reviews", "人工說明待覆核"),
                             ("gaps", "缺少資料")):
            if assessment.get(field):
                any_pending = True
                st.subheader(title)
                for index, item in enumerate(assessment[field], 1):
                    with st.container(border=True):
                        if field == "gaps" and isinstance(item, dict):
                            st.text(str(index) + ". " + text(item.get("needed")))
                            st.caption(text(item.get("query_id")) + (" · 需同 build 資料" if item.get("same_build_required") else ""))
                        else:
                            st.text(text(item))
        if not any_pending:
            st.info("本次保存結果沒有列出缺件或矛盾；仍須人工覆核範圍，不能推論其他 CVE 或部署環境安全。")
        st.caption("補充資料請使用第 04 或 05 步的補件入口；會建立新紀錄，保留這次結果。")


def render_ai(st, ai, *, context_hash, cve_id, assessment_id):
    st.subheader("AI 查核建議")
    if not isinstance(ai, dict):
        st.info("尚無 AI 調查紀錄。可先查看工程缺口、下載報告或補充資料。")
        return
    if not assessment_id or ai.get("context_hash") != context_hash or ai.get("cve_id") != cve_id or ai.get("engineering_assessment_id") != assessment_id:
        st.error("AI 紀錄與目前工程結果不符，未顯示其內容。")
        return
    st.text("模式：" + text(ai.get("mode")) + " · 狀態：" + text(ai.get("status")))
    if ai.get("mode") == "REPLAY":
        st.caption("這是既有紀錄播放，本次未呼叫模型。")
    if ai.get("status") in ("OFFLINE", "NOT_RUN", "CONFIG_REQUIRED"):
        st.info("本次沒有完成模型調查；工程结果仍可查閱與下載。")
    st.caption("AI 調查與工程判定分開；原文引用核對不表示語意已證明。")
    for index, task in enumerate(rows(ai.get("tasks")), 1):
        with st.expander("調查問題 " + str(index), expanded=True):
            st.text(text(task.get("question")))
            st.text("目的：" + text(task.get("reason")))
            st.text("動作：" + text(task.get("action")) + " · " + text(task.get("status")))
            if task.get("status") == "REJECTED":
                st.warning("此提案被拒絕，不作為有效發現或補件要求。")
                continue
            if task.get("finding"):
                st.text("AI 提案：" + text(task["finding"]))
            lines(st, task.get("citations"))
            if task.get("status") == "COMPLETED":
                if task.get("required_files"):
                    st.text("建議提供的資料（須符合本次 build／成品）")
                    lines(st, task["required_files"])
                with st.expander("工具回傳內容"):
                    st.code(text(task.get("result")), language=None)
    with st.expander("模型呼叫紀錄"):
        for call in rows(ai.get("calls")):
            st.text("模型：" + text(call.get("model")) + " · 狀態：" + text(call.get("status")))
            st.text("Response ID：" + text(call.get("response_id")))
            st.text("Usage：" + text(call.get("usage")))


def render_analysis(st, payload, *, context_hash, cve_id, key, on_report=None, on_supplement=None):
    """Render one saved CVE; caller supplies navigation callbacks and unique key.

    No file loading, analysis execution, state mutation or AI override is done here.
    """
    try:
        entry = select_analysis(payload, context_hash=context_hash, cve_id=cve_id)
    except ValueError:
        st.error("無法核對所選 CVE／快照的結果，未顯示分析內容。")
        return
    render_engineering(st, entry)
    assessment = entry.get("assessment") or {}
    render_ai(st, entry.get("ai"), context_hash=context_hash, cve_id=cve_id,
              assessment_id=assessment.get("assessment_id"))
    st.subheader("下一步")
    st.button("查看目前報告", key=key + "-report", on_click=on_report, disabled=on_report is None)
    st.button("提供補充資料", key=key + "-supplement", on_click=on_supplement, disabled=on_supplement is None)
    if on_report is None or on_supplement is None:
        st.caption("導覽尚待工作台接線；結果呈現元件本身不執行補件或更改判定。")
