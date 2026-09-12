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


def render_engineering(st, entry):
    st.subheader("工程分析結果")
    st.text("CVE：" + text(entry.get("cve_id")))
    st.text("執行狀態：" + text(entry.get("status")))
    assessment = entry.get("assessment")
    if not isinstance(assessment, dict):
        st.info("尚未產生工程判定；未知 CVE 或未完成分析不能視為安全。")
        return
    st.text(VERDICTS.get(assessment.get("verdict"), "未提供有效工程判定"))
    st.text(text(assessment.get("reason")))
    st.text("分析範圍：" + text(assessment.get("scope")))
    st.caption("工程初判仍需人工覆核；不代表已證明異常原因、實際部署暴露或來源認證。")
    query_rows = rows(entry.get("queries"))
    for qid, label in QUERIES.items():
        matches = [q for q in query_rows if q.get("query_id") == qid]
        query = matches[0] if len(matches) == 1 else {}
        with st.expander(qid + " · " + label, expanded=False):
            st.text("狀態：" + text(query.get("status")))
            if len(matches) > 1:
                st.warning("重複的查核結果，需重新核對；未選取其中任何一筆。")
            if query.get("missing"):
                st.text("需補齊的資料")
                lines(st, query["missing"])
            if query.get("conflicts"):
                st.text("需覆核的矛盾")
                lines(st, query["conflicts"])
            lines(st, query.get("evidence_ids"))
    st.subheader("條件與證據")
    conditions = rows(assessment.get("conditions"))
    if not conditions:
        st.info("未提供條件明細。")
    else:
        st.dataframe([{"條件": text(c.get("title")), "狀態": text(c.get("state"))} for c in conditions],hide_index=True)
        with st.expander("條件明細與引用"):
            for condition in conditions:
                st.text(text(condition.get("title")) + " · " + text(condition.get("state")))
                st.text(text(condition.get("explanation")))
                lines(st, condition.get("evidence_ids"))
    with st.expander("證據原值與來源"):
        st.caption("以下為保存結果的內容；引用原文需由同 run/context 的來源工具重新核對。")
        for evidence in rows(entry.get("evidence")):
            st.text(text(evidence.get("evidence_id")))
            st.code(text(evidence.get("value")), language=None)
            st.text(text(evidence.get("reason")))
            for witness in rows(evidence.get("witnesses")):
                st.text(text(witness.get("source_id")) + " · " + text(witness.get("path")))
                st.text("SHA256：" + text(witness.get("sha256")))
    for field, title in (("conflicts", "矛盾待覆核"), ("statement_reviews", "人工說明待覆核"),
                         ("gaps", "缺少資料"), ("next_steps", "建議下一步")):
        if assessment.get(field):
            st.subheader(title)
            for item in assessment[field]:
                if field == "gaps" and isinstance(item, dict):
                    st.text(text(item.get("needed")))
                    st.caption(text(item.get("query_id")) + (" · 需同 build 資料" if item.get("same_build_required") else ""))
                else: st.text(text(item))


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
