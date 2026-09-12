"""Explicitly authorized AI attempts, scoped history and immutable report views."""
from copy import deepcopy
import json
from uuid import uuid4
from .analysis_view import render_ai, VERDICTS


def selected_ai(st, runner, run):
    ai_id = st.session_state.get("selected-ai-" + run.run_id)
    if not ai_id: return None
    record = runner.read_ai(ai_id)
    if record["request"]["parent_run_id"] != run.run_id:
        raise ValueError("AI selection belongs to another engineering run")
    return record


def with_ai_result(engineering, record):
    """Make a report-only view, never save or replace the engineering envelope."""
    result = deepcopy(engineering)
    if not record or not record.get("result"): return result
    request = record["request"]
    entry = result["analyses"][0]
    if (result.get("context_hash") != request["context_hash"] or entry.get("cve_id") != request["cve_id"]
            or (entry.get("assessment") or {}).get("assessment_id") != request["assessment_id"]):
        raise ValueError("AI report scope mismatch")
    entry["ai"] = record["result"]["analyses"][0]["ai"]
    return result


def new_attempt(st, run_id):
    st.session_state["ai-token-" + run_id] = str(uuid4())


def ai_workspace(st, runner, run, engineering):
    entry = engineering["analyses"][0]
    assessment = entry.get("assessment") or {}
    if not assessment:
        st.info("此 CVE 尚無可用工程判定，不能啟動 AI 調查；可查看報告或另建查核。")
        return None
    st.subheader("追加 AI 調查")
    config = runner.ai_configuration()
    from cvevidence_core.queries import PROFILE_VERSION
    compatible = not assessment.get("profile_version") or assessment["profile_version"] == PROFILE_VERSION
    if not compatible:
        st.warning("此工程紀錄使用舊版規則。請載入其原始收件／補件紀錄重新執行 Queries，再啟動新版 AI；既有工程與 AI 紀錄仍可查閱。")
    st.text("供應者：OpenAI · 模型：" + (config.get("model") or "尚未配置"))
    if not config["configured"]:
        st.info("管理者尚未啟用本機 AI 設定；工程分析與補件仍可使用。金鑰請勿填入情境或上傳檔。")
    with st.form("ai-form-" + run.run_id):
        context = st.text_area("本次 AI 想確認的問題", value=engineering.get("discovery", {}).get("symptom", ""),
                               max_chars=4000, key="ai-context-" + run.run_id)
        consent = st.checkbox("我有權提供本次資料，並同意將本次問題、工程缺口及調查所需的來源片段送至 OpenAI。",
                              value=False, key="ai-consent-" + run.run_id)
        st.caption("只調查目前成品與 CVE；每次建立獨立紀錄，最長 180 秒。模型可能產生 API 使用費。")
        # Consent is checked again by the service. A form must submit before its
        # checkbox state is available, so the button gates configuration only.
        submit = st.form_submit_button("開始 AI 調查", disabled=not config["configured"] or not compatible)
    signature = (context, consent, config.get("model"), config.get("reasoning_effort"))
    if st.session_state.get("ai-signature-" + run.run_id) != signature:
        st.session_state["ai-signature-" + run.run_id] = signature
        new_attempt(st, run.run_id)
    if submit:
        if not consent:
            st.warning("請先確認本次資料外送授權；尚未呼叫模型。")
        else:
            try:
                with st.spinner("AI 正在調查本次資料；工程結果保持不變…"):
                    record = runner.investigate_ai(run.run_id, user_context=context, consent=True,
                        ai_id=st.session_state["ai-token-" + run.run_id], timeout=180)
                st.session_state["selected-ai-" + run.run_id] = record["request"]["ai_id"]
                st.session_state["ai-history-" + run.run_id] = record["request"]["ai_id"]
                st.rerun()
            except (ValueError, OSError, RuntimeError):
                st.error("AI 調查未完成或尚在執行。工程結果保留；請查閱下方操作紀錄，不會自動重送。")
    st.button("建立新的 AI 調查", key="new-ai-" + run.run_id, on_click=new_attempt, args=(st, run.run_id))
    records, rejected = runner.ai_history(run.run_id)
    if rejected: st.warning("部分 AI 紀錄無法核對，未顯示其內容；原檔保留。")
    if not records:
        render_ai(st, entry.get("ai"), context_hash=run.input_package.context_hash,
                  cve_id=run.cve_id, assessment_id=assessment["assessment_id"])
        return None
    by_id = {r["request"]["ai_id"]: r for r in records}
    current = st.session_state.get("selected-ai-" + run.run_id)
    choices = list(by_id)
    chosen = st.selectbox("本工程結果的 AI 調查紀錄", choices,
        index=choices.index(current) if current in choices else 0,
        format_func=lambda value: by_id[value]["request"]["created_at"][:19] + " · " + by_id[value]["status"] + " · " + value[:8],
        key="ai-history-" + run.run_id)
    st.session_state["selected-ai-" + run.run_id] = chosen
    record = by_id[chosen]
    st.text("AI ID：" + chosen + " · 狀態：" + record["status"])
    st.caption("以下為選取的保存紀錄，切換歷史不會重新呼叫模型。")
    st.download_button("下載 AI 調查紀錄", json.dumps(record, ensure_ascii=False, indent=2),
                       file_name=chosen + "-ai.json", mime="application/json", key="ai-download-" + run.run_id)
    if record["result"]:
        ai_entry = record["result"]["analyses"][0]
        render_ai(st, ai_entry["ai"], context_hash=run.input_package.context_hash,
                  cve_id=run.cve_id, assessment_id=assessment["assessment_id"])
        followup = ai_entry.get("investigation_verification")
        if followup:
            with st.expander("核心對追加調查的重新覆核"):
                st.text(followup.get("explanation", "未提供說明"))
                st.text(VERDICTS.get((followup.get("assessment") or {}).get("verdict"), "未提供新判定"))
                st.caption("原工程結果沒有覆寫；來源原文觀測不等於自由文字推論已驗證。")
                st.json(followup)
    else:
        st.info("本次沒有可顯示的 AI 結果。缺少結束收據時不判定成功；可保留目前工程報告或另建調查。")
    return record
