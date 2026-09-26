"""Explicitly authorized AI attempts, scoped history and immutable report views."""
from copy import deepcopy
import json
from uuid import uuid4
from .analysis_view import render_ai, VERDICTS
from .ai_presenter import (PROVIDERS, BILLING, provider_options, readiness_reason,
                           attempt_metadata, metadata_lines)


def selected_ai(st, runner, run):
    ai_id = st.session_state.get("selected-ai-" + run.run_id)
    if not ai_id: return None
    record = runner.read_ai(ai_id)
    if record["request"]["parent_run_id"] != run.run_id:
        raise ValueError("AI selection belongs to another engineering run")
    return record


def report_ai_selector(st, runner, run):
    """Report entry is self-contained; never depends on first visiting AI page."""
    records, rejected = runner.ai_history(run.run_id)
    if rejected:
        st.warning("部分 AI 紀錄無法核對，已排除；原檔保留。")
    if not records:
        return
    by_id = {r['request']['ai_id']: r for r in records}
    selection_key = 'selected-ai-' + run.run_id
    widget_key = 'report-ai-' + run.run_id
    seen_key = 'report-ai-seen-' + run.run_id
    current = st.session_state.get(selection_key, next(iter(by_id)))
    if current not in by_id:
        current = ''
    if widget_key not in st.session_state or st.session_state.get(seen_key) != current:
        st.session_state[widget_key] = current
    chosen = st.selectbox('報告附加的 AI 紀錄', [''] + list(by_id), key=widget_key,
        format_func=lambda v: '僅工程結果（不附加 AI）' if not v else
            by_id[v]['request']['created_at'][:19] + ' · ' + by_id[v]['status'] + ' · ' + v[:8])
    st.session_state[selection_key] = chosen
    st.session_state[seen_key] = chosen
    st.caption('預設附加最新紀錄，包含未完成或失敗結果；可選擇其他保存紀錄。查看與下載不會呼叫模型。')


def with_ai_result(engineering, record):
    """Make a report-only view, never save or replace the engineering envelope."""
    result = deepcopy(engineering)
    if not record: return result
    request = record["request"]
    entry = result["analyses"][0]
    if (result.get("context_hash") != request["context_hash"] or entry.get("cve_id") != request["cve_id"]
            or (entry.get("assessment") or {}).get("assessment_id") != request["assessment_id"]):
        raise ValueError("AI report scope mismatch")
    ai = record["result"]["analyses"][0]["ai"] if record.get("result") else None
    entry["ai_attempt"] = attempt_metadata(ai, request, status=record["status"])
    # A failed selected attempt must not inherit the engineering snapshot's
    # OFFLINE (or another saved AI) status in this report-only copy.
    entry["ai"] = deepcopy(ai)
    return result


def new_attempt(st, run_id):
    st.session_state["ai-token-" + run_id] = str(uuid4())


def ai_workspace(st, runner, run, engineering):
    entry = engineering["analyses"][0]
    assessment = entry.get("assessment") or {}
    if not assessment:
        st.info("此 CVE 尚無可用工程判定，不能啟動 AI 調查；可查看報告或另建查核。")
        return None
    timeout = 300 if assessment.get("assessment_kind") == "GENERAL_TRIAGE" else 180
    st.subheader("AI 調查結果與下一步")
    from . import ai_jobs
    pending=st.session_state.get('pending-ai-'+run.run_id)
    if pending:
        @st.fragment(run_every=2)
        def live_progress():
            try:
                status=ai_jobs.state(runner.store,pending)
                saved=ai_jobs.progress(runner.store,pending)
            except (ValueError,RuntimeError,OSError):
                st.error('AI 調查未完成或結果範圍無法核對，未選入報告。')
                del st.session_state['pending-ai-'+run.run_id]
                return
            st.info('AI 調查：'+status)
            if saved:
                st.text(saved.get('progress_phase','執行中'))
                for row in (saved.get('condition_plan') or {}).get('conditions',[]):
                    st.text(row['condition_id']+' · '+row['layer']+' · '+row['state'])
                totals=saved.get('usage_summary',{})
                st.caption('已記錄呼叫：'+str(len(saved.get('calls',[])))+' · 回報 tokens：'+(str(totals.get('total_tokens',0)) if totals.get('reported_calls') else '尚未回報'))
                complete=[t for t in saved.get('tasks',[]) if t.get('status')=='COMPLETED']
                if complete:st.text('最近完成：'+complete[-1].get('question',''))
            if status=='DONE':
                st.session_state['selected-ai-'+run.run_id]=pending
                st.session_state['ai-history-'+run.run_id]=pending
                del st.session_state['pending-ai-'+run.run_id]
                st.rerun()
            elif status=='UNKNOWN':
                st.warning('執行程序已不在本機工作清單；不會自動重送。請查看保存紀錄。')
                if st.button('離開等待畫面'):
                    del st.session_state['pending-ai-'+run.run_id];st.rerun()
            elif st.button('取消本次 AI 調查',key='cancel-'+pending):
                ai_jobs.cancel(runner.store,pending)
                st.warning('已要求停止；已送出的模型呼叫可能已計費，完成步驟會保留。')
        live_progress()
        return None
    records, rejected = runner.ai_history(run.run_id)
    saved_view = st.container()
    with st.expander("開始或接續 AI 調查", expanded=not records):
        providers, default, legacy = provider_options(runner.ai_configuration())
        provider_key = "ai-provider-" + run.run_id
        if st.session_state.get(provider_key) not in providers:
            st.session_state[provider_key] = default
        provider = st.selectbox("AI 執行來源", list(providers), key=provider_key,
            format_func=lambda key: PROVIDERS.get(key, "預設來源設定無效") + (" · 可用" if providers[key].get("configured") else " · 無法使用"))
        config = providers[provider]
        provider_label = PROVIDERS.get(provider, "尚未選定有效來源")
        from cvevidence_core.queries import PROFILE_VERSION
        from cvevidence_core.general_triage import PROFILE_VERSION as GENERAL_PROFILE_VERSION
        compatible = not assessment.get("profile_version") or assessment["profile_version"] in {PROFILE_VERSION,GENERAL_PROFILE_VERSION}
        if not compatible:
            st.warning("此工程紀錄使用舊版規則。請載入其原始收件／補件紀錄重新執行 Queries，再啟動新版 AI；既有工程與 AI 紀錄仍可查閱。")
        st.text("執行來源：" + provider_label + " · 設定模型：" + (config.get("model") or "尚未配置"))
        st.caption("推理強度：" + (config.get("reasoning_effort") or "未提供") + " · 逐項核對 PC1／PC2／PC3 的條件、原文與剩餘缺口。")
        st.caption(config.get("billing_label") or BILLING.get(provider, "選擇來源後可查看費用／額度歸屬。"))
        st.caption("可用狀態不代表尚有額度；狀態檢查與查看歷史不會呼叫調查模型。")
        for key, option in providers.items():
            if not option.get("configured"):
                st.info(PROVIDERS.get(key, "預設來源") + "：" + readiness_reason(option))
        context = st.text_area("本次 AI 想確認的問題", value=engineering.get("discovery", {}).get("symptom", ""),
                               max_chars=4000, key="ai-context-" + run.run_id)
        prior, _ = runner.ai_history(run.run_id)
        if run.parent_run_id:
            ancestor=runner.store.read(run.parent_run_id)
            seen=set()
            while ancestor.run_id not in seen:
                seen.add(ancestor.run_id)
                if ancestor.cve_id==run.cve_id:
                    records,_=runner.ai_history(ancestor.run_id);prior+=records
                if not ancestor.parent_run_id:break
                ancestor=runner.store.read(ancestor.parent_run_id)
        resumable={r['request']['ai_id']:r for r in prior if r.get('result')}
        continuation=st.selectbox('接續前次調查',['不接續']+list(resumable),
            format_func=lambda v:v if v=='不接續' else resumable[v]['request']['created_at'][:19]+' · '+resumable[v]['status']+' · '+v[:8],key='resume-'+run.run_id)
        with st.expander('本輪時間與用量上限'):
            timeout=st.slider('最長秒數',30,timeout,timeout,step=10,key='budget-time-'+run.run_id)
            max_calls=st.slider('最多模型呼叫次數',3,12,12,key='budget-calls-'+run.run_id)
            token_limit=st.number_input('累計回報 tokens 停止門檻',min_value=1000,max_value=1000000,value=200000,step=1000,key='budget-tokens-'+run.run_id)
            st.caption('門檻在下一次呼叫前檢查；單次呼叫可能超出。供應者未回報用量時不能精確計量，仍受時間與次數限制。')
        signature = (run.run_id, run.input_package.context_hash, assessment["assessment_id"],
                     provider, config.get("config_id"), config.get("auth_type"),
                     config.get("model"), config.get("reasoning_effort"), context,continuation,timeout,max_calls,token_limit)
        if (st.session_state.get("ai-signature-" + run.run_id) != signature
                or st.session_state.get("ai-active-run") != run.run_id):
            st.session_state["ai-signature-" + run.run_id] = signature
            new_attempt(st, run.run_id)
        st.session_state["ai-active-run"] = run.run_id
        attempt_id = st.session_state["ai-token-" + run.run_id]
        # The token changes whenever consent scope changes, including changing back
        # to a previous provider. No stale checkbox can authorize a new attempt.
        with st.form("ai-form-" + run.run_id):
            consent = st.checkbox("我有權提供本次資料，並同意透過 " + provider_label + " 將本次問題、工程缺口及必要來源片段送至 OpenAI。",
                                  value=False, key="ai-consent-" + run.run_id + "-" + attempt_id)
            st.caption(f"只調查目前成品與 CVE；每次建立獨立紀錄，最長 {timeout} 秒。來源或問題變更後須重新同意。")
            # Consent is checked again by the service. A form must submit before its
            # checkbox state is available, so the button gates configuration only.
            submit = st.form_submit_button("開始 AI 調查", disabled=not config.get("configured") or not compatible)
        if submit:
            if not consent:
                st.warning("請先確認本次資料外送授權；尚未呼叫模型。")
            else:
                try:
                    routing = {} if legacy else {"provider": provider, "config_id": config.get("config_id")}
                    ai_jobs.start(runner,run.run_id,user_context=context,consent=True,
                        ai_id=attempt_id,timeout=timeout,max_calls=max_calls,token_limit=int(token_limit),
                        continuation_ai_id=None if continuation=='不接續' else continuation,**routing)
                    st.session_state['pending-ai-'+run.run_id]=attempt_id
                    st.rerun()
                except (ValueError, OSError, RuntimeError):
                    st.error("AI 調查未完成或尚在執行。工程結果保留；請查閱下方操作紀錄，不會自動重送。")
        st.button("建立新的 AI 調查", key="new-ai-" + run.run_id, on_click=new_attempt, args=(st, run.run_id))
    with saved_view:
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
            format_func=lambda value: by_id[value]["request"]["created_at"][:19] + " · "
                + attempt_metadata(request=by_id[value]["request"])["provider_label"] + " · " + by_id[value]["status"] + " · " + value[:8],
            key="ai-history-" + run.run_id)
        st.session_state["selected-ai-" + run.run_id] = chosen
        record = by_id[chosen]
        st.text("AI ID：" + chosen + " · 狀態：" + record["status"])
        if not record.get("result"):
            for line in metadata_lines(attempt_metadata(request=record["request"], status=record["status"])):
                st.text(line)
        if (record.get("outcome") or {}).get("error_code"):
            st.text("失敗原因代碼：" + str(record["outcome"]["error_code"]))
        st.caption("以下為選取的保存紀錄，切換歷史不會重新呼叫模型。")
        st.download_button("下載 AI 調查紀錄", json.dumps(record, ensure_ascii=False, indent=2),
                           file_name=chosen + "-ai.json", mime="application/json", key="ai-download-" + run.run_id)
        if record["result"]:
            ai_entry = record["result"]["analyses"][0]
            if ai_entry['ai'].get('usage_summary'):
                u=ai_entry['ai']['usage_summary'];st.caption('本輪回報用量：'+(str(u['total_tokens'])+' tokens' if u.get('reported_calls') else '未知')+('（部分回報）' if not u.get('complete') else '')+'；'+u['note'])
            render_ai(st, ai_entry["ai"], context_hash=run.input_package.context_hash,
                      cve_id=run.cve_id, assessment_id=assessment["assessment_id"], request=record["request"])
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
