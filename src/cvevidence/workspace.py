"""Actual local source workspace; all collection/supplement calls share Runner."""
import os
from pathlib import Path
from .runner import Runner
from .storage import RunStore
from .reports import report, compare, excerpt
from .core_service import catalog_entries
from .requests import parse_cves
from .request_ui import request_sidebar, request_summary, reset_request, symptom_for_run
from uuid import uuid4
from .workflow_navigation import PAGES, sidebar_steps
from .analysis_view import render_engineering, render_ai, VERDICTS
from .analysis_report import export_analysis, compare_analyses, previous_engineering_run
from .candidate_view import render_candidates
from .ai_workspace import ai_workspace, selected_ai, with_ai_result
from .query_preparation import render_preparation

def controlled_path(value):
    root = Path(os.environ.get("CVEVIDENCE_ARTIFACT_ROOT", "var/artifacts")).resolve()
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Use an artifact-root relative path")
    path = (root / relative).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError("Archive outside configured root")
    return path

def navigate(st, page):
    st.session_state.step = page

def next_button(st, page, label="下一步", disabled=False):
    st.button(label, disabled=disabled, on_click=navigate, args=(st,page))

def source_viewer(st, runner, run):
    st.subheader("來源檢視")
    st.caption("直接讀取本次保存工程包；每次操作重新核對 archive、manifest 與 context hash。")
    if not run.sources:
        if run.evidence:
            selected=st.selectbox("舊版來源", [e.evidence_id for e in run.evidence])
            try: st.code(excerpt(runner.store,run.run_id,selected),language=None)
            except (ValueError, OSError, RuntimeError): st.error("原文核對失敗。")
        return
    filter_text=st.text_input("依檔案路徑篩選",max_chars=200,key="filter-"+run.run_id)
    choices=[s for s in run.sources if s.kind=="file" and filter_text.casefold() in s.path.casefold()]
    st.caption(f"符合 {len(choices)} 個檔案；列表最多顯示 300 個，可用路徑縮小範圍。")
    rows={s.source_id:s for s in choices[:300]}
    if rows:
        selected=st.selectbox("選擇原始檔案",list(rows),format_func=lambda sid:rows[sid].path,
            key="source-"+run.run_id)
        first=st.number_input("起始行",min_value=1,value=1,step=1)
        if st.button("讀取並核對原文"):
            try:
                result=runner.source_tool(run.run_id,"excerpt",source_id=selected,
                    start_line=int(first),end_line=int(first)+59)
                st.caption(f'{result["excerpt_id"]} · {result["start_line"]}–{result["end_line"]}')
                st.code(result["text"],language=None)
            except (ValueError, OSError, RuntimeError): st.error("無法讀取：可能為二進位、超出文字／行範圍，或完整性失敗。")
        if len(rows)>1:
            right=st.selectbox("另一個來源（比較）",list(rows),format_func=lambda sid:rows[sid].path,
                key="right-"+run.run_id)
            if st.button("比較兩份原文"):
                try: st.json(runner.source_tool(run.run_id,"compare",left_id=selected,right_id=right))
                except (ValueError, OSError, RuntimeError): st.error("來源比較失敗，未顯示未核對內容。")
    term=st.text_input("全文搜尋（字面比對）",max_chars=200,key="term-"+run.run_id)
    if st.button("搜尋本次資料",disabled=not term.strip()):
        try:
            result=runner.source_tool(run.run_id,"search",term=term,limit=20)
            st.caption(f'找到 {len(result["matches"])} 段；略過 {result["skipped_nontext_or_large"]} 個非文字／大型來源。')
            for match in result["matches"]:
                st.caption(match["source_id"]+" · "+str(match["start_line"]))
                st.code(match["text"],language=None)
            if result["truncated"]: st.info("已達結果上限，請縮小關鍵字範圍。")
        except (ValueError, OSError, RuntimeError): st.error("搜尋失敗，未顯示部分結果。")

def workspace(st, *, store_root=None):
    st.set_page_config(page_title="CVEvidence · 工程查核",layout="wide")
    store=RunStore(store_root if store_root is not None else os.environ.get("CVEVIDENCE_STORE","var/runtime"))
    runner=Runner(store)
    st.title("CVEvidence · 產品影響工作台")
    st.caption("確認產品風險，追溯工程證據，補齊下一步需要的資料。")
    st.session_state.setdefault("selected_run",None)
    runs, rejected=store.inspect_history()
    if rejected:
        st.sidebar.warning(f"{len(rejected)} 筆歷史紀錄無法核對，已排除顯示；原檔保留。")
        with st.sidebar.expander("歷史紀錄問題"):
            st.json(rejected)
    if runs:
        labels={r.run_id:((r.input_package.package_id if r.input_package else "匯入失敗")+" · "+(r.cve_id or "候選探索")+" · "+r.status+" · "+r.created_at[:19]+" · "+r.run_id[:8]) for r in runs}
        history_panel=st.sidebar.expander("查核紀錄與歷程")
        chosen=history_panel.selectbox("保存的查核紀錄",["—"]+list(labels),
            format_func=lambda value: labels.get(value,value),key="history_select")
        if chosen!="—" and history_panel.button("載入查核紀錄"):
            st.session_state.selected_run=chosen
    request=request_sidebar(st,runner)
    run=None
    if st.session_state.selected_run:
        try:
            run=store.read(st.session_state.selected_run)
        except (ValueError,OSError):
            st.error("選取紀錄不存在、版本不相容或已損壞。請重新選擇紀錄，原檔未修改。")
            st.session_state.selected_run=None
    payload=None
    if run and run.engineering_payload_sha256:
        try: payload=runner.read_engineering(run.run_id)
        except (ValueError,OSError,TypeError,KeyError):
            st.error("工程結果無法核對；未顯示判定或 AI 內容，原紀錄保留。")
    page=sidebar_steps(st,has_run=run is not None,failed=bool(run and run.error),has_engineering=payload is not None)
    entries=catalog_entries(Path(__file__).resolve().parents[2])
    if page==PAGES[0]:
        st.subheader("從產品與情境開始")
        source_options=["產品／版本樣品","上傳工程包"]
        if store_root is None: source_options.append("受控路徑")
        source_options.append("先描述情境")
        kind=st.radio("資料來源",source_options,horizontal=True)
        available=[e for e in entries if e["available"] and e["kind"]=="initial"]
        selected=None
        upload=None
        path=""
        if kind=="產品／版本樣品":
            if available:
                index=st.selectbox("選擇已取得的產品／建置／資料包",range(len(available)),
                    format_func=lambda i:available[i]["product_id"]+" · "+available[i]["package_id"]+" · "+available[i]["dataset"])
                selected=available[index]
                st.caption("Build: "+selected["build_id"])
            else: st.info("索引已取得，工程包尚未下載至本機。請上傳或提供受控路徑。")
            with st.expander("查看資料交付狀態"):
                st.dataframe([{"資料版":e["dataset"],"資料包":e["package_id"],"可用":"已取得" if e["available"] else "等待資料交付"} for e in entries],hide_index=True)
        elif kind=="上傳工程包":
            upload=st.file_uploader("ZIP / tar.gz 工程包（上限 512 MiB）",type=["zip","gz","tar"],max_upload_size=512)
        elif kind=="受控路徑":
            st.caption("根目錄："+os.environ.get("CVEVIDENCE_ARTIFACT_ROOT","var/artifacts"))
            path=st.text_input("相對路徑",placeholder="archives/資料版本/06_cmake.tar.gz")
        cve=st.text_input("CVE ID（最多 5 個，逗號或空白分隔；可留白）",placeholder="CVE-2022-37434, CVE-2023-38545")
        symptom=st.text_area("情境與想確認的問題",max_chars=4000,placeholder="描述操作、異常、部署方式；說明只作調查背景。")
        if cve.strip():
            try:
                preview_cves = parse_cves(cve)
            except ValueError:
                st.info("請輸入合法 CVE ID，最多五個，才能準備對應的 Queries。")
            else:
                with st.expander("依 CVE 預覽查核計畫",expanded=True):
                    for preview_cve in preview_cves:
                        render_preparation(st,preview_cve,selected.get('format') if selected else None)
        ready=bool(selected) if kind=="產品／版本樣品" else upload is not None if kind=="上傳工程包" else bool(path.strip())
        if kind=="先描述情境": ready=bool(symptom.strip() or cve.strip())
        signature=(kind,selected["archive"]["sha256"] if selected else None,
            getattr(upload,"file_id",None),path,cve,symptom,st.session_state.get("follow_parent"))
        if st.session_state.get("request_signature")!=signature:
            if st.session_state.get("request_signature") is not None:
                st.session_state.selected_run=None
                st.session_state.selected_request=None
                run=None
                request=None
            st.session_state.request_signature=signature
            st.session_state.request_token=str(uuid4())
        if st.session_state.get("follow_parent"):
            st.caption("此提交會接續草稿："+st.session_state.follow_parent)
        if st.button("匯入並建立查核",type="primary",disabled=not ready):
            try:
                with st.spinner("核對工程包並建立不可變紀錄…"):
                    kwargs=dict(cves=parse_cves(cve),symptom=symptom,
                        request_id=st.session_state.request_token,
                        parent_request_id=st.session_state.get("follow_parent"))
                    if selected:
                        result=runner.submit_request(path=selected["local_path"],archive_sha256=selected["archive"]["sha256"],
                            manifest_sha256=selected["manifest_sha256"],**kwargs)
                    elif upload:
                        upload.seek(0)
                        result=runner.submit_request(stream=upload,**kwargs)
                    elif kind=="先描述情境": result=runner.submit_request(**kwargs)
                    else: result=runner.submit_request(path=controlled_path(path),**kwargs)
                st.session_state.selected_request=result.spec.request_id
                st.session_state.selected_run=result.runs[0].run_id if result.runs else None
                st.rerun()
            except (ValueError,OSError,RuntimeError):
                st.error("請求未完成。請檢查最多5個合法CVE、工程包與路徑；相同請求若仍執行中或中斷，不會自動重跑。")
        if request: request_summary(st,request)
        st.button("建立另一個請求",on_click=reset_request,args=(st,))
        next_button(st,PAGES[1],"下一步：確認資料",disabled=run is None or bool(run.error))
        return
    if run is None:
        st.info("請先匯入工程包，或從側邊載入保存的紀錄。")
        next_button(st,PAGES[0],"返回資料來源")
        return
    with st.expander("本次查核識別資訊"):
        st.caption("Run: "+run.run_id+" · "+run.status)
    saved_context = (payload.get("discovery") or {}).get("symptom", "") if payload else run.candidates.get("symptom", "")
    if saved_context:
        with st.expander("本次情境描述", expanded=False):
            st.text(saved_context)
    if run.error:
        st.error(run.error.code+"：本次操作失敗；父 run 與原始資料保留。")
        if page!=PAGES[4]:
            next_button(st,PAGES[4],"查看失敗紀錄")
            return
    if page==PAGES[1]:
        st.subheader("資料確認與缺件")
        if run.input_package:
            p=run.input_package
            cols=st.columns(3)
            cols[0].metric("產品",p.product_id)
            cols[1].metric("資料包",p.package_id)
            cols[2].metric("已核對来源數",len(run.sources or run.evidence))
            with st.expander("建置身分與完整性"): st.json(p.model_dump())
        st.info("manifest 清單核對成功只代表交付完整性；CVE 證據是否足夠由工程 Queries 確認。")
        if run.missing:
            for item in run.missing: st.text(item)
        candidates=run.candidates.get("candidates",[])
        if payload: candidates=payload.get("discovery",{}).get("candidates",[])
        render_candidates(st,candidates,run.cve_id)
        next_button(st,PAGES[2],"下一步：調查來源")
    elif page==PAGES[2]:
        if payload:
            render_engineering(st,payload["analyses"][0],package=payload.get("input"))
            next_button(st,PAGES[3],"下一步：AI 查核與補件")
        else:
            st.subheader("執行工程分析")
            cve=run.cve_id
            if not cve:
                options=[item["cve_id"] for item in run.candidates.get("candidates",[])]
                selected=st.selectbox("選擇一個 CVE 進行分析",[""]+options,key="analysis-cve-"+run.run_id)
                cve=selected or st.text_input("或輸入 CVE ID",key="analysis-custom-"+run.run_id).strip().upper()
            else: st.text("本次分析："+cve)
            from .analysis_context import read_analysis_context
            history_ok=True
            saved_symptom=""
            if run.input_package and run.input_package.context_hash:
                try:
                    saved_symptom=read_analysis_context(runner.store,run.run_id,cve_id=cve)["symptom"]
                except (ValueError,OSError,KeyError,TypeError):
                    history_ok=False
                    st.error("本次查核的歷史材料無法核對；請保留原紀錄並確認歷程，暫停建立新判定。")
            symptom=st.text_area("本次調查情境",value=saved_symptom or symptom_for_run(request,run.run_id),max_chars=4000,key="analysis-symptom-"+run.run_id)
            can_analyze=history_ok and run.status=="COLLECTED" and bool(run.input_package and run.input_package.context_hash and cve)
            st.caption("執行目前核心的 Queries、重新核對證據並保存工程初判；OFFLINE 不呼叫模型。")
            with st.expander("Queries 如何執行：本次查核內容",expanded=True):
                if cve:
                    prepared = render_preparation(st,cve,run.input_package.format if run.input_package else None)
                    if prepared['status']=='FORMAT_GAP':
                        can_analyze=False
                        st.warning('資料包與此 CVE 的已審查格式不對應。請回到第一步更換資料包或建立正確 CVE 的請求；暫停執行，避免產生無法深入查核的結果。')
                else:
                    st.info("先選擇或輸入 CVE，這裡會列出對應的查核項目。")
            from cvevidence_core.catalog import CATALOG
            action_label="開始 CVE 調查與材料盤點" if cve and cve not in CATALOG else "執行 Queries 與正式判定"
            if st.button(action_label,type="primary",disabled=not can_analyze):
                try:
                    with st.spinner("核對本次工程資料並執行 Queries…"):
                        child=runner.analyze_offline(run.run_id,cve_id=cve,symptom=symptom)
                    st.session_state.selected_run=child.run_id
                    st.rerun()
                except (ValueError,OSError,RuntimeError): st.error("工程分析未完成，請確認 CVE 與收件狀態。")
        with st.expander("證據瀏覽器：搜尋、核對原文與比較來源"):
            source_viewer(st,runner,run)
        if not payload:
            next_button(st,PAGES[4],"下一步：查核紀錄與補件")
    else:
        if page==PAGES[3] and payload:
            entry=payload["analyses"][0]
            ai_workspace(st,runner,run,payload)
            next_button(st,PAGES[4],"查看目前報告")
            for gap in (entry.get("assessment") or {}).get("gaps",[]): st.text(str(gap.get("needed",gap)))
        st.subheader("查核紀錄與後續行動")
        ai_record=None
        report_payload=payload
        if payload:
            try:
                ai_record=selected_ai(st,runner,run)
                report_payload=with_ai_result(payload,ai_record)
            except (ValueError,OSError,KeyError,TypeError):
                st.warning("選取的 AI 紀錄無法核對，報告只包含工程結果。")
        text=export_analysis(report_payload,context_hash=run.input_package.context_hash,cve_id=run.cve_id,run_id=run.run_id) if payload else report(run)
        if ai_record:
            metadata=ai_record["request"]
            text="AI 獨立紀錄："+metadata["ai_id"]+" · "+metadata["created_at"]+" · "+ai_record["status"]+"\n原工程紀錄未覆寫。\n\n"+text
            st.text("附加 AI 紀錄："+metadata["ai_id"]+" · "+ai_record["status"])
        if payload:
            assessment=payload["analyses"][0].get("assessment") or {}
            st.text(VERDICTS.get(assessment.get("verdict"),"尚未產生工程判定"))
            st.text(assessment.get("reason","請查看紀錄中的未完成原因。"))
        with st.expander("完整報告預覽"):
            st.code(text,language=None)
        st.download_button("下載查核紀錄",text,file_name=run.run_id+".txt",mime="text/plain")
        with st.expander("來源操作紀錄"):
            try:
                history=runner.tool_history(run.run_id)
                if history["invalid_receipts"]:
                    st.warning("部分操作紀錄無法核對，原檔保留。")
                if history["events"]:
                    st.dataframe([{k:e.get(k) for k in ("created_at","operation","status","event_id")}
                        for e in history["events"]],hide_index=True)
                else: st.caption("尚無手動來源查詢紀錄。")
                st.caption("未保存搜尋詞或原文，只保留run/context與參數／結果摘要hash；缺少結束紀錄不算成功。")
                import json
                st.download_button("下載操作紀錄",json.dumps(history,ensure_ascii=False,indent=2),
                    file_name=run.run_id+"-events.json",mime="application/json")
            except (ValueError,OSError): st.error("操作紀錄無法讀取，沒有顯示未核對內容。")
        if run.parent_run_id:
            st.subheader("與父 run 比較")
            st.json(compare(store.read(run.parent_run_id),run))
        if payload:
            try:
                previous=previous_engineering_run(store,run)
                if previous:
                    st.subheader("補件前後工程結果")
                    st.text("前次工程 Run："+previous.run_id)
                    st.json(compare_analyses(runner.read_engineering(previous.run_id),payload,
                        parent_context=previous.input_package.context_hash,child_context=run.input_package.context_hash,cve_id=run.cve_id,
                        include_followup_queries=True))
            except (ValueError,OSError,TypeError,KeyError):
                st.warning("前後工程結果無法核對，不顯示未確認的比較。")
        if not run.error:
            st.subheader("補充資料，保留前後紀錄")
            real=bool(run.input_package and run.input_package.context_hash)
            matching=[e for e in entries if real and e["available"] and e["kind"]=="supplement"
                and e["base_package_id"]==run.input_package.package_id
                and e["build_id"]==run.input_package.declared_build_id]
            if matching:
                selected_delta=st.selectbox("已取得的同 build 補件",range(len(matching)),
                    format_func=lambda i:matching[i]["package_id"]+" · "+matching[i]["dataset"])
                if st.button("套用已取得的補件並建立新 run"):
                    with st.spinner("核心正在驗證補件…"):
                        item=matching[selected_delta]
                        child=runner.supplement_file(run.run_id,path=item["local_path"],
                            archive_sha256=item["archive"]["sha256"],manifest_sha256=item["manifest_sha256"])
                    st.session_state.selected_run=child.run_id
                    st.session_state.step=PAGES[2] if not child.error else PAGES[4]
                    st.rerun()
            with st.form("supplement-"+run.run_id):
                delta=st.file_uploader("同 build 增量補件 tar.gz / ZIP" if real else "完整替換快照 ZIP",
                    type=["zip","gz","tar"],max_upload_size=512,key="replacement-"+run.run_id)
                note=st.text_area("人工補充說明（待覆核）",max_chars=4000,key="note-"+run.run_id)
                send=st.form_submit_button("保存補件並建立新 run")
            st.caption("核心會核對產品／release／build／成品與既有檔案；不同 build 或衝突拒收，原 run 保留。文字不直接改判定。")
            if send:
                try:
                    with st.spinner("驗證同 build 補件…"):
                        if real:
                            if delta: delta.seek(0)
                            child=runner.supplement_file(run.run_id,stream=delta,note=note)
                        else: child=runner.supplement(run.run_id,delta.getvalue() if delta else None,note)
                    st.session_state.selected_run=child.run_id
                    st.session_state.step=PAGES[2] if not child.error else PAGES[4]
                    st.rerun()
                except (ValueError,OSError): st.error("補件未保存，請提供資料或說明。")
            next_button(st,PAGES[1],"回到資料確認")
