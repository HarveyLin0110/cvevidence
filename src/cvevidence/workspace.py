"""Local Streamlit workspace using the same Runner as CLI."""
import os
from .runner import Runner
from .storage import RunStore
from .sources import read_package
from .reports import report, compare, excerpt

def workspace(st):
    st.set_page_config(page_title="CVEvidence · 工程查核",layout="wide")
    store=RunStore(os.environ.get("CVEVIDENCE_STORE","var/runtime"))
    runner=Runner(store)
    st.title("CVEvidence · 工程查核")
    st.caption("本機整合版 · 保存／流程已接通；匯入、Q1–Q5、規則及 AI 等待 Horace 核心。")
    if not os.environ.get("CVEVIDENCE_CORE_MODULE"):
        st.warning("核心尚未接入：提交後只會保存 CORE_UNAVAILABLE，不會產生分析結果。")
    st.session_state.setdefault("selected_run",None)
    pages=["01 產品與資料來源","02 資料確認與缺件","03 分析進度與結果","04 報告與後續行動"]
    page=st.sidebar.radio("查核步驟",pages,key="step")
    runs=store.list_runs()
    if runs:
        options=["—"]+[r.run_id for r in runs]
        chosen=st.sidebar.selectbox("保存的查核紀錄",options,key="history_select")
        if chosen!="—" and st.sidebar.button("載入查核紀錄"):
            st.session_state.selected_run=chosen
    st.sidebar.info("切换 run 會依 run ID 重載結果；工程初判與執行錯誤分開呈現。")
    run=store.read(st.session_state.selected_run) if st.session_state.selected_run else None
    if page==pages[0]:
        st.subheader("產品與資料來源")
        with st.form("new_run"):
            product=st.text_input("產品 ID",value="TEST-PRODUCT")
            cve=st.text_input("CVE ID",placeholder="CVE-2014-0160")
            description=st.text_area("情境說明（選填）",max_chars=4000)
            source=st.selectbox("輸入方式",["ZIP 上傳","受控路徑"])
            upload=st.file_uploader("工程資料 ZIP（上限 20 MiB）",type=["zip"])
            path=st.text_input("artifact 根目錄下的相對路徑")
            mode=st.selectbox("模式",["OFFLINE","LIVE"])
            submit=st.form_submit_button("匯入並保存查核紀錄")
        st.caption("產品＋版本索引、無 CVE 的候選探索等待 Horace discover_candidates 介面；不使用猜測結果。")
        if submit:
            st.session_state.selected_run=None
            try:
                if not product.strip() or not cve.strip():
                    raise ValueError("目前先指定產品與 CVE；無 CVE 的探索流程待核心交付")
                if source=="ZIP 上傳":
                    if upload is None: raise ValueError("請選擇 ZIP")
                    payload=upload.getvalue()
                else:
                    root=os.environ.get("CVEVIDENCE_ARTIFACT_ROOT")
                    if not root: raise ValueError("尚未設定 CVEVIDENCE_ARTIFACT_ROOT")
                    payload=read_package(root,path)
                with st.spinner("執行受限匯入並保存…"):
                    result=runner.start(payload,product.strip(),cve.strip().upper(),mode)
                st.session_state.selected_run=result.run_id
                if description.strip() and not result.error:
                    result=runner.supplement(result.run_id,note=description)
                    st.session_state.selected_run=result.run_id
                if result.error:
                    st.error(result.error.code+": "+result.error.message)
                else:
                    st.success("資料已保存。請前往「02 資料確認與缺件」。")
                st.code(result.run_id)
            except (ValueError,OSError):
                st.error("無法匯入：請確認產品、CVE、檔案／路徑及儲存位置。原查核紀錄未覆寫。")
        return
    if run is None:
        st.info("請先匯入資料，或從側邊載入保存的查核紀錄。")
        return
    st.caption("Run: "+run.run_id+" · "+run.mode+" · "+run.status)
    if run.error:
        st.error(run.error.code+": "+run.error.message)
    if page==pages[1]:
        st.subheader("資料確認與缺件")
        if run.input_package:
            st.json(run.input_package.model_dump())
        st.write("已核對檔案數："+str(len(run.evidence)))
        st.write("manifest 缺件："+(", ".join(run.missing) or "無；仍不表示 CVE 證據完整"))
        st.info("hash 一致與 build ID 宣告相同，不等於實際來源／同次建置已認證。")
    elif page==pages[2]:
        st.subheader("分析進度與結果")
        st.warning("NOT_ASSESSED · Q1–Q5／PC 規則核心尚未串接，沒有正式漏洞判定。")
        for q in ("Q1_COMPONENT","Q2_BUILD","Q3_IMPLEMENTATION","Q4_BINDING","Q5_PATH"):
            st.write(q+" · 待核心接入")
        if run.evidence:
            evidence_id=st.selectbox("本 run 的原始證據",[e.evidence_id for e in run.evidence],key="evidence-"+run.run_id)
            try:
                st.code(excerpt(store,run.run_id,evidence_id),language=None)
            except (ValueError,OSError,RuntimeError):
                st.error("原文讀取或核對失敗，未顯示未驗證片段。")
        st.subheader("AI 建議")
        st.info("目前没有呼叫 AI；等待 Horace investigate 回傳經核對的引用與問題。")
    else:
        st.subheader("報告與後續行動")
        text=report(run)
        st.code(text,language=None)
        st.download_button("下載查核紀錄",text,file_name=run.run_id+".txt",mime="text/plain")
        if run.parent_run_id:
            st.subheader("與父 run 比較")
            st.json(compare(store.read(run.parent_run_id),run))
        if not run.error:
            st.subheader("補充資料，再建立新紀錄")
            with st.form("supplement-"+run.run_id):
                replacement=st.file_uploader("完整替換快照 ZIP（選填）",type=["zip"],key="replacement-"+run.run_id)
                note=st.text_area("人工補充說明（待覆核）",max_chars=4000,key="note-"+run.run_id)
                send=st.form_submit_button("保存補件並建立新 run")
            st.caption("既有檔案不可移除或改寫；文字不解除未知。完整的材料／規則重查等待核心串接。")
            if send:
                try:
                    child=runner.supplement(run.run_id,replacement.getvalue() if replacement else None,note)
                    st.session_state.selected_run=child.run_id
                    st.rerun()
                except (ValueError,OSError):
                    st.error("補件未保存，請確認內容與儲存狀態。")
