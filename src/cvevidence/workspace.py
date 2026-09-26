"""Actual local source workspace; all collection/supplement calls share Runner."""
import os
from cvevidence_core.partial_intake import IntakeError
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
from .ai_workspace import ai_workspace, selected_ai, with_ai_result, report_ai_selector
from .ai_presenter import attempt_metadata
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
        left, right = st.columns(2)
        left.info("不知道是哪個 CVE：描述發生了什麼，先交手邊材料；CVE 留白，再從候選選擇要深入查核的項目。")
        right.info("已知想查的 CVE：輸入 CVE 編號與產品材料，逐項核對元件、實作及部署證據。")
        st.caption("目前没有檔案可選「先描述情境」保存草稿；有零散檔案可選「部分材料」，不必先製作工程包。")
        source_options=["產品／版本樣品","上傳工程包","部分材料（SBOM／日誌／原碼／設定）","部分材料：大型 ROM／SDK（單檔）"]
        if store_root is None: source_options.append("受控路徑")
        source_options.append("先描述情境")
        kind=st.radio("資料來源",source_options,horizontal=True)
        available=[e for e in entries if e["available"] and e["kind"]=="initial"]
        selected=None
        upload=None
        partial_files=[]
        partial_large=False
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
        elif kind.startswith("部分材料"):
            st.info("可先提交手上已有的檔案；不需要自製 manifest。產品與 build 只記為聲明，不冒充已驗成品。")
            partial_large='大型' in kind
            if partial_large:
                single=st.file_uploader('大型 ROM 或 SDK 封存檔（單檔 256 MiB）',max_upload_size=256)
                partial_files=[single] if single else []
                st.caption('一次一檔，原檔及展開內容合計最多 384 MiB、5000 個檔案。接受 ROM／IMG／BIN／SquashFS 或 ZIP／tar／tar.gz／wheel。SDK 只展開為資料，不安裝或執行；網頁元件仍會暫存上傳內容。')
            else:
                partial_files=st.file_uploader("部分材料（每檔 20 MiB，最多 100 檔）",accept_multiple_files=True,max_upload_size=20)
                st.caption("最多 100 檔、每檔 20 MiB，全部材料含壓縮包展開後合計 100 MiB。可交 SBOM、日誌、原碼、設定或原始 wheel／ZIP／tar.gz；壓縮包只讀取，不安裝或執行。")
            st.caption('亦可交原始 SquashFS ROM（每次最多 3 份）；工具只讀固定套件／版本路徑，不啟動韌體。其他 ROM 格式會保留原檔並顯示尚不支援。')
            partial_product=st.text_input("產品名稱",value="未提供",max_chars=200)
            partial_release=st.text_input("產品版本",value="未提供",max_chars=200)
            partial_build=st.text_input("建置識別（不知道可保留未確認）",value="未確認",max_chars=200)
        elif kind=="受控路徑":
            st.caption("根目錄："+os.environ.get("CVEVIDENCE_ARTIFACT_ROOT","var/artifacts"))
            path=st.text_input("相對路徑",placeholder="archives/資料版本/06_cmake.tar.gz")
        cve=st.text_input("CVE ID（最多 5 個，逗號或空白分隔；可留白）",placeholder="CVE-2022-37434, CVE-2023-38545")
        symptom=st.text_area("情境與想確認的問題",max_chars=4000,placeholder="描述操作、異常、部署方式；說明只作調查背景。")
        ready=bool(selected) if kind=="產品／版本樣品" else upload is not None if kind=="上傳工程包" else bool(path.strip())
        if kind.startswith("部分材料"):ready=bool(partial_files)
        if kind=="先描述情境": ready=bool(symptom.strip() or cve.strip())
        signature=(kind,selected["archive"]["sha256"] if selected else None,
            getattr(upload,"file_id",None),tuple((f.name,f.file_id) for f in partial_files),
            (partial_product,partial_release,partial_build) if kind.startswith("部分材料") else None,path,cve,symptom,st.session_state.get("follow_parent"))
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
                    elif partial_files:
                        from cvevidence_core.partial_intake import create
                        import tempfile
                        with tempfile.TemporaryDirectory(dir=runner.store.root) as temporary:
                            archive=Path(temporary)/"partial.tar.gz"
                            create([(f.name,f) for f in partial_files],archive,product=partial_product,release=partial_release,build=partial_build,large=partial_large)
                            result=runner.submit_request(path=archive,**kwargs)
                    elif upload:
                        upload.seek(0)
                        result=runner.submit_request(stream=upload,**kwargs)
                    elif kind=="先描述情境": result=runner.submit_request(**kwargs)
                    else: result=runner.submit_request(path=controlled_path(path),**kwargs)
                st.session_state.selected_request=result.spec.request_id
                st.session_state.selected_run=result.runs[0].run_id if result.runs else None
                st.rerun()
            except IntakeError as exc:
                st.error(str(exc))
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
    discovery_key = "public-discovery-" + run.run_id
    if discovery_key not in st.session_state:
        try:
            st.session_state[discovery_key] = runner.public_discovery(run.run_id)
        except (ValueError, OSError, KeyError, TypeError):
            st.error("公開候選歷史無法核對，未顯示未驗證結果；原紀錄保留，可重新查詢。")
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
        from .compilation_view import render as render_compilation
        render_compilation(st,(payload.get('discovery',{}) if payload else run.candidates).get('compilation_database'),
                           {s.source_id:s.path for s in run.sources})
        provenance=(payload.get('discovery',{}) if payload else run.candidates).get('build_provenance')
        if provenance and provenance.get('records'):
            with st.expander('建置聲明與交付檔案核對（未認證來源）'):
                st.caption(provenance['note'])
                status_labels={
                    'DECLARED_DIGESTS_MATCH':'聲明中的 SHA256 均與交付檔案吻合（建置來源仍未驗證）',
                    'PARTIAL_DIGEST_COVERAGE':'僅部分資料可核對，尚不足以建立完整對應',
                    'NAMED_SOURCE_CONFLICT':'同名檔案內容與聲明不一致，需先釐清版本',
                    'MALFORMED_DECLARATION':'聲明欄位格式有誤，無法核對',
                    'ENVELOPE_NOT_SUPPORTED':'尚不支援此簽章封裝，未核對內容或簽章',
                    'REFERENCE_LIMIT':'聲明項目超過讀取上限，未完成核對',
                }
                reference_labels={
                    'MATCHES_DELIVERED_BYTES':'SHA256 與交付檔案吻合',
                    'NOT_IN_SNAPSHOT':'本次材料中沒有相同 SHA256 的檔案',
                    'NO_SUPPORTED_DIGEST':'未提供可核對的 SHA256',
                }
                source_paths={s.source_id:s.path for s in run.sources}
                for record in provenance['records']:
                    st.text(record['path']+' · '+status_labels.get(record['status'],'未知核對狀態'))
                    if record.get('references'):
                        st.dataframe([{'角色':{'subject':'產出成品','dependency':'建置輸入'}.get(r['role'],'其他'),
                            '聲明名稱':r['declared_name'],
                            '核對結果':'同名檔案內容不一致' if r['named_source_conflict'] else reference_labels.get(r['state'],'未知核對狀態'),
                            '對應交付檔案':'、'.join(source_paths.get(sid,sid) for sid in r['matched_source_ids']) or '無',
                            '聲明 SHA256':r.get('declared_sha256') or '未提供',
                            '顯示範圍':'僅顯示前 8 個吻合檔案' if r.get('matches_truncated') else '已顯示全部吻合檔案',
                            } for r in record['references']],hide_index=True)
                if provenance.get('coverage_limited'):st.caption('建置聲明僅掃描有限範圍，未列出不代表不存在。')
        binaries=(payload.get('discovery',{}) if payload else run.candidates).get('binary_metadata')
        if binaries and binaries.get('files'):
            with st.expander('執行檔架構與動態依賴（PC2 線索）'):
                st.caption(binaries['note'])
                st.dataframe([{'來源':r['path'],'狀態':r['status'],
                    '位元':(r.get('metadata') or {}).get('class_bits'),
                    '架構編號':(r.get('metadata') or {}).get('machine_id'),
                    '位元組序':(r.get('metadata') or {}).get('byte_order'),
                    '動態依賴名稱':'、'.join((r.get('metadata') or {}).get('needed',[])),
                    '相同內容的交付檔案':'、'.join(m['path'] for m in r.get('identical_delivered_files',[])) or '未列出',
                    'SHA256':r['sha256']} for r in binaries['files']],hide_index=True)
                st.caption('相同內容依 SHA256 比對；只能證明檔案內容一致，未認證建置來源或實際載入關係。未列出不代表不存在。')
                with st.expander('查看成品的動態符號（PC2 線索）'):
                    st.caption('匯入符號表示檔案中的外部符號參照，不代表執行時已呼叫或路徑可達。未列出不能排除靜態整合、動態查找或讀取限制。')
                    for item in binaries['files']:
                        symbols=(item.get('metadata') or {}).get('symbols',{})
                        st.text(item['path'])
                        if symbols.get('status')!='READ':
                            st.caption('未取得可用動態符號表；不能據此判定未使用某 API。')
                            continue
                        imports=symbols.get('imports',[])
                        if imports:
                            st.dataframe([{'匯入符號':s['name'],
                                '類型':{0:'未指定',1:'資料物件',2:'函式',6:'執行緒資料'}.get(s['type'],'其他'),
                                '連結屬性':{1:'全域',2:'弱參照'}.get(s['binding'],'其他')} for s in imports],hide_index=True)
                        else:st.caption('此動態符號表沒有列出的外部參照；仍不能排除其他呼叫方式。')
                        if symbols.get('coverage_limited'):st.caption('符號清單已截短，僅顯示有限項目。')
                if binaries.get('coverage_limited'):st.caption('僅完成有限範圍掃描；未列出不代表不存在。')
        firmware=(payload.get('discovery',{}) if payload else run.candidates).get('firmware_inventory',[])
        if firmware:
            with st.expander('ROM 套件、版本與成品讀取狀態',expanded=True):
                labels={'PARTIAL_READ':'已讀取部分材料（非完整 ROM）','NO_INVENTORY_READ':'未能讀取選定材料（不代表不存在）',
                        'UNSUPPORTED_FORMAT':'目前不支援此映像格式','TOOL_UNAVAILABLE':'伺服器未備妥 ROM 讀取工具',
                        'ISOLATION_UNAVAILABLE':'伺服器無法建立隔離讀取環境，未解析 ROM',
                        'INVALID_RECEIPT':'讀取紀錄無法核對'}
                for item in firmware:
                    st.text(str(item['image_path'])+'：'+labels.get(item['status'],'讀取狀態待確認'))
                    if item.get('binary_scan'):
                        count=sum(r.get('kind')=='ELF_CANDIDATE' and r.get('status')=='READ' for r in item.get('files',[]))
                        st.caption(f'本次擷取 {count} 份 ELF 候選，架構與相同內容比對見上方面板。只探查有限路徑與大小；未列出不代表不存在。')
                    if item['status']=='ISOLATION_UNAVAILABLE':
                        st.caption('請由部署維護者檢查隔離環境；不會停用隔離改成直接讀取，也不需要因此重傳相同 ROM。')
                    if item['status'] in ('UNSUPPORTED_FORMAT','TOOL_UNAVAILABLE','NO_INVENTORY_READ'):
                        st.caption('可先提供現有套件清單／SBOM 繼續調查；這是讀取能力或固定路徑限制，不是要求提供所有工程材料。')
                    with st.expander('查看 ROM 讀取範圍與 hash '+str(item['image_path'])):
                        st.json(item)
                st.caption('原 ROM 與擷取檔案的 hash 關聯不代表來源認證，也不能證明 SDK／原碼／運作紀錄屬於同次建置。')
        inventory=(payload.get('discovery',{}) if payload else run.candidates).get('components',[])
        if inventory:
            with st.expander('已辨識的元件與套件清單',expanded=True):
                st.caption('這是材料中的版本聲明，尚未證明屬於同一 ROM 或同次建置。一般套件名稱不會自動轉成上游生態系統。自動解析最多掃描 100 份合格檔案、保留 100 筆一般清單項目；不是完整軟體資產盤點。')
                st.dataframe([{'元件':r['name'],'版本聲明':r['version'],'來源':r.get('source_path',r['source_id']),
                    '類型':r['source_kind'],'原文行':str(r.get('start_line',''))+('–'+str(r['end_line']) if r.get('end_line') else '')}
                    for r in inventory],hide_index=True,width='stretch')
        if run.missing:
            for item in run.missing: st.text(item)
        with st.expander("擴充公開漏洞候選探索（SBOM 元件／版本）"):
            st.caption("支援 CycloneDX／SPDX 的套件 purl。只外送套件名稱、生態系統與版本至 OSV；症狀與原碼留在本機，症狀僅用於排序，不能證明原因。")
            public_consent=st.checkbox("同意將已提交的套件名稱及版本查詢 OSV",key="osv-consent-"+run.run_id)
            if st.button("查詢公開候選",disabled=not public_consent):
                try:
                    st.session_state[discovery_key]=runner.discover_public(run.run_id,consent=True)
                except (ValueError, OSError, RuntimeError, KeyError, TypeError):
                    st.error("本次公開查詢未完成；先前保存結果仍保留，未把失敗當成沒有漏洞。")
            public_result=st.session_state.get("public-discovery-"+run.run_id)
            if public_result:
                import json
                st.download_button('下載公開候選查詢紀錄',json.dumps(public_result,ensure_ascii=False,indent=2),file_name=run.run_id+'-public-candidates.json',mime='application/json')
                st.text("查詢狀態："+public_result["discovery"]["status"])
                st.caption("已保存本次查詢；重新整理後可還原，查看紀錄不會重新連網。重新查詢才會更新候選。")
                st.caption(public_result["discovery"]["scope"])
                st.caption(f"找到 {len(public_result['discovery']['candidates'])} 個候選；下方可查看漏洞摘要與命中套件。")
                with st.expander("完整公開查詢紀錄（JSON）", expanded=False):
                    st.json(public_result)
        candidates=(payload.get("discovery",{}) if payload else run.candidates).get("candidates",[])
        public_candidates=(st.session_state.get("public-discovery-"+run.run_id) or {}).get("discovery",{}).get("candidates",[])
        # Prefer public summaries while retaining the selected inventory's scope fields.
        merged={item["cve_id"]:dict(item) for item in public_candidates}
        for item in candidates:
            merged[item["cve_id"]]={**merged.get(item["cve_id"],{}),**item}
        candidates=list(merged.values())
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
                public_candidates=(st.session_state.get('public-discovery-'+run.run_id) or {}).get('discovery',{}).get('candidates',[])
                options=list(dict.fromkeys(item['cve_id'] for item in run.candidates.get('candidates',[])+public_candidates))
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
            gaps=(entry.get("assessment") or {}).get("gaps",[])
            if gaps:
                with st.expander("原工程缺口（不是本輪補件清單）",expanded=False):
                    for message in dict.fromkeys(str(gap.get("needed",gap)) for gap in gaps):st.text(message)
        st.subheader("查核紀錄與後續行動")
        ai_record=None
        report_payload=payload
        if payload:
            try:
                if page == PAGES[4]:
                    report_ai_selector(st,runner,run)
                ai_record=selected_ai(st,runner,run)
                report_payload=with_ai_result(payload,ai_record)
            except (ValueError,OSError,KeyError,TypeError):
                ai_record=None
                st.warning("選取的 AI 紀錄無法核對，報告只包含工程結果。")
        text=export_analysis(report_payload,context_hash=run.input_package.context_hash,cve_id=run.cve_id,run_id=run.run_id) if payload else report(run)
        if ai_record:
            metadata=ai_record["request"]
            text="AI 獨立紀錄："+metadata["ai_id"]+" · "+metadata["created_at"]+" · "+ai_record["status"]+"\n原工程紀錄未覆寫。\n\n"+text
            st.text("附加 AI 紀錄："+metadata["ai_id"]+" · "+attempt_metadata(request=metadata)["provider_label"]+" · "+ai_record["status"])
        if ai_record and page == PAGES[4]:
            from .review_workspace import review_workspace, report_text
            selected_review = review_workspace(st, runner, run, ai_record)
            if selected_review:
                text += "\n\n" + report_text(selected_review)
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
            st.subheader("本次與前次材料差異")
            difference = compare(store.read(run.parent_run_id),run)
            if difference['status'] == 'REJECTED':
                st.warning("補件未接受；前次材料與結果保留。")
            else:
                columns = st.columns(3)
                for column, field, label in zip(columns, ('added','removed','changed'), ('新增檔案','移除檔案','內容變更')):
                    column.metric(label, len(difference[field]))
                st.caption("檔案變化不等於漏洞條件已證實；補件仍需執行查核。")
            with st.expander("材料差異明細與完整紀錄"):
                st.json(difference)
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
            if real and run.input_package.format=='partial':
                st.caption('僅補本輪要求的材料即可，不需把所有可能檔案都補齊。每檔 20 MiB，最多 100 檔；新增材料含展開後合計 100 MiB，同名衝突拒收。')
                loose=st.file_uploader('補上原始檔案（保留原材料，拒絕同名覆寫）',accept_multiple_files=True,max_upload_size=20,key='partial-delta-'+run.run_id)
                large_loose=st.file_uploader('或補一份大型 ROM／SDK（單檔 256 MiB）',max_upload_size=256,key='partial-large-delta-'+run.run_id)
                st.caption('一般多檔與大型單檔請擇一。大型檔案及展開内容、以及補件後整份快照，最多 384 MiB／5000 檔。')
                if st.button('保存部分材料補件',disabled=not (loose or large_loose) or bool(loose and large_loose)):
                    try:
                        chosen_loose=[large_loose] if large_loose else loose
                        child=runner.supplement_partial(run.run_id,[(f.name,f) for f in chosen_loose],large=bool(large_loose))
                        st.session_state.selected_run=child.run_id
                        st.session_state.step=PAGES[2] if not child.error else PAGES[4]
                        st.rerun()
                    except IntakeError as exc:st.error(str(exc))
                    except (ValueError,OSError):st.error('補件與原快照衝突或格式不符，未覆寫原材料。')
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
