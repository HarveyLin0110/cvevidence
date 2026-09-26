"""Read-only rendering of saved core output; never executes or verifies analysis.

The caller must read a validated, user-scoped saved result. Scope checks here are
defence against displaying the wrong selection, not proof of evidence integrity.
"""
import json
from .ai_presenter import attempt_metadata, metadata_lines, receipt_lines
from .query_display import query_ids, query_title, query_description
from .result_summary import conclusion, query_summaries, condition_interpretation, condition_groups, pc_summaries

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
FOLLOWUP_STATES = {
    "WAITING_USER_INPUT": "等待用戶補件",
    "WAITING_VERIFICATION": "材料已收到，等待交叉驗證",
    "VERIFIED": "核心已驗證",
    "REJECTED": "已拒絕",
}
RUNTIME_STATES = {
    "MISSING": "缺少實際運作證據",
    "AWAITING_EVIDENCE": "等待運作證據補件",
    "VERIFIED": "核心已驗證運作證據",
    "REJECTED": "運作證據已拒絕",
    "NOT_REQUIRED": "本次核心判定不需運作證據",
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


def scoped_followup_queries(entry, *, context_hash):
    """Check display scope/identity only, without verifying or resolving a gap."""
    if "followup_queries" not in entry:
        return []
    queries = entry["followup_queries"]
    if not isinstance(queries, list):
        raise ValueError("Invalid follow-up queries")
    seen = set()
    for query in queries:
        if not isinstance(query, dict):
            raise ValueError("Invalid follow-up query")
        qid = query.get("query_id")
        if (not isinstance(qid, str) or not qid or qid in seen
                or not context_hash or query.get("context_hash") != context_hash
                or query.get("origin") != "RULE_GAP"
                or query.get("target_condition_id") != "runtime_observation"
                or query.get("status") not in FOLLOWUP_STATES
                or any(not isinstance(query.get(k), str) for k in ("question", "reason"))
                or any(not isinstance(query.get(k), list)
                       or any(not isinstance(v, str) for v in query[k])
                       for k in ("required_files", "evidence_ids"))):
            raise ValueError("Follow-up query identity or scope mismatch")
        seen.add(qid)
    return queries


def runtime_summary(entry):
    """Describe only the saved summary; absence in old runs means no new claim."""
    if "runtime_observation" not in entry:
        return []
    observation = entry["runtime_observation"]
    if not isinstance(observation, dict):
        return ["此紀錄的運作證據摘要格式無法讀取；請核對保存資料。"]
    basis = {
        "CONTROLLED_LOCAL_OBSERVATION": "受控環境本機觀測",
        "USER_SUPPLIED_OBSERVATION": "用戶提供的運作觀測材料",
        "NOT_OBSERVED": "尚無運作觀測",
    }
    return ["PC3 運作證據狀態：" + RUNTIME_STATES.get(observation.get("status"), "未提供有效狀態")
            + "（" + text(observation.get("status")) + "）",
            "證據基礎：" + basis.get(observation.get("evidence_basis"), "未提供有效證據基礎")
            + "（" + text(observation.get("evidence_basis")) + "）",
            text(observation.get("description")),
            "保存的 provenance_verified：" + text(observation.get("provenance_verified")),
            "受控環境觀測或用戶提供材料不代表實體客戶 FW 認證；本頁未驗證來源真實性。"]


def model_task_status(task):
    if task.get("status") == "COMPLETED":
        if task.get("action") == "ASK_USER":
            return "等待用戶補件（WAITING_USER_INPUT；補件要求已提出）"
        return "調查動作已完成（不代表 CVE 條件成立）"
    return text(task.get("status"))


def render_followup_queries(st, entry, *, context_hash):
    if "followup_queries" not in entry:
        return
    st.subheader("追加 Query · 規則缺口")
    st.caption("RULE_GAP 由核心提出；問題狀態採保存結果，補件與條件是否成立由核心核對。")
    try:
        queries = scoped_followup_queries(entry, context_hash=context_hash)
    except ValueError:
        st.error("追加 Query 的格式或快照範圍不符，未顯示其內容。")
        return
    if not queries:
        st.info("本次核心未列出規則缺口追加 Query。")
    for query in queries:
        with st.expander(text(query["query_id"]) + " · " + FOLLOWUP_STATES[query["status"]], expanded=True):
            st.text(query["question"])
            st.text("原因：" + query["reason"])
            st.caption("來源：RULE_GAP · 目標條件：" + query["target_condition_id"])
            st.text("問題狀態：" + query["status"])
            if query["status"] == "REJECTED":
                st.warning("此證據未通過驗證，請覆核或補回正確的同成品資料。")
                lines(st, query["required_files"])
            else:
                st.text("需提供的資料（同 build／成品）" if query["status"] == "WAITING_USER_INPUT"
                        else "此問題要求的資料（保存紀錄）")
                lines(st, query["required_files"])
            st.text("引用證據：" + text(query["evidence_ids"]))
            st.caption("Context：" + query["context_hash"])


def render_excerpts(st, evidence):
    excerpts = rows(evidence.get("excerpts"))
    if not excerpts:
        st.caption("此紀錄未附原文段落，可由證據瀏覽器核對來源。")
        return
    paths = {w.get("source_id"): w.get("path") for w in rows(evidence.get("witnesses"))}
    for excerpt in excerpts:
        st.text(text(paths.get(excerpt.get("source_id")) or excerpt.get("source_id"))
                + " · 行 " + text(excerpt.get("start_line")) + "–" + text(excerpt.get("end_line")))
        st.code(text(excerpt.get("text")), language=None)
        st.caption(text(excerpt.get("excerpt_id")) + " · SHA256 " + text(excerpt.get("file_sha256")))


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
        st.info("尚未產生工程判定；未完成分析不能視為安全。")
        if entry.get('status') == 'UNSUPPORTED_CVE':
            st.warning('需要進一步調查：此為舊版未支援紀錄，當時未執行 CVE 條件驗證。請從原收件紀錄重新分析以啟動通用調查；歷史結果保留。')
        return
    if assessment.get('assessment_kind') == 'GENERAL_TRIAGE':
        from .general_triage_view import render
        render(st, entry)
        return
    if package:
        with st.expander("本次建置與輸入材料", expanded=False):
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
    tone = "affected" if verdict == "AFFECTED" else "pending" if verdict == "NEEDS_INVESTIGATION" else "neutral"
    # Keys select static CSS only. Evidence continues to use literal st.text.
    import hashlib
    scope_key = hashlib.sha256(str(assessment.get("assessment_id", entry.get("cve_id"))).encode()).hexdigest()[:16]
    with st.container(border=True, key="result_" + tone + "_" + scope_key):
        st.text(VERDICTS.get(verdict, "未提供有效工程判定"))
        summary = conclusion(entry)
        st.text(summary["text"])
        st.text("判定依據：" + text(summary["reason"]))
        if summary["detail"]: st.text(summary["detail"])
        st.caption("工程初判須覆核；不代表異常已歸因，也不是部署安全認證。")
    conditions = rows(assessment.get("conditions"))
    metrics = st.columns(3)
    metrics[0].metric("有證據支持的條件", sum(c.get("state") == "SUPPORTED" for c in conditions))
    metrics[1].metric("有證據阻斷的條件", sum(c.get("state") == "BLOCKED" for c in conditions))
    metrics[2].metric("尚待確認的條件", sum(c.get("state") == "UNKNOWN" for c in conditions))
    overview, queries_tab, evidence_tab, gaps_tab = st.tabs(["結果摘要", "Queries 執行紀錄", "證據與引用", "待補資料與覆核"])
    with overview:
        st.subheader("PC1／PC2／PC3 綜合結果")
        groups = pc_summaries(entry)
        if groups:
            st.caption("紅字標示本次受影響判定的支持條件；共用前提本身不代表風險。各 PC 不另產生獨立安全判定。")
            for index, group in enumerate(g for g in groups if not g["shared"]):
                with st.container(border=True, key="pc_" + group["tone"] + "_" + scope_key + "_" + str(index)):
                    st.text(text(group.get("group_id")) + " · " + text(group.get("title")) + " ｜ " + group["label"])
                    if group["context"]: st.text(group["context"])
                    for finding in group["findings"]:
                        st.text(finding["headline"])
                        if finding["locations"]:
                            st.caption("來源位置：" + "；".join(loc["label"] for loc in finding["locations"][:2]))
                        elif finding["state"] == "UNKNOWN":
                            st.caption("目前尚無可用來確認此條件的命中位置。")
                        for missing in finding["missing"][:2]: st.text("尚缺：" + missing)
                        for conflict in finding["conflicts"][:2]: st.text("矛盾：" + conflict)
                        if finding["condition_id"] == "runtime_observation" and finding["state"] == "SUPPORTED":
                            observation = next((loc for loc in finding["locations"] if loc["excerpt"]), None)
                            if observation:
                                st.text("本次原始運作紀錄：")
                                st.code("\n".join(observation["excerpt"].splitlines()[:3]), language=None)
                    with st.expander(text(group["group_id"]) + " 的判讀依據與命中原文", expanded=False):
                        for finding in group["findings"]:
                            st.text(finding["explanation"])
                            for location in finding["locations"][:8]:
                                st.text(location["label"])
                                if location["excerpt"]: st.code(location["excerpt"], language=None)
                                st.caption("來源 SHA256：" + text(location["file_sha256"]))
                            if len(finding["locations"]) > 8:
                                st.caption("其餘來源請見「證據與引用」。")
                    if group.get("meaning"): st.caption(text(group["meaning"]))
                    if any(c.get("condition_id") in ("entry_reachable", "trigger_prerequisites") for c in group["conditions"]):
                        st.caption("本段是交付程式路徑與必要條件的工程證據；不代表漏洞已觸發、實際部署可達或已遭利用。")
            shared = next(g for g in groups if g["shared"])
            count = "＋".join(str(len(g["conditions"])) for g in groups)
            st.caption("條件數：共用前提＋各 PC = " + count + " = " + str(len(conditions)) + " 項。Queries 是蒐集證據的查核工作，與條件數不同。")
            with st.expander("共用前提 · " + shared["label"], expanded=shared["tone"] == "pending"):
                st.text(shared["summary"])
        else:
            st.info("此保存紀錄未提供完整且不重複的 PC 分組；保留原始條件，重新分析後可取得新版分組。")
        if (entry.get("condition_groups") or {}).get("schema_version") == "2.0":
            st.caption("PC2：成品實作與靜態輸入路徑。PC3：實際部署與運作證據；靜態路徑不等於已觀測到實際運作。")
        for line in runtime_summary(entry):
            st.text(line)
        st.subheader("下一步可以做什麼")
        if assessment.get("gaps") or assessment.get("statement_reviews") or assessment.get("conflicts"):
            st.info("先看「待補資料與覆核」，再從側邊第 04 步提供同 build 材料；補件後回第 03 步重新分析。")
        else:
            st.info("先核對本次成品範圍與關鍵證據，再從側邊第 05 步下載報告供工程師覆核。")
        lines(st, assessment.get("next_steps"))
        st.subheader("適用範圍")
        st.text(text(assessment.get("scope")))
        if conditions:
            with st.expander("所有條件與詳細說明"):
                association = {c["condition_id"]: g["group_id"] for g in groups for c in g["conditions"]}
                st.dataframe([{"分組": association.get(c.get("condition_id"), "未提供分組"), "條件": text(c.get("title")),
                               "狀態": condition_interpretation(c)[0],
                               "說明": text(c.get("explanation")),
                               "尚不能據此認定": condition_interpretation(c)[1]} for c in conditions],
                             hide_index=True, use_container_width=True)
        else:
            st.info("未提供條件明細。")
    with queries_tab:
        st.caption("每項查核顯示當次保存的狀態；查核完成不代表產品不受影響。")
        summaries = query_summaries(entry)
        st.text("本次保存 " + str(len(summaries)) + " 項工程 Queries；數量依本次紀錄，不代表全部成功。")
        if summaries:
            st.dataframe([{"Query": q["query_id"], "名稱": q["label"], "用途": q["description"],
                           "層級": q["pc_layer"] or "未提供", "狀態": q["state"]} for q in summaries],
                         hide_index=True, use_container_width=True)
        else: st.info("本次沒有保存工程 Queries，不補造已執行項目。")
        query_rows = rows(entry.get("queries"))
        evidence_by_id = {e.get("evidence_id"): e for e in rows(entry.get("evidence"))}
        status_names = {"COMPLETED": "已完成", "COMPLETED_WITH_GAPS": "已執行・有缺件", "CONFLICT": "有矛盾待覆核"}
        for qid in query_ids(entry):
            matches = [q for q in query_rows if q.get("query_id") == qid]
            query = matches[0] if len(matches) == 1 else {}
            label = query_title(query, qid)
            status = status_names.get(query.get("status"), text(query.get("status")))
            with st.expander(qid + " · " + label + " ｜ " + status):
                st.text("狀態：" + text(query.get("status")))
                st.text(query_description(query))
                if query.get("pc_layer"):
                    st.caption("核心查核層級：" + text(query["pc_layer"]))
                if isinstance(query.get("metadata"), dict):
                    st.text("查核範圍：" + text(query["metadata"]))
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
                        with st.expander("原文段落 · " + text(eid)):
                            render_excerpts(st, evidence)
                with st.expander("追溯識別碼與查核原始資料"):
                    st.json(query)
        render_followup_queries(st, entry, context_hash=assessment.get("context_hash"))
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
                render_excerpts(st, evidence)
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
        if not any_pending and "followup_queries" not in entry:
            st.info("本次保存結果沒有列出缺件或矛盾；仍須人工覆核範圍，不能推論其他 CVE 或部署環境安全。")
        st.caption("補充資料請使用第 04 或 05 步的補件入口；會建立新紀錄，保留這次結果。")


def saved_collection_guide(ai, *, context_hash, cve_id, assessment_id):
    """Check display scope/shape; this does not verify collected materials."""
    for task in reversed(rows(ai.get("tasks"))):
        if task.get("action") != "ASK_USER" or task.get("status") != "COMPLETED": continue
        result = task.get("result")
        guide = result.get("collection_guide") if isinstance(result, dict) else None
        if not isinstance(guide, dict): continue
        if (guide.get("origin") != "CORE_PARSER_CONTRACT" or guide.get("schema_version") != "1.0"
                or guide.get("context_hash") != context_hash or guide.get("cve_id") != cve_id
                or guide.get("assessment_id") != assessment_id): continue
        items = guide.get("items")
        if not isinstance(items, list) or not 1 <= len(items) <= 8 or not isinstance(guide.get("details"), dict): continue
        if any(not isinstance(row, dict) or type(row.get("present")) is not bool
               or any(not isinstance(row.get(k), str) or not row[k] or len(row[k]) > 4000
                      for k in ("title", "path", "how", "purpose")) for row in items): continue
        return guide
    return None


def render_ai(st, ai, *, context_hash, cve_id, assessment_id, request=None):
    st.subheader("AI 查核建議")
    if not isinstance(ai, dict):
        st.info("尚無 AI 調查紀錄。可先查看工程缺口、下載報告或補充資料。")
        return
    if not assessment_id or ai.get("context_hash") != context_hash or ai.get("cve_id") != cve_id or ai.get("engineering_assessment_id") != assessment_id:
        st.error("AI 紀錄與目前工程結果不符，未顯示其內容。")
        return
    st.text("模式：" + text(ai.get("mode")) + " · 狀態：" + text(ai.get("status")))
    metadata = attempt_metadata(ai, request)
    for line in metadata_lines(metadata):
        st.text(line)
    if ai.get("mode") == "REPLAY":
        st.caption("這是既有紀錄播放，本次未呼叫模型。")
    if ai.get("status") in ("OFFLINE", "NOT_RUN", "CONFIG_REQUIRED"):
        st.info("本次沒有完成模型調查；工程结果仍可查閱與下載。")
    st.caption("AI 調查與工程判定分開；原文引用核對不表示語意已證明。")
    if ai.get("analysis_depth") == "PC_EVIDENCE_REVIEW":
        st.caption("本次採 PC1／PC2／PC3 原文查核；各層是否完成及限制，以保存的調查說明為準。")
        if ai.get("status") in ("COMPLETED", "NEEDS_USER_INPUT"):
            final = next((task for task in reversed(rows(ai.get("tasks")))
                          if task.get("status") == "COMPLETED" and task.get("action") in ("COMPLETE", "ASK_USER")), None)
            if final and final.get("finding"):
                st.subheader("PC1／PC2／PC3 查核說明")
                st.text(text(final["finding"]))
    st.caption("追加 Query 來源：MODEL。LIST／READ 等動作完成只代表工具已執行；ASK_USER 完成代表已提出補件要求。")
    from .investigation_view import render as render_investigation, render_requests
    render_investigation(st, ai)
    has_requests = render_requests(st, ai)
    guide = saved_collection_guide(ai, context_hash=context_hash, cve_id=cve_id, assessment_id=assessment_id)
    if guide and not has_requests:
        st.subheader("需要準備的最小材料")
        st.caption("清單依核心可接受的收件格式整理；已收到不等於已通過驗證。AI 調查與詳細格式可展開查看。")
        for item in guide["items"]:
            st.text(item["title"] + (" · 已收件，仍需核對" if item["present"] else " · 待提供"))
            st.text("取得方式：" + item["how"])
            st.caption("檔案：" + item["path"])
        with st.expander("詳細格式、成品範圍與驗收方式", expanded=False):
            st.text(text(guide.get("notice")))
            for item in guide["items"]: st.text(item["title"] + "：" + item["purpose"])
            st.code(text(guide["details"]), language="json")
    for index, task in enumerate(rows(ai.get("tasks")), 1):
        with st.expander("追加 Query · MODEL · " + text(task.get("task_id") or index), expanded=False):
            st.text(text(task.get("question")))
            st.text("目的：" + text(task.get("reason")))
            st.text("動作：" + text(task.get("action")) + " · " + model_task_status(task))
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
            for line in receipt_lines(call, metadata["provider"]):
                st.text(line)


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
