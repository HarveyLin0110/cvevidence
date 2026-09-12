"""Plain text export and scoped comparison of saved core JSON.

Callers supply authorized saved runs; this module does not load files or verify
core evidence. Comparisons describe differences, never infer why verdicts changed.
"""
from .analysis_view import QUERIES, VERDICTS, rows, select_analysis, text, condition_groups
from .result_summary import conclusion_dimensions


def previous_engineering_run(store, run):
    """Follow explicit local parent IDs, with cycle/depth guard; never search by CVE."""
    seen = {run.run_id}
    current = run.parent_run_id
    for _ in range(32):
        if not current: return None
        if current in seen: raise ValueError("Cyclic run lineage")
        seen.add(current)
        parent = store.read(current)
        if parent.cve_id and parent.cve_id != run.cve_id: raise ValueError("Parent CVE mismatch")
        if parent.engineering_payload_sha256: return parent
        current = parent.parent_run_id
    raise ValueError("Run lineage exceeds display limit")


def export_analysis(payload, *, context_hash, cve_id, run_id):
    entry = select_analysis(payload, context_hash=context_hash, cve_id=cve_id)
    assessment = entry.get("assessment") or {}
    output = ["CVEvidence 查核報告", "Run: " + run_id, "Context: " + context_hash,
              "CVE: " + cve_id, "執行狀態: " + text(entry.get("status")),
              "工程判定: " + VERDICTS.get(assessment.get("verdict"), "尚未產生有效判定"),
              "理由: " + text(assessment.get("reason")), "範圍: " + text(assessment.get("scope")),
              "工程初判須人工覆核；不代表實際部署暴露、已被利用或異常已歸因。"]
    output += ["", "結論面向與證據邊界"]
    for dimension in conclusion_dimensions(entry):
        output += [dimension["面向"] + ": " + dimension["本次結論"], dimension["解讀邊界"]]
    for qid, title in QUERIES.items():
        matches = [q for q in rows(entry.get("queries")) if q.get("query_id") == qid]
        query = matches[0] if len(matches) == 1 else {}
        output += ["", qid + " · " + title, "狀態: " + text(query.get("status"))]
        for field in ("missing", "conflicts", "evidence_ids"):
            if query.get(field): output.append(field + ": " + text(query[field]))
    for field in ("conditions", "conflicts", "statement_reviews", "gaps", "next_steps"):
        output += ["", field + ":", text(assessment.get(field))]
    output += ["", "PC 分組（僅呈現，不另推算判定）", text(condition_groups(entry))]
    output += ["", "證據原值（保存紀錄；此匯出沒有重新驗證原文）"]
    for evidence in rows(entry.get("evidence")):
        for field in ("evidence_id", "value", "reason", "witnesses", "excerpts"):
            output.append(field + ": " + text(evidence.get(field)))
    output += ["", "AI 調查（不覆蓋工程判定）"]
    ai = entry.get("ai")
    if not isinstance(ai, dict):
        output.append("尚無 AI 紀錄")
    elif not assessment.get("assessment_id") or ai.get("context_hash") != context_hash or ai.get("cve_id") != cve_id or ai.get("engineering_assessment_id") != assessment.get("assessment_id"):
        output.append("AI_SCOPE_MISMATCH：未匯出不符目前判定的 AI 內容")
    else:
        output += ["模式: " + text(ai.get("mode")), "狀態: " + text(ai.get("status"))]
        if ai.get("mode") == "REPLAY": output.append("舊紀錄播放，本次未呼叫模型。")
        for task in rows(ai.get("tasks")):
            output += ["問題: " + text(task.get("question")), "目的: " + text(task.get("reason")),
                       "狀態: " + text(task.get("status"))]
            if task.get("status") != "COMPLETED":
                output.append("此項未完成或被拒絕，不列為有效調查結果。")
                continue
            for field in ("action", "finding", "citations", "required_files"):
                output.append(field + ": " + text(task.get(field)))
        output.append("引用核對不等於語意已證明；AI 建議仍需覆核。")
    return "\n".join(output) + "\n"


def compare_analyses(parent, child, *, parent_context, child_context, cve_id):
    """Same product/release/build/artifact only; caller checks parent run lineage."""
    before = select_analysis(parent, context_hash=parent_context, cve_id=cve_id)
    after = select_analysis(child, context_hash=child_context, cve_id=cve_id)
    identities = []
    for payload in (parent, child):
        identity = payload.get("input")
        if not isinstance(identity, dict): raise ValueError("Missing product scope")
        artifact = identity.get("primary_artifact") or {}
        fields = [identity.get(k) for k in ("product_id", "release_id", "build_id")]
        fields.append(artifact.get("sha256"))
        if any(not isinstance(v, str) or not v for v in fields): raise ValueError("Incomplete product scope")
        identities.append(fields)
    if identities[0] != identities[1]: raise ValueError("Cannot compare different product builds")
    condition_maps = []
    for entry in (before, after):
        conditions = rows((entry.get("assessment") or {}).get("conditions"))
        mapping = {}
        for condition in conditions:
            key = condition.get("condition_id")
            if not isinstance(key, str) or not key or key in mapping:
                raise ValueError("Invalid or duplicate condition identity")
            mapping[key] = condition
        condition_maps.append(mapping)
    left, right = condition_maps
    changes = []
    for key in sorted(set(left) | set(right)):
        a, b = left.get(key, {}), right.get(key, {})
        if a != b:
            changes.append({"condition_id": key, "before": a or None, "after": b or None})
    return {"cve_id": cve_id, "parent_context": parent_context, "child_context": child_context,
            "before_verdict": (before.get("assessment") or {}).get("verdict"),
            "after_verdict": (after.get("assessment") or {}).get("verdict"),
            "condition_changes": changes,
            "note": "僅呈現保存結果差異；不由差異推論因果或確認 parent run 關係。"}
