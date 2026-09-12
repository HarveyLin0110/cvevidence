"""Deterministic presentation of saved findings; does not infer a verdict."""
from .query_display import query_ids, query_title, query_description
from .pc_context import openssl_context
QUERY_LABELS = {
    "Q1_COMPONENT": "Q1 元件與版本",
    "Q2_BUILD": "Q2 建置身分",
    "Q3_IMPLEMENTATION": "Q3 受影響實作",
    "Q4_BINDING": "Q4 成品綁定與範圍",
    "Q5_PATH": "Q5 輸入路徑與必要條件",
}
def objects(value):
    return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []

def query_summaries(entry):
    evidence = {}
    for item in objects(entry.get("evidence")):
        evidence.setdefault(item.get("evidence_id"), []).append(item)
    result = []
    for qid in query_ids(entry):
        matches = [q for q in objects(entry.get("queries")) if q.get("query_id") == qid]
        query = matches[0] if len(matches) == 1 else {}
        label = query_title(query, qid)
        status = query.get("status")
        state = {"COMPLETED": "查核已完成", "COMPLETED_WITH_GAPS": "有缺件，尚未查清",
                 "CONFLICT": "存在矛盾，需覆核"}.get(status, "未提供可用結果")
        if len(matches) > 1: state = "結果重複，需覆核"
        findings = []
        for eid in query.get("evidence_ids", []):
            items = evidence.get(eid, [])
            if len(items) == 1 and isinstance(items[0].get("reason"), str) and items[0]["reason"]:
                if items[0]["reason"] not in findings: findings.append(items[0]["reason"])
        missing = query.get("missing") if isinstance(query.get("missing"), list) else []
        conflicts = query.get("conflicts") if isinstance(query.get("conflicts"), list) else []
        if conflicts: state = "存在矛盾，需覆核"
        elif missing: state = "有缺件，尚未查清"
        result.append({"query_id": qid, "label": label, "description": query_description(query), "pc_layer": query.get("pc_layer"), "state": state, "findings": findings,
                       "missing": missing, "conflicts": conflicts})
    return result

def conclusion(entry):
    assessment = entry.get("assessment") or {}
    verdict = assessment.get("verdict")
    conclusions = {
        "AFFECTED": "本次成品被判定受此 CVE 影響。請優先安排修補或緩解，並由工程師覆核。",
        "NOT_AFFECTED": "本次成品被判定不受此 CVE 影響。此結論只適用目前提交的成品、建置與查核範圍。",
        "NEEDS_INVESTIGATION": "目前還不能確認本次成品是否受此 CVE 影響；需補齊或釐清關鍵證據後再判定。",
    }
    conditions = objects(assessment.get("conditions"))
    relevant = [c for c in conditions if c.get("state") == ("BLOCKED" if verdict == "NOT_AFFECTED" else "UNKNOWN")]
    titles = [c["title"] for c in relevant if isinstance(c.get("title"), str)]
    detail = ""
    if verdict == "NOT_AFFECTED" and titles:
        detail = "判定依據中的阻斷條件：" + "、".join(titles) + "。"
    elif verdict == "NEEDS_INVESTIGATION" and titles:
        detail = "仍待確認：" + "、".join(titles) + "。"
    return {"text": conclusions.get(verdict, "尚未提供有效判定，不能將此結果視為安全。"),
            "reason": assessment.get("reason"), "detail": detail}

def conclusion_dimensions(entry):
    """Current engineering schema has no separately verified reproduction/deployment verdict."""
    return [
        {"面向": "工程適用性", "本次結論": conclusion(entry)["text"],
         "解讀邊界": "依核心對本次成品、建置與 CVE 的工程判定；不是實際攻擊成功紀錄。"},
        {"面向": "漏洞重現", "本次結論": "尚無獨立覆核的重現結論",
         "解讀邊界": "此報告未提供專用的重現驗收結果；不等於已重現，也不等於重現失敗。正常測試不能代替漏洞重現。"},
        {"面向": "部署暴露與實際利用", "本次結論": "尚無獨立覆核的部署／利用結論",
         "解讀邊界": "程式路徑可達不等於實際部署可從外部存取；需另外核對配置、網路路徑、權限與觀測證據。"},
    ]

def condition_interpretation(condition):
    state = condition.get("state")
    label = {"SUPPORTED": "支持此項工程條件", "BLOCKED": "此項工程條件有阻斷證據",
             "UNKNOWN": "此項條件仍需確認"}.get(state, "此項條件仍需確認")
    boundary = "此狀態只描述這一項主張，不能單獨代表整體受影響或安全。"
    if condition.get("condition_id") == "trigger_prerequisites":
        boundary = "此列只描述核心已審查的必要使用條件；不代表已實際觸發漏洞。重現與部署暴露須另行覆核。"
    elif condition.get("condition_id") == "entry_reachable":
        boundary = "此列描述交付程式的路徑；實際部署的外部可達性與權限仍須另行覆核。"
    return label, boundary


def condition_groups(entry):
    """Validate a complete, non-overlapping presentation mapping from core."""
    mapping = entry.get("condition_groups")
    if not isinstance(mapping, dict) or mapping.get("cve_id") != entry.get("cve_id") or mapping.get("grouping_only") is not True:
        return []
    conditions = objects((entry.get("assessment") or {}).get("conditions"))
    by_id = {c.get("condition_id"): c for c in conditions}
    if len(by_id) != len(conditions): return []
    groups = [{"group_id": "共用前提", "title": "建置、綁定與範圍", "condition_ids": mapping.get("shared_prerequisite_ids", [])}, *objects(mapping.get("groups"))]
    result, seen = [], set()
    for group in groups:
        ids = group.get("condition_ids")
        if not isinstance(ids, list) or not ids or any(not isinstance(cid, str) or cid not in by_id or cid in seen for cid in ids):
            return []
        if len(set(ids)) != len(ids): return []
        seen.update(ids)
        result.append({**group, "conditions": [by_id[cid] for cid in ids]})
    return result if seen == set(by_id) else []


def condition_finding(entry, condition):
    """Display only uniquely linked saved evidence; never search or re-assess."""
    assessment = entry.get("assessment") or {}
    eid_map = {}
    for row in objects(entry.get("evidence")):
        if isinstance(row.get("evidence_id"), str): eid_map.setdefault(row["evidence_id"], []).append(row)
    condition_ids = condition.get("evidence_ids")
    records = [eid_map[eid][0] for eid in condition_ids
               if isinstance(eid, str) and len(eid_map.get(eid, [])) == 1
               and eid_map[eid][0].get("fact_key") == condition.get("condition_id")] if isinstance(condition_ids, list) else []
    title = str(condition.get("title") or condition.get("condition_id") or "未命名條件")
    state = condition.get("state")
    headline = ("已核對：" if state == "SUPPORTED" else "已核對阻斷證據：" if state == "BLOCKED" else "尚未確認：") + title
    if condition.get("condition_id") == "component" and state == "SUPPORTED":
        values = [r.get("value") for r in records if isinstance(r.get("value"), dict)]
        if len(values) == 1 and values[0].get("confirmed") is True:
            name, version = values[0].get("name"), values[0].get("version")
            if isinstance(name, str) and isinstance(version, str):
                headline = "已辨識元件：" + name + " " + version
    elif condition.get("condition_id") == "vulnerable_implementation" and state == "SUPPORTED":
        headline = "已找到受影響實作，尚無有效排除證據"
    elif condition.get("condition_id") == "runtime_observation" and state == "SUPPORTED":
        headline = "已核對同一成品的正常運作紀錄"
    elif condition.get("condition_id") in ("entry_reachable", "trigger_prerequisites") and state == "SUPPORTED":
        if len(records) == 1 and isinstance(records[0].get("reason"), str):
            headline = records[0]["reason"]
    locations, used = [], set()
    for record in records:
        witnesses = {}
        for witness in objects(record.get("witnesses")):
            if isinstance(witness.get("source_id"), str): witnesses.setdefault(witness["source_id"], []).append(witness)
        for excerpt in objects(record.get("excerpts")):
            if not isinstance(excerpt.get("source_id"), str): continue
            matches = witnesses.get(excerpt.get("source_id"), [])
            first, last = excerpt.get("start_line"), excerpt.get("end_line")
            if (len(matches) != 1 or not assessment.get("context_hash")
                    or excerpt.get("context_hash") != assessment.get("context_hash")
                    or not isinstance(excerpt.get("file_sha256"), str) or len(excerpt["file_sha256"]) != 64
                    or excerpt.get("file_sha256") != matches[0].get("sha256")
                    or type(first) is not int or type(last) is not int or not 1 <= first <= last
                    or not isinstance(excerpt.get("text"), str) or not isinstance(matches[0].get("path"), str)):
                continue
            path = matches[0]["path"]
            key = (excerpt["source_id"], first, last)
            if key in used: continue
            used.add(key)
            locations.append({"path": path, "source_id": excerpt["source_id"],
                              "label": path + " · 第 " + str(first) + "–" + str(last) + " 行",
                              "excerpt": excerpt["text"], "excerpt_id": excerpt.get("excerpt_id"),
                              "file_sha256": excerpt["file_sha256"]})
        excerpt_sources = {loc["source_id"] for loc in locations}
        for sid, matches in witnesses.items():
            if len(matches) != 1 or sid in excerpt_sources or (sid, None, None) in used:
                continue
            witness = matches[0]
            if not isinstance(witness.get("path"), str): continue
            used.add((sid, None, None))
            locations.append({"path": witness["path"], "source_id": sid, "label": witness["path"],
                              "excerpt": None, "excerpt_id": None, "file_sha256": witness.get("sha256")})
    missing, conflicts = [], []
    query_ids = {r.get("query_id") for r in records}
    for query in objects(entry.get("queries")):
        if query.get("query_id") not in query_ids: continue
        for key, target in (("missing", missing), ("conflicts", conflicts)):
            for value in query.get(key, []) if isinstance(query.get(key), list) else []:
                if isinstance(value, str) and value not in target: target.append(value)
    return {"condition_id": condition.get("condition_id"), "state": state, "headline": headline,
            "explanation": str(condition.get("explanation") or "尚無保存說明"),
            "locations": locations, "missing": missing, "conflicts": conflicts,
            "evidence_ids": [r["evidence_id"] for r in records]}


def pc_summaries(entry):
    """Combine saved condition explanations without generating a PC verdict."""
    summaries = []
    affected = (entry.get("assessment") or {}).get("verdict") == "AFFECTED"
    for group in condition_groups(entry):
        shared = group["group_id"] == "共用前提"
        states = [c.get("state") for c in group["conditions"]]
        highlight = affected and not shared and all(s == "SUPPORTED" for s in states)
        tone = "affected" if highlight else "pending" if any(s not in ("SUPPORTED", "BLOCKED") for s in states) else "neutral"
        label = "受影響判定的支持條件" if highlight else "含待確認條件" if tone == "pending" else "含阻斷證據" if "BLOCKED" in states else "條件有證據支持"
        context = openssl_context(entry, group['group_id'])
        paragraphs = [context] if context else []
        findings = []
        for condition in group["conditions"]:
            finding = condition_finding(entry, condition)
            findings.append(finding)
            title = str(condition.get("title") or condition.get("condition_id") or "未命名條件")
            explanation = str(condition.get("explanation") or "尚無保存說明")
            paragraphs.append(title + "（" + condition_interpretation(condition)[0] + "）：" + explanation)
            paragraphs.append(finding["headline"])
            if finding["locations"]:
                paragraphs.append("來源位置：" + "；".join(loc["label"] for loc in finding["locations"][:3]))
            paragraphs.extend("尚缺：" + item for item in finding["missing"][:3])
            paragraphs.extend("矛盾：" + item for item in finding["conflicts"][:3])
        summaries.append({**group, "shared": shared, "tone": tone, "label": label,
                          "summary": "\n\n".join(paragraphs), "findings": findings,
                          "context": context})
    return summaries
