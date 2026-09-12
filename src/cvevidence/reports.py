"""Text reports reflect saved data, not fixture expectations."""
import hashlib
import io
import zipfile
from .adapters import CoreAdapter

def report(run):
    p=run.input_package
    lines=["CVEvidence — 工程查核紀錄（待工程師覆核）", "Run: "+run.run_id,
        "Parent: "+(run.parent_run_id or "—"), "CVE: "+run.cve_id,
        "Mode: "+run.mode, "Execution: "+run.status]
    if p:
        lines += ["Product: "+p.product_id, "Release: "+p.release_id,
            "Declared build: "+p.declared_build_id, "Archive SHA256: "+p.archive_sha256]
    lines += ["Assessment: "+(run.assessment.verdict if run.assessment else "NOT_ASSESSED — 尚未完成漏洞判定")]
    if run.error: lines += ["Error: "+run.error.code+" — "+run.error.message]
    lines += ["Engineering: "+run.engineering_status, "AI: "+run.ai_status]
    if p and p.context_hash:
        lines += ["Context hash: "+p.context_hash]
    lines += ["", "Sources (hash consistency only; not engineering facts):"]
    lines += [f"{s.source_id} | {s.path} | {s.sha256}" for s in run.sources]
    lines += ["", "Evidence (legacy records / verified facts only when a verifier is connected):"]
    lines += [f"{e.evidence_id} | {e.path} | {e.sha256}" for e in run.evidence]
    lines += ["", "Missing:"] + (run.missing or ["No missing manifest entries; this does not establish complete CVE evidence."])
    if run.supplement:
        lines += ["", "Unverified supplement note:", run.supplement.note or "—"]
    lines += ["", "Limitations:"] + run.limitations
    return "\n".join(lines)+"\n"

def compare(parent, child):
    if child.parent_run_id != parent.run_id:
        raise ValueError("runs are not directly parent-linked")
    if child.error:
        return {"status":"REJECTED", "error":child.error.code,
                "added":[], "removed":[], "changed":[], "resolved_missing":[]}
    old={e.path:e.sha256 for e in (parent.sources or parent.evidence)}
    new={e.path:e.sha256 for e in (child.sources or child.evidence)}
    return {"status":"COMPARED",
        "added":sorted(new.keys()-old.keys()), "removed":sorted(old.keys()-new.keys()),
        "changed":sorted(p for p in old.keys() & new.keys() if old[p]!=new[p]),
        "resolved_missing":sorted(set(parent.missing)-set(child.missing))}

def excerpt(store, run_id, evidence_id):
    run=store.read(run_id)
    record=next((e for e in run.evidence if e.evidence_id==evidence_id), None)
    if record is None or run.input_package is None:
        raise ValueError("evidence not in this run")
    blob=store.read_blob(run.input_package.archive_sha256)
    content=CoreAdapter().read_excerpt(blob,record)
    if len(content)!=record.size or hashlib.sha256(content).hexdigest()!=record.sha256:
        raise ValueError("evidence integrity error")
    if b"\x00" in content[:4096]:
        return "[Binary evidence; text preview unavailable]"
    return content[:16000].decode("utf-8",errors="replace") + ("\n[Preview truncated]" if len(content)>16000 else "")
