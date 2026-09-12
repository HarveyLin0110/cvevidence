"""Acceptance through real Runner workers; expected outcomes stay outside core.

Run against a fixed candidate checkout or a separately identified preview copy.
No model call, uploaded-program execution, server restart or deployment occurs.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from time import monotonic


CASES = {"rom": "CVE-2014-0160", "cmake": "CVE-2022-37434", "curl": "CVE-2023-38545"}
QUERY_IDS = ["Q1_COMPONENT", "Q2_BUILD", "Q3_IMPLEMENTATION", "Q4_BINDING", "Q5_PATH"]
LAYERS = ["PC1", "PC2", "PC2", "PC2", "PC3"]
NOTE = "產品還有另一個未交付的網路更新入口，會接收 gzip；該入口的程式與編譯資料尚未提供。"


def sha(path):
    value = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def source_inventory(root):
    return {str(p.relative_to(root)): sha(p) for p in sorted((root / "src").rglob("*"))
            if p.is_file() and p.suffix in (".py", ".json") and "__pycache__" not in p.parts}


def main():
    parser = argparse.ArgumentParser(description="第二版 PC 分層、運作補件與 Runner 歷史驗收")
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--data-root", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="新的本機驗收資料夾，不放入 Git")
    parser.add_argument("--candidate-label", required=True, help="固定 commit；未提交快照須明示 PREVIEW")
    args = parser.parse_args()
    source = args.source_root.resolve()
    data = (args.data_root or source).resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(source / "src"))
    from cvevidence.runner import Runner
    from cvevidence.storage import RunStore
    from cvevidence_core.integrity import safe_extract, ingest_package
    from cvevidence_core.supplements import validate_supplement

    started = monotonic()
    report = {"candidate": args.candidate_label, "mode": "REAL_RUNNER_OFFLINE",
              "started_at": datetime.now(timezone.utc).isoformat(),
              "source_files": source_inventory(source), "checks": [], "cases": [], "history": None}
    if not report["source_files"]:
        raise ValueError("指定的程式來源沒有可核對的檔案")

    def check(name, condition):
        report["checks"].append({"name": name, "pass": bool(condition)})

    def analyze(runner, parent):
        child = runner.analyze_offline(parent.run_id)
        if child.status != "COMPLETED":
            raise ValueError("工程未完成：" + child.status + " / " + str(child.error))
        return child, runner.read_engineering(child.run_id)

    def states(entry):
        return {c["condition_id"]: c["state"] for c in entry["assessment"]["conditions"]}

    def summary(run, payload):
        entry = payload["analyses"][0]
        return {"run_id": run.run_id, "parent_run_id": run.parent_run_id,
                "context_hash": payload["context_hash"], "archive_sha256": payload["archive_sha256"],
                "primary_artifact": payload["input"]["primary_artifact"],
                "profile_version": entry["assessment"]["profile_version"],
                "verdict": entry["assessment"]["verdict"], "conditions": states(entry),
                "queries": [{k: q[k] for k in ("query_id", "pc_layer", "status")} for q in entry["queries"]],
                "followup_queries": entry["followup_queries"],
                "runtime_observation": entry["runtime_observation"]}

    catalog = json.loads((data / "data/catalogs/fresh-pc3-runtime-v2.json").read_text())
    entries = {e["package_id"]: e for e in catalog["packages"]}
    check("六個明確配對的第二版輸入", len(entries) == 6)
    for family, cve in CASES.items():
        row = {"family": family, "error": None}
        report["cases"].append(row)
        try:
            initial = entries["pc3_" + family + "_static"]
            extra = entries["supplement_pc3_" + family + "_runtime"]
            paths = [data / e["archive"]["repo_path"] for e in (initial, extra)]
            for entry, path in zip((initial, extra), paths):
                if sha(path) != entry["archive"]["sha256"]:
                    raise ValueError("輸入 archive 與 catalog hash 不符")
            row["inputs"] = [{"package_id": e["package_id"], "sha256": e["archive"]["sha256"]}
                             for e in (initial, extra)]
            check(family + " 補件維持同成品", initial["primary_artifact"] == extra["primary_artifact"])
            check(family + " 補件明確指向原包", extra["base_package_id"] == initial["package_id"])
            # Inspect delivered files, not a label claiming this is runtime-only.
            base_dir, delta_dir = output / family / "initial", output / family / "delta"
            safe_extract(paths[0], base_dir)
            safe_extract(paths[1], delta_dir)
            plan = validate_supplement(ingest_package(base_dir), delta_dir)
            check(family + " 只新增運作材料", plan["can_merge"] and bool(plan["added_files"])
                  and all(r["path"].startswith("runtime/") for r in plan["added_files"]))
            runner = Runner(RunStore(output / family / "runtime"))
            symptom = "本次要核對同成品的實際運作條件；沒有運作材料時請保留未知。"
            intake = runner.start_file(paths[0], cve=cve, symptom=symptom,
                                       archive_sha256=initial["archive"]["sha256"])
            before_run, before = analyze(runner, intake)
            original_blob = runner.store.read_blob(before_run.engineering_payload_sha256)
            original_run = runner.store._run_path(before_run.run_id).read_bytes()
            delta = runner.supplement_file(before_run.run_id, path=paths[1],
                                            archive_sha256=extra["archive"]["sha256"])
            runner = Runner(RunStore(runner.store.root))
            after_run, after = analyze(runner, delta)
            a, b = before["analyses"][0], after["analyses"][0]
            row.update(before=summary(before_run, before), after=summary(after_run, after))
            check(family + " 新 profile 版本", a["assessment"]["profile_version"].endswith("-runtime-v2"))
            check(family + " 缺運作材料保留待查", a["assessment"]["verdict"] == "NEEDS_INVESTIGATION"
                  and states(a)["runtime_observation"] == "UNKNOWN")
            check(family + " 五 Query 重新分層", [q["query_id"] for q in a["queries"]] == QUERY_IDS
                  and [q["pc_layer"] for q in a["queries"]] == LAYERS)
            check(family + " PC2 不因補運作資料改寫", {k: v for k, v in states(a).items() if k != "runtime_observation"}
                  == {k: v for k, v in states(b).items() if k != "runtime_observation"})
            check(family + " 運作原文驗證後才重判", states(b)["runtime_observation"] == "SUPPORTED"
                  and b["assessment"]["verdict"] == "AFFECTED")
            check(family + " 追加 Query 維持身分並增加材料查核", len(b["followup_queries"]) > len(a["followup_queries"])
                  and a["followup_queries"][0]["query_id"] == b["followup_queries"][0]["query_id"]
                  and all(q["status"] == "VERIFIED" for q in b["followup_queries"]))
            check(family + " 新快照與原成品", before["context_hash"] != after["context_hash"]
                  and before["input"]["primary_artifact"] == after["input"]["primary_artifact"])
            check(family + " 原工程與檔案不改寫", runner.read_engineering(before_run.run_id) == before
                  and runner.store.read_blob(before_run.engineering_payload_sha256) == original_blob
                  and runner.store._run_path(before_run.run_id).read_bytes() == original_run)
            check(family + " 重開 Runner 保留原情境", after["discovery"]["symptom"] == symptom)
            check(family + " 不冒稱設備认证或漏洞重現", b["runtime_observation"]["evidence_basis"] == "CONTROLLED_LOCAL_OBSERVATION"
                  and b["runtime_observation"]["provenance_verified"] is False
                  and b["assessment"]["symptom_causation"] == "NOT_ESTABLISHED")

            if family == "cmake":
                note = runner.supplement_file(before_run.run_id, note=NOTE)
                noted_run, noted = analyze(runner, note)
                delta = runner.supplement_file(noted_run.run_id, path=paths[1])
                final_run, final = analyze(runner, delta)
                x, y = (p["analyses"][0]["assessment"] for p in (noted, final))
                carried = y.get("statement_context", [])
                check("新 PC3 補件仍保留未交付入口", y["verdict"] == "NEEDS_INVESTIGATION" and len(carried) == 1
                      and carried[0]["blocks_verdict"] is True
                      and carried[0]["statement_id"] == x["statement_context"][0]["statement_id"]
                      and carried[0]["source_context_hash"] == x["statement_context"][0]["source_context_hash"])
                check("新增範圍文字不更改已驗條件", states(final["analyses"][0]) == states(b))
                report["history"] = {"before_run": noted_run.run_id, "after_run": final_run.run_id,
                                     "verdict": y["verdict"], "statements": carried}
        except Exception as exc:
            row["error"] = {"type": type(exc).__name__, "message": str(exc)}
            check(family + " 流程完整執行", False)
        print(json.dumps(row, ensure_ascii=False), flush=True)
        (output / "progress.json").write_text(json.dumps(report, ensure_ascii=False, indent=2))

    check("驗收期間程式未變動", report["source_files"] == source_inventory(source))
    report.update(finished_at=datetime.now(timezone.utc).isoformat(), elapsed_seconds=round(monotonic() - started, 3))
    report["pass"] = len(report["cases"]) == 3 and report["history"] is not None and all(c["pass"] for c in report["checks"])
    (output / "summary.json").write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps({"pass": report["pass"], "checks": len(report["checks"]),
                      "failed": [c["name"] for c in report["checks"] if not c["pass"]],
                      "summary": str(output / "summary.json")}, ensure_ascii=False), flush=True)
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
