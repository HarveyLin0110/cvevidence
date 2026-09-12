"""Validate two independent initial uploads; stop flow 2 at AI guidance."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from time import monotonic


CONTEXT = "產品的更新檔匯入偶爾失敗。我們想確認這個成品是否受 CVE-2022-37434 影響；目前先提供拿得到的工程資料。若資訊不足，請具體說明缺什麼、為何需要，以及由誰在哪裡如何取得。這次只展示調查與補件指引，不在現場補件或重現漏洞。"


def main():
    parser = argparse.ArgumentParser(description="驗收兩個獨立 Demo 輸入；第二版在補件指引結束")
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--data-root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--live", action="store_true", help="使用操作者已設定的 OpenAI API；會產生費用")
    args = parser.parse_args()
    source = args.source_root.resolve()
    data = (args.data_root or source).resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(source / "src"))
    from cvevidence.runner import Runner
    from cvevidence.storage import RunStore
    from cvevidence.core_service import catalog_entries

    def inventory():
        return {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted((source / "src").rglob("*"))
                if p.is_file() and p.suffix in (".py", ".json") and "__pycache__" not in p.parts}

    started = monotonic()
    report = {"started_at": datetime.now(timezone.utc).isoformat(),
              "code_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip(),
              "source_files": inventory(), "checks": [], "cases": [], "ai": None,
              "scope": "真實 Runner、本機驗收；第二版不呼叫補件或重新判定，不代表已部署網站。"}

    def save():
        (output / "summary.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")

    def check(name, value):
        report["checks"].append({"name": name, "pass": bool(value)})

    entries = json.loads((data / "data/catalogs/fresh-demo-two-flows-v2.json").read_text())["packages"]
    available = [e for e in catalog_entries(data) if e["dataset"] == "fresh-demo-two-flows-v2"]
    check("網頁樣品索引可取得兩個初始包", len(available) == 2 and all(e["available"] and e["kind"] == "initial" for e in available))
    for number, entry in enumerate(entries, 1):
        path = data / entry["archive"]["repo_path"]
        check(f"Demo {number} 輸入 hash", hashlib.sha256(path.read_bytes()).hexdigest() == entry["archive"]["sha256"])
        runner = Runner(RunStore(output / str(number) / "runtime"))
        intake = runner.start_file(path, cve="CVE-2022-37434", symptom=CONTEXT,
                                   archive_sha256=entry["archive"]["sha256"])
        run = runner.analyze_offline(intake.run_id)
        check(f"Demo {number} 工程完成", run.status == "COMPLETED")
        payload = runner.read_engineering(run.run_id)
        analysis = payload["analyses"][0]
        states = {c["condition_id"]: c["state"] for c in analysis["assessment"]["conditions"]}
        report["cases"].append({"flow": number, "archive_sha256": entry["archive"]["sha256"],
            "intake_run_id": intake.run_id, "engineering_run_id": run.run_id,
            "primary_artifact": payload["input"]["primary_artifact"], "context_hash": payload["context_hash"],
            "verdict": analysis["assessment"]["verdict"], "conditions": states,
            "followup_queries": analysis["followup_queries"]})
        check(f"Demo {number} 實際判定", analysis["assessment"]["verdict"] == ("AFFECTED" if number == 1 else "NEEDS_INVESTIGATION"))
        check(f"Demo {number} PC3", states["runtime_observation"] == ("SUPPORTED" if number == 1 else "UNKNOWN"))
        check(f"Demo {number} 第二版 profile", analysis["assessment"]["profile_version"].endswith("-runtime-v2"))
        save()
        print(json.dumps({"flow": number, "verdict": analysis["assessment"]["verdict"]}), flush=True)
        if number == 2 and args.live:
            print(json.dumps({"live_configuration": runner.ai_configuration()}), flush=True)
            attempt = runner.investigate_ai(run.run_id, user_context=CONTEXT, consent=True, timeout=180)
            (output / "live-record.json").write_text(json.dumps(attempt, ensure_ascii=False, indent=2) + "\n")
            ai = (((attempt.get("result") or {}).get("analyses") or [{}])[0].get("ai") or {})
            report["ai"] = {"ai_id": attempt["request"]["ai_id"], "status": attempt["status"],
                "mode": ai.get("mode"), "model": ai.get("model"), "reasoning_effort": ai.get("reasoning_effort"),
                "record_hash": ai.get("record_hash"), "elapsed_seconds": ai.get("elapsed_seconds"),
                "calls": ai.get("calls", []), "tasks": ai.get("tasks", [])}
            check("第二版 Live 真實呼叫並停在詢問使用者", attempt["status"] == "NEEDS_USER_INPUT"
                  and ai.get("mode") == "LIVE" and bool(ai.get("calls")))
            check("AI 後原工程不變", runner.read_engineering(run.run_id) == payload)
            reopened = Runner(RunStore(runner.store.root))
            check("重開 Runner 可讀原 AI", reopened.read_ai(attempt["request"]["ai_id"]) == attempt)
            save()
    check("兩個版本是同一個今日成品", len(report["cases"]) == 2 and report["cases"][0]["primary_artifact"] == report["cases"][1]["primary_artifact"])
    check("驗收期間程式來源不變", report["source_files"] == inventory())
    report.update(elapsed_seconds=round(monotonic() - started, 3),
                  passed=sum(c["pass"] for c in report["checks"]), total=len(report["checks"]))
    save()
    print(json.dumps({k: report[k] for k in ("passed", "total", "elapsed_seconds")}), flush=True)
    if report["passed"] != report["total"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
