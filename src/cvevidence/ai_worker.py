"""Trusted, fixed AI stage. Uploaded files never supply credentials or commands."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from .core_worker import checked_archive
from cvevidence_core.integrity import safe_extract, ingest_package, file_hash
from cvevidence_core.workflow import investigate_after_engineering


def execute(request):
    allowed = {"archive", "archive_sha256", "context_hash", "temporary_root", "engineering_blob",
               "engineering_payload_sha256", "cve_id", "assessment_id", "user_context", "consent"}
    if set(request) != allowed or request["consent"] is not True or os.environ.get("CVEVIDENCE_AI_ENABLED") != "1":
        raise ValueError("AI execution not authorized")
    if not os.environ.get("OPENAI_API_KEY") or not os.environ.get("OPENAI_MODEL"):
        raise ValueError("AI operator configuration missing")
    blob = Path(request["engineering_blob"])
    if blob.is_symlink() or not blob.is_file() or blob.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Invalid engineering blob")
    data = blob.read_bytes()
    if hashlib.sha256(data).hexdigest() != request["engineering_payload_sha256"]:
        raise ValueError("Engineering blob changed")
    saved = json.loads(data)
    entries = saved.get("analyses", [])
    if len(entries) != 1 or entries[0].get("cve_id") != request["cve_id"] or (entries[0].get("assessment") or {}).get("assessment_id") != request["assessment_id"]:
        raise ValueError("AI engineering scope mismatch")
    archive, actual = checked_archive(request["archive"], request["archive_sha256"])
    with tempfile.TemporaryDirectory(prefix="ai-read-", dir=request["temporary_root"]) as temp:
        root = Path(temp) / "package"
        safe_extract(archive, root)
        context = ingest_package(root)
        if context.context_hash != request["context_hash"] or saved.get("archive_sha256") != actual:
            raise ValueError("AI archive context mismatch")
        # This entry re-verifies collection in this process before calling investigate.
        result = investigate_after_engineering(context, saved, request["user_context"], analysis_depth="pc")
        if file_hash(archive) != actual or hashlib.sha256(blob.read_bytes()).hexdigest() != request["engineering_payload_sha256"]:
            raise ValueError("AI inputs changed during execution")
        return result


def main():
    try:
        raw = sys.stdin.read(32001)
        if len(raw) > 32000: raise ValueError("AI request too large")
        result = execute(json.loads(raw))
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0
    except (ValueError, OSError, KeyError, TypeError):
        # Never print exception strings, uploaded content or credentials.
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
