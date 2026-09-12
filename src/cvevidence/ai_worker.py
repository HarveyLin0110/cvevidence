"""Trusted, fixed AI stage. Uploaded files never supply credentials or commands."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from time import monotonic
from .core_worker import checked_archive
from cvevidence_core.integrity import safe_extract, ingest_package, file_hash
from cvevidence_core.workflow import investigate_after_engineering
from cvevidence_core.providers import ProviderError


def execute(request):
    allowed = {"archive", "archive_sha256", "context_hash", "temporary_root", "engineering_blob",
               "engineering_payload_sha256", "cve_id", "assessment_id", "user_context", "consent"}
    provider_name = request.get("provider")
    if provider_name is not None:
        allowed |= {"provider", "auth_type", "config_id", "provider_config", "deadline_monotonic"}
    if set(request) != allowed or request["consent"] is not True or os.environ.get("CVEVIDENCE_AI_ENABLED") != "1":
        raise ValueError("AI execution not authorized")
    if provider_name not in (None, "openai_api", "codex_cli"):
        raise ValueError("Unknown provider")
    if provider_name != "codex_cli" and (not os.environ.get("OPENAI_API_KEY") or not os.environ.get("OPENAI_MODEL")):
        raise ValueError("AI operator configuration missing")
    provider = None
    if provider_name is not None:
        if request["auth_type"] != ("chatgpt" if provider_name == "codex_cli" else "api_key"):
            raise ValueError("Provider authentication mismatch")
        config = request["provider_config"]
        if not isinstance(config, dict) or set(config) - {"bin", "model", "reasoning_effort", "codex_home", "auth_revision", "auth_identity"}:
            raise ValueError("Invalid provider configuration")
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
        options = {}
        if provider_name is not None:
            remaining = request["deadline_monotonic"] - monotonic()
            if not 0 < remaining <= 300:
                return {"worker_error": {"status": "TIMED_OUT", "code": "AI_DEADLINE_EXCEEDED"}}
            if provider_name == "openai_api":
                from cvevidence_core.providers import OpenAIAdapter
                provider = OpenAIAdapter({key: os.environ[key] for key in
                    ("OPENAI_API_KEY", "OPENAI_MODEL", "OPENAI_REASONING_EFFORT") if key in os.environ})
            else:
                from cvevidence_core.codex_provider import CodexCLIAdapter
                provider = CodexCLIAdapter(config)
            options = {"provider": provider, "timeout_seconds": remaining}
        try:
            result = investigate_after_engineering(context, saved, request["user_context"], analysis_depth="pc", **options)
        finally:
            if provider is not None:
                provider.close()
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
    except ProviderError as exc:
        print(json.dumps({"worker_error": {"status": exc.status, "code": exc.code}}))
        return 0
    except (ValueError, OSError, KeyError, TypeError):
        # Never print exception strings, uploaded content or credentials.
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
