"""Explicit consent, immutable attempts and bounded trusted AI subprocesses."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
from time import monotonic
from uuid import uuid4
from .ai_store import AIRequest, AIOutcome, AIStore, validate_ai_payload
from .engineering import read_engineering


def now():
    return datetime.now(timezone.utc).isoformat()


def operator_config():
    from cvevidence_core.ai import settings
    # Only operator process configuration may name this file; there is no UI/API path parameter.
    try: config = settings(env_file=os.environ.get("CVEVIDENCE_AI_ENV_FILE"))
    except (ValueError, OSError): config = {}
    model = config.get("OPENAI_MODEL", "")
    valid_model = bool(re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", model))
    effort = config.get("OPENAI_REASONING_EFFORT", "medium")
    valid_effort = effort in ("none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra")
    config["OPENAI_REASONING_EFFORT"] = effort
    ready = os.name == "posix" and os.environ.get("CVEVIDENCE_AI_ENABLED") == "1" and valid_model and valid_effort and bool(config.get("OPENAI_API_KEY"))
    return config, {"configured": bool(ready), "model": model if valid_model else None,
                    "reasoning_effort": effort if valid_effort else None, "provider": "OpenAI", "mode": "LIVE"}


class AIService:
    def __init__(self, store):
        self.store = store
        self.records = AIStore(store)

    def invoke(self, request, user_context, config, timeout):
        if timeout <= 0: raise subprocess.TimeoutExpired("AI stage", timeout)
        parent = self.store.read(request.parent_run_id)
        temp = self.store.root / "ai-temporary"
        if temp.is_symlink(): raise ValueError("Invalid AI temporary root")
        temp.mkdir(exist_ok=True, mode=0o700)
        payload = {"archive": str(self.store.root / "blobs" / parent.input_package.archive_sha256),
                   "archive_sha256": parent.input_package.archive_sha256,
                   "context_hash": request.context_hash, "temporary_root": str(temp),
                   "engineering_blob": str(self.store.root / "blobs" / request.engineering_payload_sha256),
                   "engineering_payload_sha256": request.engineering_payload_sha256,
                   "cve_id": request.cve_id, "assessment_id": request.assessment_id,
                   "user_context": user_context, "consent": request.consent}
        env = {key: os.environ[key] for key in ("PATH", "LANG") if key in os.environ}
        env.update({key: config[key] for key in ("OPENAI_API_KEY", "OPENAI_MODEL", "OPENAI_REASONING_EFFORT") if config.get(key)})
        env.update(PYTHONPATH=str(Path(__file__).resolve().parents[1]), CVEVIDENCE_AI_ENABLED="1")
        with tempfile.TemporaryFile(dir=temp) as output:
            process = subprocess.Popen([sys.executable, "-m", "cvevidence.ai_worker"], stdin=subprocess.PIPE,
                                       stdout=output, stderr=subprocess.DEVNULL, env=env, start_new_session=True)
            try:
                process.communicate(json.dumps(payload, ensure_ascii=False).encode(), timeout=timeout)
            except BaseException:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                process.wait()
                raise
            if process.returncode: raise ValueError("AI worker rejected input or failed")
            if output.tell() > 16 * 1024 * 1024: raise ValueError("AI output limit exceeded")
            output.seek(0)
            return json.loads(output.read())

    def start(self, parent_run_id, *, user_context="", consent=False, ai_id=None, timeout=180):
        started = monotonic()
        if type(consent) is not bool or not isinstance(user_context, str) or len(user_context) > 4000:
            raise ValueError("Invalid AI user input")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 300:
            raise ValueError("Invalid AI deadline")
        parent = self.store.read(parent_run_id)
        engineering = read_engineering(self.store, parent_run_id)
        assessment = engineering["analyses"][0].get("assessment")
        if not assessment or parent.engineering_status != "COMPLETED":
            raise ValueError("A completed supported engineering assessment is required")
        config, public = operator_config()
        request = AIRequest(ai_id=ai_id or str(uuid4()), parent_run_id=parent_run_id,
            engineering_payload_sha256=parent.engineering_payload_sha256,
            context_hash=parent.input_package.context_hash, cve_id=parent.cve_id,
            assessment_id=assessment["assessment_id"], consent=consent,
            context_text_sha256=hashlib.sha256(user_context.encode()).hexdigest(),
            model=public["model"], reasoning_effort=public["reasoning_effort"], created_at=now(), timeout_seconds=float(timeout))
        try:
            self.records.begin(request)
        except FileExistsError:
            previous = self.records.read(request.ai_id)
            expected = request.model_dump(exclude={"created_at"})
            existing = {k: v for k, v in previous["request"].items() if k != "created_at"}
            if existing != expected: raise ValueError("AI attempt ID already belongs to different input")
            if previous["outcome"] is None: raise RuntimeError("AI attempt running or interrupted; no automatic retry")
            return previous
        outcome = AIOutcome(ai_id=request.ai_id, status="FAILED", completed_at=now())
        if not consent:
            outcome.status = "CONSENT_REQUIRED"
        elif not public["configured"]:
            outcome.status = "CONFIG_REQUIRED"
        else:
            try:
                payload = self.invoke(request, user_context, config, float(timeout) - (monotonic() - started))
                outcome.status = validate_ai_payload(payload, request)
                outcome.payload_sha256 = self.store.put_blob(json.dumps(payload, ensure_ascii=False, sort_keys=True, allow_nan=False).encode())
            except subprocess.TimeoutExpired:
                outcome.status = "TIMED_OUT"
                outcome.error_code = "AI_DEADLINE_EXCEEDED"
            except (ValueError, OSError, RuntimeError, KeyError, TypeError):
                outcome.status = "FAILED"
                outcome.error_code = "AI_EXECUTION_OR_INTEGRITY_ERROR"
        outcome.completed_at = now()
        self.records.finish(outcome)
        return self.records.read(request.ai_id)
