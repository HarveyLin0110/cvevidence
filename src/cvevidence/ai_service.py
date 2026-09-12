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
from .ai_store import AIRequest, AIRequestV2, AIOutcome, AIStore, validate_ai_payload
from .engineering import read_engineering
from .ai_config import provider_configuration
from .ai_process import run_worker, WorkerLimitError


class AIExecutionError(RuntimeError):
    def __init__(self, status, code):
        super().__init__(code)
        self.status, self.code = status, code


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
        if isinstance(request, AIRequestV2):
            # User input cannot choose commands, provider modules or credential paths.
            public_keys = ("bin", "model", "reasoning_effort", "codex_home", "auth_revision", "auth_identity")
            payload.update(provider=request.provider, auth_type=request.auth_type,
                           config_id=request.config_id,
                           provider_config={key: config[key] for key in public_keys if key in config},
                           deadline_monotonic=monotonic() + timeout)
            if request.provider == "codex_cli":
                env = {key: value for key, value in env.items() if not key.startswith("OPENAI_")}
                env["HOME"] = str(Path.home())
            code, raw = run_worker([sys.executable, "-m", "cvevidence.ai_worker"],
                json.dumps(payload, ensure_ascii=False, allow_nan=False).encode(), env=env, timeout=timeout)
            if code:
                raise AIExecutionError("FAILED", "AI_WORKER_FAILED")
            result = json.loads(raw)
            if isinstance(result, dict) and set(result) == {"worker_error"}:
                error = result["worker_error"]
                raise AIExecutionError(error["status"], error["code"])
            return result
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

    def start(self, parent_run_id, *, user_context="", consent=False, ai_id=None, timeout=180,
              provider=None, config_id=None):
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
        if provider is None:
            if config_id is not None:
                raise ValueError("Provider required with configuration identity")
            config, public = operator_config()
            request_type, identity = AIRequest, {}
        else:
            config, public = provider_configuration(provider)
            if not isinstance(config_id, str) or not re.fullmatch(r"[a-f0-9]{64}", config_id):
                raise ValueError("Current provider configuration identity required")
            request_type = AIRequestV2
            identity = {"provider": provider, "auth_type": public["auth_type"], "config_id": config_id}
        request = request_type(ai_id=ai_id or str(uuid4()), parent_run_id=parent_run_id,
            engineering_payload_sha256=parent.engineering_payload_sha256,
            context_hash=parent.input_package.context_hash, cve_id=parent.cve_id,
            assessment_id=assessment["assessment_id"], consent=consent,
            context_text_sha256=hashlib.sha256(user_context.encode()).hexdigest(),
            model=public["model"], reasoning_effort=public["reasoning_effort"], created_at=now(), timeout_seconds=float(timeout),
            **identity)
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
        elif provider is not None and config_id != public["config_id"]:
            outcome.status = "CONSENT_REQUIRED"
            outcome.error_code = "PROVIDER_CONFIGURATION_CHANGED"
        elif not public["configured"]:
            outcome.status = "CONFIG_REQUIRED"
            outcome.error_code = public.get("reason_code")
        else:
            try:
                payload = self.invoke(request, user_context, config, float(timeout) - (monotonic() - started))
                outcome.status = validate_ai_payload(payload, request)
                outcome.payload_sha256 = self.store.put_blob(json.dumps(payload, ensure_ascii=False, sort_keys=True, allow_nan=False).encode())
            except subprocess.TimeoutExpired:
                outcome.status = "TIMED_OUT"
                outcome.error_code = "AI_DEADLINE_EXCEEDED"
            except WorkerLimitError:
                outcome.status = "BUDGET_EXHAUSTED"
                outcome.error_code = "AI_IO_LIMIT_EXCEEDED"
            except AIExecutionError as exc:
                # Reject unknown worker fields; errors are codes, never uploaded text.
                allowed = {"CONFIG_REQUIRED", "FAILED", "CONNECTION_ERROR", "API_ERROR", "TIMED_OUT",
                           "BUDGET_EXHAUSTED", "INVALID_MODEL_OUTPUT", "INPUT_CHANGED_OR_INVALID"}
                outcome.status = exc.status if exc.status in allowed else "FAILED"
                outcome.error_code = exc.code if isinstance(exc.code, str) and re.fullmatch(r"[A-Z0-9_]{1,100}", exc.code) else "AI_WORKER_FAILED"
            except (ValueError, OSError, RuntimeError, KeyError, TypeError):
                outcome.status = "FAILED"
                outcome.error_code = "AI_EXECUTION_OR_INTEGRITY_ERROR"
        outcome.completed_at = now()
        self.records.finish(outcome)
        return self.records.read(request.ai_id)
