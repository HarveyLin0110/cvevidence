"""Operator-owned AI configuration; public views never contain credentials."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re

PROVIDERS = ("openai_api", "codex_cli")
EFFORTS = {"none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra"}
SETTING_KEYS = {
    "OPENAI_API_KEY", "OPENAI_MODEL", "OPENAI_REASONING_EFFORT",
    "CVEVIDENCE_AI_ENABLED", "CVEVIDENCE_AI_PROVIDERS", "CVEVIDENCE_AI_DEFAULT_PROVIDER",
    "CVEVIDENCE_AI_AUTH_REVISION", "CVEVIDENCE_CODEX_BIN", "CVEVIDENCE_CODEX_HOME",
    "CVEVIDENCE_CODEX_MODEL", "CVEVIDENCE_CODEX_REASONING_EFFORT",
}


def operator_settings():
    values = {}
    filename = os.environ.get("CVEVIDENCE_AI_ENV_FILE")
    if filename:
        data = Path(filename).read_text(encoding="utf-8")
        if len(data) > 65536:
            raise ValueError("Operator configuration too large")
        for raw in data.splitlines():
            line = raw.strip().removeprefix("export ").strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip() in SETTING_KEYS:
                values[key.strip()] = value.strip().strip("\"'")
    for key in SETTING_KEYS:
        if key in os.environ:
            values[key] = os.environ[key]
    return values


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def provider_configuration(provider):
    if provider not in PROVIDERS:
        raise ValueError("Unknown AI provider")
    invalid_file = False
    try:
        settings = operator_settings()
    except (OSError, ValueError, UnicodeError):
        settings, invalid_file = {}, True
    enabled = {part.strip() for part in settings.get("CVEVIDENCE_AI_PROVIDERS", "openai_api").split(",")}
    prefix = "OPENAI" if provider == "openai_api" else "CVEVIDENCE_CODEX"
    model = settings.get(prefix + "_MODEL", "")
    effort = settings.get(prefix + "_REASONING_EFFORT", "medium")
    private = {
        "provider": provider, "model": model, "reasoning_effort": effort,
        "auth_revision": settings.get("CVEVIDENCE_AI_AUTH_REVISION", "1"),
    }
    public = {
        "provider": provider, "configured": False, "reason_code": None,
        "model": model if re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", model) else None,
        "reasoning_effort": effort if effort in EFFORTS else None,
        "auth_type": "api_key" if provider == "openai_api" else "chatgpt",
        "billing_label": "後端 API 帳號，依 API 用量計費" if provider == "openai_api" else "後端登入的 ChatGPT 帳號，使用 Codex 額度",
        "version": None, "mode": "LIVE",
    }
    if provider == "openai_api":
        private.update(OPENAI_API_KEY=settings.get("OPENAI_API_KEY", ""),
                       OPENAI_MODEL=model, OPENAI_REASONING_EFFORT=effort)
    else:
        private.update(bin=settings.get("CVEVIDENCE_CODEX_BIN", "codex"),
                       codex_home=settings.get("CVEVIDENCE_CODEX_HOME", ""))
    if invalid_file:
        reason = "CONFIG_UNREADABLE"
    elif os.name != "posix":
        reason = "LINUX_RUNTIME_REQUIRED"
    elif settings.get("CVEVIDENCE_AI_ENABLED") != "1":
        reason = "AI_DISABLED"
    elif enabled - set(PROVIDERS):
        reason = "PROVIDER_CONFIG_INVALID"
    elif provider not in enabled:
        reason = "PROVIDER_DISABLED"
    elif public["model"] is None or public["reasoning_effort"] is None:
        reason = "MODEL_CONFIG_REQUIRED"
    elif provider == "openai_api":
        reason = None if private["OPENAI_API_KEY"] else "API_KEY_REQUIRED"
    else:
        try:
            from cvevidence_core.codex_provider import codex_readiness
            readiness = codex_readiness(private)
            reason = readiness.get("reason_code") if not readiness.get("configured") else None
            if not readiness.get("configured") and not reason:
                reason = "CODEX_CONFIG_REQUIRED"
            public["version"] = readiness.get("version")
            if readiness.get("auth_type") != "chatgpt":
                reason = "CHATGPT_LOGIN_REQUIRED"
            private["auth_identity"] = readiness.get("auth_identity")
        except ImportError:
            reason = "CODEX_ADAPTER_UNAVAILABLE"
        except (OSError, ValueError, RuntimeError):
            reason = "CODEX_CONFIG_REQUIRED"
    public.update(configured=reason is None, reason_code=reason)
    # Only a digest leaves this module. Credential changes invalidate submitted consent.
    public["config_id"] = _digest({"private": private, "auth_type": public["auth_type"],
                                   "version": public["version"], "enabled": sorted(enabled),
                                   "ai_enabled": settings.get("CVEVIDENCE_AI_ENABLED")})
    return private, public


def public_configuration():
    try:
        default = operator_settings().get("CVEVIDENCE_AI_DEFAULT_PROVIDER", "openai_api")
    except (OSError, ValueError, UnicodeError):
        default = "openai_api"
    providers = {name: provider_configuration(name)[1] for name in PROVIDERS}
    # Preserve old single-provider callers without silently changing their route.
    legacy = providers["openai_api"]
    return {**legacy, "provider": "OpenAI", "default_provider": default, "providers": providers}
