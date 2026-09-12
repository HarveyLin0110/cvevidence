"""Safe, read-only labels for validated AI records and public configuration.

These helpers do not validate receipts or infer provider identity from settings.
They never enrich or rewrite a saved payload (including its record hash).
"""
import json

PROVIDERS = {"openai_api": "OpenAI API", "codex_cli": "Codex CLI"}
BILLING = {
    "openai_api": "使用操作者的 API 計費帳號，可能產生 API 使用費。",
    "codex_cli": "使用後端 ChatGPT 登入帳號的 Codex 額度；不是瀏覽者的帳號。",
}
REASONS = {
    "CONFIG_UNREADABLE": "無法讀取操作者設定。",
    "LINUX_RUNTIME_REQUIRED": "AI 調查需要 WSL Linux 後端。",
    "MODEL_CONFIG_REQUIRED": "尚未設定有效的模型與推理強度。",
    "API_KEY_REQUIRED": "尚未設定 API Key。",
    "CLI_NOT_INSTALLED": "後端尚未安裝或設定 Codex CLI。",
    "CLI_VERSION_UNSUPPORTED": "Codex CLI 版本尚未通過此接線的驗證。",
    "CLI_NATIVE_LINUX_REQUIRED": "請設定 WSL 內的原生 Linux Codex CLI 路徑。",
    "CLI_CHATGPT_LOGIN_REQUIRED": "後端 Codex 尚未使用 ChatGPT 登入。",
    "CLI_FILE_AUTH_IDENTITY_REQUIRED": "找不到官方 CLI 的檔案認證入口，請依設定文件完成登入。",
    "CHATGPT_LOGIN_REQUIRED": "後端 Codex 必須使用 ChatGPT 登入。",
    "DEFAULT_PROVIDER_INVALID": "預設來源設定無效，請明確選擇可用來源。",
    "AI_DISABLED": "管理者尚未啟用 AI 調查。",
    "PROVIDER_DISABLED": "管理者尚未啟用此來源。",
    "API_KEY_MISSING": "尚未設定 API Key。",
    "MODEL_REQUIRED": "尚未設定模型。",
    "CLI_NOT_FOUND": "後端尚未安裝或設定 Codex CLI。",
    "NOT_LOGGED_IN": "後端 Codex 尚未登入。",
    "AUTH_TYPE_MISMATCH": "後端 Codex 必須使用 ChatGPT 登入。",
    "UNSUPPORTED_CLI": "Codex CLI 版本或必要能力尚未通過檢查。",
}


def value(item):
    if item is None or item == "":
        return "未知"
    if isinstance(item, (dict, list)):
        return json.dumps(item, ensure_ascii=False, sort_keys=True)
    return str(item)


def provider_options(config):
    """Return public choices; retain the legacy single-API calling contract."""
    if isinstance(config.get("providers"), dict):
        choices = {key: dict(item) for key, item in config["providers"].items()
                   if key in PROVIDERS and isinstance(item, dict)}
        default = config.get("default_provider", "openai_api")
        # A missing default is unavailable, never an implicit fallback.
        if not isinstance(default, str) or default not in PROVIDERS:
            default = "__invalid_default__"
            choices[default] = {"configured": False, "reason_code": "DEFAULT_PROVIDER_INVALID"}
        for provider in PROVIDERS:
            choices.setdefault(provider, {"provider": provider, "configured": False,
                                          "reason_code": "PROVIDER_DISABLED"})
        return choices, default, False
    return {"openai_api": dict(config, provider="openai_api")}, "openai_api", True


def readiness_reason(config):
    code = config.get("reason_code")
    return REASONS.get(code, "此來源目前無法使用，請由操作者檢查後端設定。") + (
        "（" + value(code) + "）" if code else "")


def receipt_model(call, provider):
    """A queued/failed call may contain a legacy configured-model placeholder.

Only a model attached to a native receipt is presented as provider-reported.
This display check does not validate the receipt or imply successful execution.
"""
    kind = provider or call.get("provider")
    if call.get("provider") not in (None, kind):
        return None
    key = "thread_id" if kind == "codex_cli" else "response_id"
    identity, model = call.get(key), call.get("model")
    if (kind not in (None, "openai_api", "codex_cli")
            or not isinstance(identity, str) or not identity.strip()
            or not isinstance(model, str) or not model.strip()):
        return None
    return model


def attempt_metadata(ai=None, request=None, *, status=None):
    """Identity comes only from a saved request/AI, not today's selector."""
    ai = ai if isinstance(ai, dict) else {}
    request = request if isinstance(request, dict) else {}
    provider = request.get("provider") or ai.get("provider")
    legacy = request.get("schema_version") == "1.0" and not request.get("provider")
    if legacy:
        provider = "openai_api"
    label = "舊版 OpenAI API" if legacy else PROVIDERS.get(provider, "未知來源")
    calls = [call for call in (ai.get("calls") or []) if isinstance(call, dict)]
    models = list(dict.fromkeys(model for call in calls if (model := receipt_model(call, provider))))
    reported = "、".join(models) or None
    return {
        "ai_id": request.get("ai_id"), "status": status or ai.get("status"),
        "provider": provider if provider in PROVIDERS else None, "provider_label": label,
        "configured_model": request.get("model", ai.get("model")),
        "actual_model": reported, "auth_type": request.get("auth_type", ai.get("auth_type")),
        "config_id": request.get("config_id"), "created_at": request.get("created_at"),
    }


def metadata_lines(metadata):
    return ["執行來源：" + value(metadata.get("provider_label")),
            "設定模型：" + value(metadata.get("configured_model")),
            "實際回報模型：" + value(metadata.get("actual_model"))]


def receipt_lines(call, provider):
    output = ["回報模型：" + value(receipt_model(call, provider)), "狀態：" + value(call.get("status"))]
    if provider == "codex_cli":
        output += ["Thread ID：" + value(call.get("thread_id")),
                   "結束事件：" + value(call.get("terminal_event")),
                   "程序退出碼：" + value(call.get("exit_code"))]
    else:
        output.append("Response ID：" + value(call.get("response_id")))
    output.append("Usage：" + value(call.get("usage")))
    return output
