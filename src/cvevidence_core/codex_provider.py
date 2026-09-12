"""Pinned, tool-free Codex CLI transport; Python retains all evidence tools.

The model catalog is an execution policy, not a claim about model capabilities.
Only the official CLI reads authentication. No auth file is opened here.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

from .providers import ProviderError, ProviderStep

CLI_VERSION = "codex-cli 0.153.4"
POLICY_VERSION = "codex-no-tools-v1"
MAX_INPUT = 256 * 1024
MAX_STREAM = 2 * 1024 * 1024
MAX_LINE = 256 * 1024
MAX_FINAL = 128 * 1024
READINESS_TTL = 15.0
_READINESS_CACHE: dict[tuple, tuple[float, dict]] = {}
_READINESS_LOCK = threading.Lock()
_SUPERVISOR = """import ctypes,os,signal,subprocess,sys
def stop(*args): os.killpg(os.getpgrp(),signal.SIGKILL)
signal.signal(signal.SIGTERM,stop)
if ctypes.CDLL(None,use_errno=True).prctl(1,signal.SIGTERM,0,0,0)!=0: sys.exit(125)
if os.getppid()!=int(sys.argv[1]): stop()
child=subprocess.Popen(sys.argv[2:],close_fds=True)
code=child.wait()
sys.exit(code if code>=0 else 128-code)
"""
DISABLED_FEATURES = (
    "shell_tool", "multi_agent", "multi_agent_v2", "apps", "plugins",
    "remote_plugin", "hooks", "browser_use", "browser_use_external",
    "browser_use_full_cdp_access", "computer_use", "image_generation",
    "view_image", "code_mode", "code_mode_host", "code_mode_only",
    "memories", "goals", "skill_search", "skill_mcp_dependency_install",
    "tool_suggest", "sleep_tool", "request_permissions_tool", "shell_snapshot",
    "workspace_dependencies", "auth_elicitation", "unbounded_connection_retries",
)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def restricted_catalog(model: str, effort: str) -> dict:
    """Fresh minimal 0.153.4 ModelInfo; no executable or hosted tool metadata."""
    return {"models": [{
        "slug": model, "display_name": model, "description": None,
        "default_reasoning_level": effort,
        "supported_reasoning_levels": [{"effort": effort, "description": "Configured effort"}],
        "shell_type": "disabled", "visibility": "list", "supported_in_api": True,
        "priority": 0, "availability_nux": None, "upgrade": None,
        "model_messages": {"instructions_template": "Return a structured investigation decision.", "instructions_variables": None},
        "support_verbosity": False, "default_verbosity": None,
        "apply_patch_tool_type": None,
        "truncation_policy": {"mode": "tokens", "limit": 10000},
        "context_window": 128000, "experimental_supported_tools": [],
        "input_modalities": ["text"], "node_repl_disabled": True,
        "supports_search_tool": False, "include_apps_usage_instructions": False,
        "include_skills_usage_instructions": False,
        "include_plugin_usage_instructions": False,
    }]}


def policy_args(directory: Path, model: str, effort: str, instructions: str) -> list[str]:
    catalog = directory / "catalog.json"
    catalog.write_text(_json(restricted_catalog(model, effort)), encoding="utf-8")
    system = directory / "instructions.txt"
    system.write_text(instructions, encoding="utf-8")
    settings: dict[str, Any] = {
        "model_provider": "openai", "model_reasoning_effort": effort,
        "model_catalog_json": str(catalog), "model_instructions_file": str(system),
        "web_search": "disabled", "mcp_servers": {}, "agents.enabled": False,
        "tools.update_plan.enabled": False,
        "tools.experimental_request_user_input.enabled": False,
        "orchestrator.skills.enabled": False, "orchestrator.mcp.enabled": False,
        "skills.include_instructions": False, "project_doc_max_bytes": 0,
        "include_environment_context": False, "include_apps_instructions": False,
        "include_collaboration_mode_instructions": False,
        "memories.use_memories": False, "analytics.enabled": False,
        "feedback.enabled": False, "history.persistence": "none",
        "model_reasoning_summary": "none", "forced_login_method": "chatgpt",
        "suppress_unstable_features_warning": True,
    }
    args = ["exec", "--ignore-user-config", "--ignore-rules", "--ephemeral",
            "--skip-git-repo-check", "--sandbox", "read-only", "--json",
            "--color", "never", "--cd", str(directory), "--model", model]
    for key, value in settings.items():
        args += ["-c", key + "=" + _json(value)]
    for feature in DISABLED_FEATURES:
        args += ["--disable", feature]
    args += ["--enable", "skip_host_skill_discovery"]
    return args


def _environment(directory: Path, codex_home: str) -> dict[str, str]:
    # No inherited API keys, proxy configuration, app credentials, or project env.
    return {"PATH": "/usr/bin:/bin", "HOME": str(directory), "LANG": "C.UTF-8",
            "CODEX_HOME": codex_home, "CODEX_SQLITE_HOME": str(directory / "state"),
            "XDG_CACHE_HOME": str(directory / "cache"), "TMPDIR": str(directory),
            "RUST_LOG": "off"}


def _kill_group(process: subprocess.Popen) -> None:
    # Kill even after the leader exits: descendants may still own stream FDs.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        raise ProviderError("FAILED", "CLI_CLEANUP_FAILED") from None


def _bounded_run(argv: list[str], *, data: bytes, cwd: Path, env: dict,
                 timeout: float, max_output: int = MAX_STREAM,
                 owner: Any = None) -> tuple[int, bytes, bytes]:
    if timeout <= 0:
        raise ProviderError("TIMED_OUT", "CLI_DEADLINE")
    deadline = time.monotonic() + timeout
    # A tiny supervisor makes worker death kill the CLI and its complete group.
    # It remains alive until the CLI exits; no preexec_fn in a threaded parent.
    supervised = [sys.executable, "-c", _SUPERVISOR, str(os.getpid()), *argv]
    process = subprocess.Popen(supervised, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, cwd=cwd, env=env,
                               start_new_session=True, close_fds=True)
    if owner is not None:
        owner._process = process
    selector = selectors.DefaultSelector()
    out, err = bytearray(), bytearray()
    pending = memoryview(data)
    try:
        for stream, label in ((process.stdout, "out"), (process.stderr, "err")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        os.set_blocking(process.stdin.fileno(), False)
        if pending:
            selector.register(process.stdin, selectors.EVENT_WRITE, "in")
        else:
            process.stdin.close()
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProviderError("TIMED_OUT", "CLI_DEADLINE")
            for key, _ in selector.select(min(remaining, 0.1)):
                if key.data == "in":
                    try:
                        written = os.write(key.fd, pending[:65536])
                        pending = pending[written:]
                    except BrokenPipeError:
                        pending = pending[:0]
                    if not pending:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    continue
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                (out if key.data == "out" else err).extend(chunk)
                if len(out) + len(err) > max_output:
                    raise ProviderError("BUDGET_EXHAUSTED", "CLI_OUTPUT_LIMIT")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProviderError("TIMED_OUT", "CLI_DEADLINE")
        try:
            code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            raise ProviderError("TIMED_OUT", "CLI_DEADLINE") from None
        return code, bytes(out), bytes(err)
    finally:
        selector.close()
        _kill_group(process)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream and not stream.closed:
                stream.close()
        if owner is not None:
            owner._process = None


def _validate_config(config: dict) -> tuple[str, str, str, str]:
    cli = str(config.get("bin", ""))
    model = str(config.get("model", ""))
    effort = str(config.get("reasoning_effort") or "low")
    home = str(config.get("codex_home") or Path.home() / ".codex")
    if sys.platform != "linux" or not cli or not Path(cli).is_absolute():
        raise ProviderError("CONFIG_REQUIRED", "CLI_NATIVE_LINUX_REQUIRED")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,119}", model):
        raise ProviderError("CONFIG_REQUIRED", "CLI_MODEL_REQUIRED")
    if effort not in {"minimal", "low", "medium", "high", "xhigh", "max", "ultra"}:
        raise ProviderError("CONFIG_REQUIRED", "CLI_EFFORT_INVALID")
    if not Path(home).is_absolute() or not Path(home).is_dir():
        raise ProviderError("CONFIG_REQUIRED", "CLI_AUTH_HOME_REQUIRED")
    try:
        with Path(cli).open("rb") as handle:
            magic = handle.read(4)
    except OSError:
        raise ProviderError("CONFIG_REQUIRED", "CLI_NOT_INSTALLED") from None
    if magic != b"\x7fELF" or not os.access(cli, os.X_OK):
        raise ProviderError("CONFIG_REQUIRED", "CLI_NATIVE_LINUX_REQUIRED")
    return cli, model, effort, home


def _auth_link(home: str, directory: Path) -> Path:
    """Expose only the official file-backed auth entry, never copy its bytes."""
    auth_home = directory / "auth"
    auth_home.mkdir(mode=0o700)
    source = Path(home) / "auth.json"
    if not source.is_file():
        raise ProviderError("CONFIG_REQUIRED", "CLI_FILE_AUTH_IDENTITY_REQUIRED")
    (auth_home / "auth.json").symlink_to(source)
    return auth_home


def _file_identity(path: Path) -> tuple:
    """Metadata only; detect both symlink replacement and target replacement."""
    try:
        link = path.lstat()
        target = path.stat()
        return tuple((st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns,
                      st.st_ctime_ns, st.st_mode) for st in (link, target))
    except OSError as exc:
        return ("unavailable", exc.errno)


def _readiness_cache_key(config: dict) -> tuple:
    cli = str(config.get("bin", ""))
    home = str(config.get("codex_home") or Path.home() / ".codex")
    fields = tuple(str(config.get(key) or "") for key in
                   ("provider", "model", "reasoning_effort", "auth_revision"))
    return (cli, home, fields, CLI_VERSION, POLICY_VERSION,
            _file_identity(Path(cli)), _file_identity(Path(home) / "auth.json"))


def _account_identity(cli: str, home: str, directory: Path, timeout: float) -> str:
    """Official account/read only; a link isolates config without copying secrets.

    No account values leave this function. This identifies an email/plan, not a
    separately authenticated workspace ID (the protocol does not supply one).
    """
    if timeout <= 0:
        raise ProviderError("TIMED_OUT", "CLI_DEADLINE")
    account_directory = directory / "account-check"
    account_directory.mkdir(mode=0o700)
    auth_home = _auth_link(home, account_directory)
    args = [cli, "app-server", "--stdio", "-c", "features.plugins=false",
            "-c", "features.hooks=false", "-c", "features.apps=false",
            "-c", "analytics.enabled=false"]
    process = subprocess.Popen([sys.executable, "-c", _SUPERVISOR, str(os.getpid()), *args],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=directory, env=_environment(directory, str(auth_home)),
        start_new_session=True, close_fds=True)
    selector = selectors.DefaultSelector()
    pending = bytearray()
    total = 0
    deadline = time.monotonic() + timeout

    def send(message: dict) -> None:
        process.stdin.write((_json(message) + "\n").encode())
        process.stdin.flush()

    try:
        for stream, label in ((process.stdout, "out"), (process.stderr, "err")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        send({"id": 1, "method": "initialize", "params": {
            "clientInfo": {"name": "cvevidence-readiness", "version": POLICY_VERSION}}})
        while time.monotonic() < deadline:
            for key, _ in selector.select(min(.1, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fd, 65536)
                total += len(chunk)
                if total > 65536:
                    raise ProviderError("CONFIG_REQUIRED", "CLI_ACCOUNT_OUTPUT_LIMIT")
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data != "out":
                    continue
                pending.extend(chunk)
                while b"\n" in pending:
                    line, _, tail = pending.partition(b"\n")
                    pending = bytearray(tail)
                    message = json.loads(line)
                    if message.get("id") == 1:
                        if "result" not in message:
                            raise ProviderError("CONFIG_REQUIRED", "CLI_ACCOUNT_CHECK_FAILED")
                        send({"id": 2, "method": "account/read", "params": {"refreshToken": False}})
                    if message.get("id") == 2:
                        account = message.get("result", {}).get("account") or {}
                        email = account.get("email")
                        if account.get("type") != "chatgpt" or not isinstance(email, str) or not email:
                            raise ProviderError("CONFIG_REQUIRED", "CLI_ACCOUNT_IDENTITY_UNAVAILABLE")
                        identity = ["chatgpt", email.strip().lower(), account.get("planType")]
                        return hashlib.sha256(_json(identity).encode()).hexdigest()
            if not selector.get_map():
                break
        raise ProviderError("CONFIG_REQUIRED", "CLI_ACCOUNT_CHECK_TIMEOUT")
    except (ValueError, OSError, TypeError):
        raise ProviderError("CONFIG_REQUIRED", "CLI_ACCOUNT_CHECK_FAILED") from None
    finally:
        selector.close()
        _kill_group(process)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def codex_readiness(config: dict, *, timeout: float = 8, force_refresh: bool = False) -> dict:
    """No inference; messages and credential contents never escape this check."""
    key = _readiness_cache_key(config)
    now = time.monotonic()
    if not force_refresh:
        with _READINESS_LOCK:
            cached = _READINESS_CACHE.get(key)
            if cached is not None and now - cached[0] < READINESS_TTL:
                return dict(cached[1])
    result = {"configured": False, "reason_code": "CLI_NOT_INSTALLED", "version": None,
              "auth_type": None, "auth_identity": None, "policy_version": POLICY_VERSION}
    try:
        deadline = time.monotonic() + timeout
        cli, _, _, home = _validate_config(config)
        with tempfile.TemporaryDirectory(prefix="cvevidence-ready-") as name:
            directory = Path(name)
            auth_home = _auth_link(home, directory)
            env = _environment(directory, str(auth_home))
            code, out, _ = _bounded_run([cli, "--version"], data=b"", cwd=directory,
                                         env=env, timeout=min(3, deadline-time.monotonic()), max_output=4096)
            version = out.decode("utf-8", errors="replace").strip()
            result["version"] = version if re.fullmatch(r"codex-cli [0-9.]+", version) else None
            if code or version != CLI_VERSION:
                raise ProviderError("CONFIG_REQUIRED", "CLI_VERSION_UNSUPPORTED")
            code, out, err = _bounded_run([cli, "login", "status"], data=b"", cwd=directory,
                                          env=env, timeout=min(3, deadline-time.monotonic()), max_output=8192)
            status = (out + err).decode("utf-8", errors="replace").lower()
            if code or "logged in using chatgpt" not in status:
                raise ProviderError("CONFIG_REQUIRED", "CLI_CHATGPT_LOGIN_REQUIRED")
            result["auth_type"] = "chatgpt"
            if not str(config.get("auth_revision", "")).strip():
                raise ProviderError("CONFIG_REQUIRED", "CLI_AUTH_REVISION_REQUIRED")
            result["auth_identity"] = _account_identity(cli, home, directory, max(0, deadline-time.monotonic()))
        result.update(configured=True, reason_code="READY")
    except ProviderError as exc:
        result["reason_code"] = exc.code
    except (OSError, ValueError):
        result["reason_code"] = "CLI_READINESS_FAILED"
    # If credentials changed during this check, don't associate a possibly old
    # account response with new file metadata. The next call must check again.
    if key == _readiness_cache_key(config):
        with _READINESS_LOCK:
            if len(_READINESS_CACHE) >= 32:
                _READINESS_CACHE.pop(min(_READINESS_CACHE, key=lambda item: _READINESS_CACHE[item][0]))
            _READINESS_CACHE[key] = (time.monotonic(), dict(result))
    return result


def _parse_events(output: bytes, code: int) -> tuple[dict, dict]:
    if code != 0:
        # Raw diagnostics are intentionally not copied into stored/user-facing errors.
        lower = output.lower()
        if b"rate limit" in lower or b"usage limit" in lower or b"quota" in lower:
            raise ProviderError("FAILED", "PROVIDER_RATE_OR_QUOTA_LIMIT")
        if b"unauthorized" in lower or b"authentication" in lower:
            raise ProviderError("CONFIG_REQUIRED", "CLI_CHATGPT_LOGIN_REQUIRED")
        raise ProviderError("FAILED", "CLI_PROCESS_FAILED")
    events = []
    try:
        for line in output.splitlines():
            if not line.strip():
                continue
            if len(line) > MAX_LINE:
                raise ProviderError("BUDGET_EXHAUSTED", "CLI_EVENT_LIMIT")
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError()
            events.append(event)
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise ProviderError("INVALID_MODEL_OUTPUT", "CLI_INVALID_EVENTS") from None
    starts = [e for e in events if e.get("type") == "thread.started"]
    terminals = [e for e in events if e.get("type") in {"turn.completed", "turn.failed", "error"}]
    if len(starts) != 1 or len(terminals) != 1 or terminals[0].get("type") != "turn.completed":
        raise ProviderError("FAILED", "CLI_NO_TERMINAL_RECEIPT")
    if events[0] is not starts[0] or events[-1] is not terminals[0] or sum(e.get("type") == "turn.started" for e in events) != 1:
        raise ProviderError("FAILED", "CLI_INVALID_EVENT_ORDER")
    thread_id = starts[0].get("thread_id")
    if not isinstance(thread_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", thread_id):
        raise ProviderError("FAILED", "CLI_INVALID_THREAD_RECEIPT")
    messages = []
    safe_events = []
    for event in events:
        typ = event.get("type")
        if typ in {"item.started", "item.updated", "item.completed"}:
            item = event.get("item", {})
            if item.get("type") not in {"agent_message", "reasoning"}:
                raise ProviderError("FAILED", "CLI_UNEXPECTED_TOOL_EVENT")
            if typ == "item.completed" and item.get("type") == "agent_message":
                messages.append(item.get("text"))
            # Private reasoning is neither retained nor hashed into receipts.
            safe_events.append({"type": typ, "item_type": item.get("type"), "item_id": item.get("id")})
        elif typ in {"thread.started", "turn.started", "turn.completed"}:
            safe_events.append(event)
        else:
            raise ProviderError("FAILED", "CLI_UNRECOGNIZED_EVENT")
    if not messages or not isinstance(messages[-1], str) or len(messages[-1].encode()) > MAX_FINAL:
        raise ProviderError("INVALID_MODEL_OUTPUT", "CLI_FINAL_OUTPUT_INVALID")
    try:
        decision = json.loads(messages[-1])
        if not isinstance(decision, dict):
            raise ValueError()
    except (ValueError, TypeError):
        raise ProviderError("INVALID_MODEL_OUTPUT", "CLI_FINAL_JSON_INVALID") from None
    terminal = terminals[0]
    usage = terminal.get("usage")
    if usage is not None and (not isinstance(usage, dict) or any(type(v) is not int or v < 0 for v in usage.values())):
        raise ProviderError("FAILED", "CLI_USAGE_INVALID")
    receipt = {"provider": "codex_cli", "status": "completed", "model": None,
               "usage": usage, "thread_id": thread_id, "terminal_event": "turn.completed",
               "exit_code": code, "events_sha256": hashlib.sha256(_json(safe_events).encode()).hexdigest(),
               "cli_version": CLI_VERSION, "policy_version": POLICY_VERSION}
    return decision, receipt


class CodexCLIAdapter:
    provider_id = "codex_cli"
    auth_type = "chatgpt"
    mode = "LIVE"
    version = POLICY_VERSION

    def __init__(self, config: dict):
        self.config = dict(config)
        self.cli, self.model, self.reasoning_effort, self.codex_home = _validate_config(config)
        self._process = None
        self._auth_identity = config.get("auth_identity")

    def step(self, *, instructions: str, packet: dict, history: list[dict],
             budget: dict, timeout: float) -> ProviderStep:
        started = time.monotonic()
        if timeout <= 0:
            raise ProviderError("TIMED_OUT", "CLI_DEADLINE")
        ready = codex_readiness(self.config, timeout=min(8, timeout), force_refresh=True)
        if not ready["configured"]:
            if time.monotonic() - started >= timeout:
                raise ProviderError("TIMED_OUT", "CLI_DEADLINE")
            raise ProviderError("CONFIG_REQUIRED", ready["reason_code"])
        if self._auth_identity and self._auth_identity != ready["auth_identity"]:
            raise ProviderError("INPUT_CHANGED_OR_INVALID", "CLI_AUTH_IDENTITY_CHANGED")
        self._auth_identity = ready["auth_identity"]
        from .ai import TOOL  # Deferred to avoid the provider/controller import cycle.
        content = _json({"packet": packet, "history": history, "budget": budget})
        data = content.encode("utf-8")
        if len(data) > MAX_INPUT:
            raise ProviderError("BUDGET_EXHAUSTED", "CLI_INPUT_LIMIT")
        with tempfile.TemporaryDirectory(prefix="cvevidence-codex-") as name:
            directory = Path(name)
            schema = directory / "decision.schema.json"
            schema.write_text(_json(TOOL["parameters"]), encoding="utf-8")
            argv = [self.cli] + policy_args(directory, self.model, self.reasoning_effort, instructions)
            argv += ["--output-schema", str(schema), "-"]
            auth_home = _auth_link(self.codex_home, directory)
            code, output, _ = _bounded_run(argv, data=data, cwd=directory,
                                          env=_environment(directory, str(auth_home)),
                                          timeout=timeout - (time.monotonic() - started), owner=self)
            decision, receipt = _parse_events(output, code)
            return ProviderStep(decision=decision, receipt=receipt)

    def close(self) -> None:
        if self._process is not None:
            _kill_group(self._process)
            self._process = None
