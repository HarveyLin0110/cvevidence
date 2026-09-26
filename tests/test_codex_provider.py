"""TEST_ONLY transport/OS checks, never evidence of a real CVE or LIVE run."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

from cvevidence_core.codex_provider import (
    CLI_VERSION, MAX_INPUT, CodexCLIAdapter, _bounded_run, _environment,
    _parse_events, _validate_config, _auth_link, codex_readiness, policy_args,
    restricted_catalog,
)
from cvevidence_core.providers import ProviderError


@pytest.fixture(autouse=True)
def clear_readiness_cache():
    import cvevidence_core.codex_provider as provider
    provider._READINESS_CACHE.clear()
    yield
    provider._READINESS_CACHE.clear()


def events(*, decision=None, item_type="agent_message", usage=None):
    return b"\n".join(json.dumps(x).encode() for x in [
        {"type": "thread.started", "thread_id": "test-only-thread"},
        {"type": "turn.started"},
        {"type": "item.completed", "item": {"id": "i1", "type": item_type,
            "text": json.dumps(decision or {"action": "ASK_USER"})}},
        {"type": "turn.completed", "usage": usage},
    ])


def test_native_receipt_and_unknown_usage_are_not_api_ids():
    decision, receipt = _parse_events(events(), 0)
    assert decision == {"action": "ASK_USER"}
    assert receipt["provider"] == "codex_cli"
    assert receipt["model"] is None and receipt["usage"] is None
    assert receipt["thread_id"] == "test-only-thread"
    assert receipt["terminal_event"] == "turn.completed"
    assert len(receipt["events_sha256"]) == 64
    assert "response_id" not in receipt and "turn_id" not in receipt


@pytest.mark.parametrize("output,code,error", [
    (b"{}", 0, "CLI_NO_TERMINAL_RECEIPT"),
    (b"[]", 0, "CLI_INVALID_EVENTS"),
    (events(item_type="command_execution"), 0, "CLI_UNEXPECTED_TOOL_EVENT"),
    (events(item_type="file_change"), 0, "CLI_UNEXPECTED_TOOL_EVENT"),
    (events(item_type="mcp_tool_call"), 0, "CLI_UNEXPECTED_TOOL_EVENT"),
    (events(usage={"input_tokens": -1}), 0, "CLI_USAGE_INVALID"),
    (events(usage={"input_tokens": True}), 0, "CLI_USAGE_INVALID"),
    (events() + b'\n{"type":"turn.completed"}', 0, "CLI_NO_TERMINAL_RECEIPT"),
    (events(), 1, "CLI_PROCESS_FAILED"),
    (b'{"error":"quota reached"}', 1, "PROVIDER_RATE_OR_QUOTA_LIMIT"),
])
def test_bad_output_cannot_be_a_completed_receipt(output, code, error):
    with pytest.raises(ProviderError) as caught:
        _parse_events(output, code)
    assert caught.value.code == error


def test_private_reasoning_not_retained_or_hashed():
    reasoning = b'\n{"type":"item.completed","item":{"id":"r1","type":"reasoning","text":"PRIVATE"}}'
    first = events().replace(b'\n{"type": "turn.completed"', reasoning + b'\n{"type": "turn.completed"')
    second = first.replace(b"PRIVATE", b"DIFFERENT")
    assert _parse_events(first, 0)[1]["events_sha256"] == _parse_events(second, 0)[1]["events_sha256"]
    assert "PRIVATE" not in json.dumps(_parse_events(first, 0)[1])


def test_policy_removes_executable_model_tools_and_inherited_inputs(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "TEST_ONLY_DO_NOT_INHERIT")
    monkeypatch.setenv("CODEX_API_KEY", "TEST_ONLY_DO_NOT_INHERIT")
    monkeypatch.setenv("HTTPS_PROXY", "TEST_ONLY_DO_NOT_INHERIT")
    env = _environment(tmp_path, "/trusted/auth")
    assert "OPENAI_API_KEY" not in env and "CODEX_API_KEY" not in env and "HTTPS_PROXY" not in env
    assert env["HOME"] == str(tmp_path)
    catalog = restricted_catalog("gpt-5.6-sol", "low")["models"][0]
    assert catalog["shell_type"] == "disabled"
    assert catalog["apply_patch_tool_type"] is None
    assert catalog["experimental_supported_tools"] == []
    argv = policy_args(tmp_path, "gpt-5.6-sol", "low", "Trusted instructions")
    assert "--ignore-user-config" in argv and "--ephemeral" in argv
    assert 'web_search="disabled"' in argv and "mcp_servers={}" in argv
    assert "skills.include_instructions=false" in argv
    assert "Trusted instructions" not in argv
    assert (tmp_path / "instructions.txt").read_text() == "Trusted instructions"


@pytest.mark.skipif(sys.platform != "linux", reason="Native Linux auth symlink")
def test_auth_link_shares_only_path_and_cleanup_keeps_original(tmp_path):
    import tempfile
    original = tmp_path / "original"
    original.mkdir()
    payload = b"TEST_ONLY_NOT_A_CREDENTIAL"
    (original / "auth.json").write_bytes(payload)
    (original / "config.toml").write_text("TEST_ONLY_PERSONAL_CONFIG")
    with tempfile.TemporaryDirectory(dir=tmp_path) as name:
        home = _auth_link(str(original), Path(name))
        assert (home / "auth.json").is_symlink()
        assert list(home.iterdir()) == [home / "auth.json"]
    assert (original / "auth.json").read_bytes() == payload


def test_readiness_rejects_api_auth_and_does_not_query_identity(monkeypatch, tmp_path):
    import cvevidence_core.codex_provider as provider
    monkeypatch.setattr(provider, "_validate_config", lambda config: ("/fake", "model", "low", str(tmp_path)))
    (tmp_path / "auth.json").write_text("TEST_ONLY_AUTH_METADATA")
    responses = iter([(0, CLI_VERSION.encode(), b""), (0, b"Logged in using an API key", b"")])
    monkeypatch.setattr(provider, "_bounded_run", lambda *args, **kwargs: next(responses))
    monkeypatch.setattr(provider, "_account_identity", lambda *args: pytest.fail("API auth must not query identity"))
    result = codex_readiness({"auth_revision": "test-only"})
    assert not result["configured"] and result["reason_code"] == "CLI_CHATGPT_LOGIN_REQUIRED"


def test_readiness_returns_only_identity_hash(monkeypatch, tmp_path):
    import cvevidence_core.codex_provider as provider
    monkeypatch.setattr(provider, "_validate_config", lambda config: ("/fake", "model", "low", str(tmp_path)))
    (tmp_path / "auth.json").write_text("TEST_ONLY_AUTH_METADATA")
    responses = iter([(0, CLI_VERSION.encode(), b""), (0, b"Logged in using ChatGPT", b"")])
    monkeypatch.setattr(provider, "_bounded_run", lambda *args, **kwargs: next(responses))
    monkeypatch.setattr(provider, "_account_identity", lambda *args: "a" * 64)
    result = codex_readiness({"auth_revision": "test-only"})
    assert result["configured"] and result["auth_identity"] == "a" * 64
    assert "email" not in result


def _fake_ready(monkeypatch, tmp_path):
    import cvevidence_core.codex_provider as provider
    source = tmp_path / "auth.json"
    source.write_text("TEST_ONLY_AUTH_METADATA")
    cli = tmp_path / "codex"
    cli.write_bytes(b"TEST_ONLY_BINARY_METADATA")
    calls = []
    monkeypatch.setattr(provider, "_validate_config", lambda config: (str(cli), "model", "low", str(tmp_path)))

    def run(argv, **kwargs):
        calls.append(argv)
        home = Path(kwargs["env"]["CODEX_HOME"])
        assert home != tmp_path and (home / "auth.json").is_symlink()
        assert not (home / "config.toml").exists()
        return (0, CLI_VERSION.encode() if "--version" in argv else b"Logged in using ChatGPT", b"")

    monkeypatch.setattr(provider, "_bounded_run", run)
    monkeypatch.setattr(provider, "_account_identity", lambda *args: "a" * 64)
    return provider, {"bin": str(cli), "codex_home": str(tmp_path), "model": "test-model", "auth_revision": "r1"}, calls


def test_readiness_ttl_cache_is_copied_and_force_refresh_bypasses(monkeypatch, tmp_path):
    provider, config, calls = _fake_ready(monkeypatch, tmp_path)
    first = provider.codex_readiness(config)
    first["configured"] = False
    assert provider.codex_readiness(config)["configured"]
    assert len(calls) == 2
    assert provider.codex_readiness(config, force_refresh=True)["configured"]
    assert len(calls) == 4
    key, (timestamp, result) = next(iter(provider._READINESS_CACHE.items()))
    provider._READINESS_CACHE[key] = (timestamp - provider.READINESS_TTL - 1, result)
    assert provider.codex_readiness(config)["configured"]
    assert len(calls) == 6


@pytest.mark.parametrize("change", ["auth", "bin", "revision", "model"])
def test_metadata_or_operator_config_change_invalidates_cache(monkeypatch, tmp_path, change):
    provider, config, calls = _fake_ready(monkeypatch, tmp_path)
    assert provider.codex_readiness(config)["configured"]
    if change in {"auth", "bin"}:
        path = tmp_path / ("auth.json" if change == "auth" else "codex")
        replacement = tmp_path / "replacement"
        replacement.write_text("TEST_ONLY_REPLACEMENT")
        replacement.replace(path)
    else:
        config["auth_revision" if change == "revision" else "model"] = "r2"
    assert provider.codex_readiness(config)["configured"]
    assert len(calls) == 4


def test_step_never_uses_ui_readiness_cache(monkeypatch, tmp_path):
    import cvevidence_core.codex_provider as provider
    monkeypatch.setattr(provider, "_validate_config", lambda config: ("/fake", "model", "low", str(tmp_path)))
    observed = []
    def readiness(config, **kwargs):
        observed.append(kwargs)
        return {"configured": False, "reason_code": "TEST_ONLY_STOP"}
    monkeypatch.setattr(provider, "codex_readiness", readiness)
    adapter = provider.CodexCLIAdapter({})
    with pytest.raises(ProviderError):
        adapter.step(instructions="test", packet={}, history=[], budget={}, timeout=1)
    assert observed == [{"timeout": 1, "force_refresh": True}]


@pytest.mark.skipif(sys.platform != "linux", reason="Native Linux process supervision")
def test_rejects_windows_interop_and_scripts(tmp_path):
    cli = tmp_path / "codex.exe"
    cli.write_bytes(b"MZtest-only")
    cli.chmod(0o755)
    with pytest.raises(ProviderError) as error:
        _validate_config({"bin": str(cli), "model": "gpt-5.6-sol", "codex_home": str(tmp_path)})
    assert error.value.code == "CLI_NATIVE_LINUX_REQUIRED"


@pytest.mark.skipif(sys.platform != "linux", reason="Native Linux process supervision")
def test_bounded_bidirectional_io_avoids_pipe_deadlock(tmp_path):
    script = "import sys; sys.stdout.buffer.write(b'x'*200000); sys.stdout.flush(); data=sys.stdin.buffer.read(); sys.stderr.write(str(len(data)))"
    code, out, err = _bounded_run([sys.executable, "-c", script], data=b"a" * 200000,
                                  cwd=tmp_path, env=_environment(tmp_path, str(tmp_path)), timeout=5)
    assert code == 0 and out == b"x" * 200000 and err == b"200000"


def _running(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()[0] != "Z"
    except (FileNotFoundError, ProcessLookupError):
        return False


@pytest.mark.skipif(sys.platform != "linux", reason="Native Linux process supervision")
@pytest.mark.parametrize("mode", ["timeout", "output"])
def test_deadline_and_output_limit_kill_descendant(tmp_path, mode):
    receipt = tmp_path / "child.pid"
    script = (
        "import subprocess,sys,time,pathlib; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); "
        + ("time.sleep(30)" if mode == "timeout" else "sys.stdout.write('x'*200000); sys.stdout.flush(); time.sleep(30)")
    )
    started = time.monotonic()
    with pytest.raises(ProviderError) as caught:
        _bounded_run([sys.executable, "-c", script, str(receipt)], data=b"", cwd=tmp_path,
                     env=_environment(tmp_path, str(tmp_path)), timeout=1, max_output=4096)
    assert caught.value.code == ("CLI_DEADLINE" if mode == "timeout" else "CLI_OUTPUT_LIMIT")
    assert time.monotonic() - started < 3
    pid = int(receipt.read_text())
    for _ in range(20):
        if not _running(pid):
            break
        time.sleep(.025)
    assert not _running(pid)


@pytest.mark.skipif(sys.platform != "linux", reason="Native Linux parent-death supervision")
def test_worker_death_kills_cli_and_descendants(tmp_path):
    receipt = tmp_path / "child.pid"
    child = "import pathlib,subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); pathlib.Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(30)"
    worker_code = (
        "import sys; from pathlib import Path; from cvevidence_core.codex_provider import _bounded_run,_environment; "
        "root=Path(sys.argv[1]); _bounded_run([sys.executable,'-c',sys.argv[2],sys.argv[3]],data=b'',cwd=root,env=_environment(root,str(root)),timeout=30)"
    )
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(str(x) for x in __import__("cvevidence_core").__path__))
    # Use the package parent; injected dependency paths in development remain available.
    env["PYTHONPATH"] = os.pathsep.join(str(Path(x).parent) for x in __import__("cvevidence_core").__path__)
    process = subprocess.Popen([sys.executable, "-c", worker_code, str(tmp_path), child, str(receipt)], env=env)
    try:
        deadline = time.monotonic() + 5
        while not receipt.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(.025)
        assert receipt.exists()
        pid = int(receipt.read_text())
        process.kill()
        process.wait(timeout=2)
        for _ in range(40):
            if not _running(pid):
                break
            time.sleep(.025)
        assert not _running(pid)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


@pytest.mark.parametrize("failure",[FileNotFoundError(),ProcessLookupError()])
def test_process_probe_handles_exit_during_read(monkeypatch,failure):
    def gone(*args,**kwargs):raise failure
    monkeypatch.setattr(Path,"read_text",gone)
    assert not _running(123)


def test_process_probe_does_not_hide_permission_failure(monkeypatch):
    def denied(*args,**kwargs):raise PermissionError()
    monkeypatch.setattr(Path,"read_text",denied)
    with pytest.raises(PermissionError):_running(123)
