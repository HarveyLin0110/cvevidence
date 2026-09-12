"""TEST_ONLY synthetic model receipts; no network or real LIVE claim."""
import hashlib
import json
from pathlib import Path
import subprocess
from uuid import uuid4
import pytest
from cvevidence.runner import Runner
from cvevidence.storage import RunStore
from cvevidence.ai_service import AIService
ROOT = Path(__file__).resolve().parents[1]

@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.delenv("CVEVIDENCE_AI_ENV_FILE", raising=False)
    monkeypatch.setenv("CVEVIDENCE_AI_ENABLED", "1")
    monkeypatch.setenv("OPENAI_API_KEY", "TEST_ONLY_SECRET")
    monkeypatch.setenv("OPENAI_MODEL", "TEST_ONLY_MODEL")
    runner = Runner(RunStore(tmp_path / "runtime"))
    intake = runner.start_file(ROOT / "demo-inputs/cmake/06_cmake.tar.gz", cve="CVE-2022-37434")
    return runner, runner.analyze_offline(intake.run_id)

def synthetic(request, status="NEEDS_USER_INPUT"):
    ai = {"mode": "LIVE", "status": status, "context_hash": request.context_hash,
          "cve_id": request.cve_id, "engineering_assessment_id": request.assessment_id,
          "model": request.model, "tasks": [], "excerpts": [],
          "calls": [{"response_id": "TEST_ONLY_RESPONSE", "model": "TEST_ONLY_MODEL"}]}
    schema_version = getattr(request, "schema_version", "1.0")
    if schema_version == "2.0":
        ai.update(schema_version="2.0", provider=request.provider, auth_type=request.auth_type,
                  reasoning_effort=request.reasoning_effort)
        ai["calls"][0].update(provider=request.provider, call_number=1, status="completed")
    ai["record_hash"] = hashlib.sha256(json.dumps(ai, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    return {"schema_version": schema_version, **({"provider": request.provider, "auth_type": request.auth_type} if schema_version == "2.0" else {}),
            "context_hash": request.context_hash, "mode": "LIVE",
            "status": "COMPLETED" if status in ("NEEDS_USER_INPUT", "COMPLETED") else "INCOMPLETE",
            "analyses": [{"cve_id": request.cve_id, "engineering_assessment_id": request.assessment_id, "ai": ai}]}

def test_no_consent_or_configuration_never_calls_worker(case, monkeypatch):
    runner, parent = case
    monkeypatch.setattr(AIService, "invoke", lambda *a, **k: pytest.fail("Worker must not run"))
    blocked = runner.investigate_ai(parent.run_id)
    assert blocked["status"] == "CONSENT_REQUIRED" and blocked["result"] is None
    monkeypatch.delenv("OPENAI_API_KEY")
    missing = runner.investigate_ai(parent.run_id, consent=True)
    assert missing["status"] == "CONFIG_REQUIRED" and missing["result"] is None
    assert "TEST_ONLY_SECRET" not in json.dumps(runner.ai_history(parent.run_id))
    assert not runner.ai_configuration()["configured"]

def test_success_saved_separately_idempotent_and_secret_free(case, monkeypatch):
    runner, parent = case
    before = runner.store._run_path(parent.run_id).read_bytes()
    calls = []
    def invoke(self, request, *args):
        calls.append(request.ai_id)
        return synthetic(request)
    monkeypatch.setattr(AIService, "invoke", invoke)
    ai_id = str(uuid4())
    first = runner.investigate_ai(parent.run_id, consent=True, ai_id=ai_id, user_context="TEST_ONLY question")
    again = runner.investigate_ai(parent.run_id, consent=True, ai_id=ai_id, user_context="TEST_ONLY question")
    assert first == again and first["status"] == "NEEDS_USER_INPUT" and calls == [ai_id]
    with pytest.raises(ValueError): runner.investigate_ai(parent.run_id, consent=True, ai_id=ai_id, user_context="changed")
    assert runner.store._run_path(parent.run_id).read_bytes() == before
    assert runner.read_engineering(parent.run_id)["analyses"][0]["ai"]["status"] == "OFFLINE"
    assert "TEST_ONLY_SECRET" not in json.dumps(first)
    with pytest.raises(FileNotFoundError): Runner(RunStore(runner.store.root / "other-account")).read_ai(ai_id)

def test_timeout_and_wrong_scope_never_publish_ai_success(case, monkeypatch):
    runner, parent = case
    def timeout(*args): raise subprocess.TimeoutExpired("TEST_ONLY", 1)
    monkeypatch.setattr(AIService, "invoke", timeout)
    assert runner.investigate_ai(parent.run_id, consent=True)["status"] == "TIMED_OUT"
    def wrong(self, request, *args):
        result = synthetic(request)
        result["context_hash"] = "0" * 64
        return result
    monkeypatch.setattr(AIService, "invoke", wrong)
    result = runner.investigate_ai(parent.run_id, consent=True)
    assert result["status"] == "FAILED" and result["result"] is None
    assert runner.read_engineering(parent.run_id)["engineering_status"] == "COMPLETED"

def test_unfinished_attempt_is_not_retried(case, monkeypatch):
    runner, parent = case
    def interrupted(*args): raise KeyboardInterrupt("TEST_ONLY process interruption")
    monkeypatch.setattr(AIService, "invoke", interrupted)
    ai_id = str(uuid4())
    with pytest.raises(KeyboardInterrupt): runner.investigate_ai(parent.run_id, consent=True, ai_id=ai_id)
    assert runner.read_ai(ai_id)["status"] == "NO_TERMINAL_RECEIPT"
    with pytest.raises(RuntimeError): runner.investigate_ai(parent.run_id, consent=True, ai_id=ai_id)

def test_tampered_payload_and_receipt_are_rejected(case, monkeypatch):
    runner, parent = case
    monkeypatch.setattr(AIService, "invoke", lambda self, request, *a: synthetic(request))
    result = runner.investigate_ai(parent.run_id, consent=True)
    blob = runner.store.root / "blobs" / result["outcome"]["payload_sha256"]
    blob.write_bytes(b"{}")
    with pytest.raises(ValueError): runner.read_ai(result["request"]["ai_id"])
    valid, rejected = runner.ai_history(parent.run_id)
    assert not valid and rejected

def test_worker_environment_has_only_ai_credentials(case, monkeypatch):
    runner, parent = case
    monkeypatch.setenv("GITHUB_TOKEN", "TEST_ONLY_GITHUB_SECRET")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "TEST_ONLY_OAUTH_SECRET")
    captured = {}
    class Process:
        returncode = 0
        pid = 999999
        def __init__(self, args, **kwargs):
            captured.update(kwargs)
            self.output = kwargs["stdout"]
        def communicate(self, raw, timeout):
            request = json.loads(raw)
            assert "TEST_ONLY_SECRET" not in raw.decode()
            from types import SimpleNamespace
            scope = SimpleNamespace(context_hash=request["context_hash"], cve_id=request["cve_id"],
                assessment_id=request["assessment_id"], model="TEST_ONLY_MODEL")
            self.output.write(json.dumps(synthetic(scope)).encode())
    monkeypatch.setattr(subprocess, "Popen", Process)
    result = runner.investigate_ai(parent.run_id, consent=True)
    assert result["status"] == "NEEDS_USER_INPUT"
    assert captured["start_new_session"] is True
    assert captured["env"]["OPENAI_API_KEY"] == "TEST_ONLY_SECRET"
    assert not {"GITHUB_TOKEN", "OAUTH_CLIENT_SECRET", "CVEVIDENCE_AI_ENV_FILE"} & captured["env"].keys()

def test_worker_rejects_missing_consent_before_reading_inputs(monkeypatch):
    from cvevidence.ai_worker import execute
    monkeypatch.setenv("CVEVIDENCE_AI_ENABLED", "1")
    with pytest.raises(ValueError): execute({"consent": False})

def test_concurrent_attempt_executes_once(case, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    runner, parent = case
    entered, release = Event(), Event()
    calls = []
    def invoke(self, request, *args):
        calls.append(request.ai_id)
        entered.set()
        assert release.wait(10)
        return synthetic(request)
    monkeypatch.setattr(AIService, "invoke", invoke)
    ai_id = str(uuid4())
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(runner.investigate_ai, parent.run_id, consent=True, ai_id=ai_id)
        try:
            assert entered.wait(10)
            with pytest.raises(RuntimeError):
                runner.investigate_ai(parent.run_id, consent=True, ai_id=ai_id)
        finally:
            release.set()
        assert first.result()["status"] == "NEEDS_USER_INPUT"
    assert calls == [ai_id]


def test_timeout_kills_process_group(case, monkeypatch):
    import signal
    import cvevidence.ai_service as service
    runner, parent = case
    killed, waited = [], []
    class Process:
        pid = 999999
        def __init__(self, *args, **kwargs): pass
        def communicate(self, *args, **kwargs):
            raise subprocess.TimeoutExpired("TEST_ONLY", 1)
        def wait(self): waited.append(True)
    monkeypatch.setattr(subprocess, "Popen", Process)
    monkeypatch.setattr(service.os, "killpg", lambda pid, sig: killed.append((pid, sig)))
    assert runner.investigate_ai(parent.run_id, consent=True)["status"] == "TIMED_OUT"
    assert killed == [(999999, signal.SIGKILL)] and waited == [True]


def test_ai_form_requires_consent_and_report_preserves_engineering(case, monkeypatch):
    from streamlit.testing.v1 import AppTest
    from cvevidence.ai_workspace import with_ai_result
    runner, parent = case
    calls = []
    def invoke(self, request, *args):
        calls.append(request.ai_id)
        return synthetic(request)
    monkeypatch.setattr(AIService, "invoke", invoke)
    source = ("import streamlit as st\n"
        "from cvevidence.runner import Runner\n"
        "from cvevidence.storage import RunStore\n"
        "from cvevidence.ai_workspace import ai_workspace\n"
        f"r = Runner(RunStore({str(runner.store.root)!r}))\n"
        f"run = r.store.read({parent.run_id!r})\n"
        "ai_workspace(st, r, run, r.read_engineering(run.run_id))\n")
    app = AppTest.from_string(source).run()
    assert not app.exception
    next(b for b in app.button if b.label == "開始 AI 調查").click().run()
    assert not app.exception and not calls and app.warning
    app.checkbox[0].check()
    next(b for b in app.button if b.label == "開始 AI 調查").click().run()
    assert not app.exception and len(calls) == 1
    record = runner.read_ai(calls[0])
    original = runner.read_engineering(parent.run_id)
    report = with_ai_result(original, record)
    assert report["analyses"][0]["ai"]["mode"] == "LIVE"
    assert original["analyses"][0]["ai"]["mode"] == "OFFLINE"
    next(b for b in app.button if b.label == "開始 AI 調查").click().run()
    assert not app.exception and len(calls) == 1


def test_old_engineering_profile_disables_new_ai_without_hiding_history(case):
    from streamlit.testing.v1 import AppTest
    runner, parent = case
    source = ("import streamlit as st\n"
        "from cvevidence.runner import Runner\n"
        "from cvevidence.storage import RunStore\n"
        "from cvevidence.ai_workspace import ai_workspace\n"
        f"r = Runner(RunStore({str(runner.store.root)!r}))\n"
        f"run = r.store.read({parent.run_id!r})\n"
        "payload = r.read_engineering(run.run_id)\n"
        "payload['analyses'][0]['assessment']['profile_version'] = 'TEST_ONLY_OLD_PROFILE'\n"
        "ai_workspace(st, r, run, payload)\n")
    app = AppTest.from_string(source).run()
    assert not app.exception
    assert next(b for b in app.button if b.label == '開始 AI 調查').disabled
    assert any('舊版規則' in warning.value for warning in app.warning)
