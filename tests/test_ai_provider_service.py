"""Contract/service fixtures are synthetic; real provider acceptance is separate."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from uuid import uuid4

import pytest

from cvevidence.ai_config import provider_configuration, public_configuration
from cvevidence.ai_process import run_worker, WorkerLimitError
from cvevidence.ai_service import AIService
from cvevidence.ai_store import AIRequest, AIRequestV2, parse_ai_request, validate_ai_payload
from cvevidence.runner import Runner
from cvevidence.storage import RunStore

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def settings(monkeypatch):
    monkeypatch.delenv("CVEVIDENCE_AI_ENV_FILE", raising=False)
    monkeypatch.setenv("CVEVIDENCE_AI_ENABLED", "1")
    monkeypatch.setenv("CVEVIDENCE_AI_PROVIDERS", "openai_api")
    monkeypatch.setenv("OPENAI_API_KEY", "TEST_ONLY_SECRET")
    monkeypatch.setenv("OPENAI_MODEL", "TEST_ONLY_MODEL")


def request(provider="openai_api"):
    return AIRequestV2(ai_id=str(uuid4()), parent_run_id=str(uuid4()),
        engineering_payload_sha256="1" * 64, context_hash="2" * 64,
        cve_id="CVE-2022-37434", assessment_id="A-TEST_ONLY", consent=True,
        context_text_sha256="3" * 64, model="TEST_ONLY_MODEL", created_at="TEST_ONLY",
        timeout_seconds=180, provider=provider,
        versions={"code_sha256": "6" * 64, "prompt_sha256": "7" * 64, "contract_version": "2.0"},
        auth_type="api_key" if provider == "openai_api" else "chatgpt", config_id="4" * 64)


def synthetic(req):
    call = {"provider": req.provider, "call_number": 1, "status": "completed", "model": None, "usage": None}
    if req.provider == "openai_api":
        call["response_id"] = "TEST_ONLY_RESPONSE"
    else:
        call.update(thread_id="TEST_ONLY_THREAD", exit_code=0, terminal_event="turn.completed", events_sha256="5" * 64)
    ai = {"schema_version": "2.0", "provider": req.provider, "auth_type": req.auth_type,
          "mode": "LIVE", "status": "NEEDS_USER_INPUT", "context_hash": req.context_hash,
          "cve_id": req.cve_id, "engineering_assessment_id": req.assessment_id,
          "model": req.model, "reasoning_effort": req.reasoning_effort, "calls": [call], "tasks": [], "excerpts": []}
    ai["record_hash"] = hashlib.sha256(json.dumps(ai, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    return {"schema_version": "2.0", "provider": req.provider, "auth_type": req.auth_type,
            "versions": req.versions.model_dump(),
            "context_hash": req.context_hash, "mode": "LIVE", "status": "COMPLETED",
            "analyses": [{"cve_id": req.cve_id, "engineering_assessment_id": req.assessment_id, "ai": ai}]}


def test_readiness_does_not_disclose_credentials_and_tracks_changes(settings, monkeypatch):
    public = public_configuration()
    assert public["providers"]["openai_api"]["configured"]
    assert not public["providers"]["codex_cli"]["configured"]
    assert "TEST_ONLY_SECRET" not in json.dumps(public)
    first = public["providers"]["openai_api"]["config_id"]
    monkeypatch.setenv("OPENAI_API_KEY", "TEST_ONLY_DIFFERENT_SECRET")
    assert provider_configuration("openai_api")[1]["config_id"] != first
    monkeypatch.setenv("CVEVIDENCE_AI_DEFAULT_PROVIDER", "codex_cli")
    assert public_configuration()["default_provider"] == "codex_cli"
    assert not public_configuration()["providers"]["codex_cli"]["configured"]


def test_version_dispatch_does_not_upgrade_old_request():
    newer = request()
    assert isinstance(parse_ai_request(newer.model_dump_json()), AIRequestV2)
    older = newer.model_dump(exclude={"provider", "auth_type", "config_id", "versions"})
    older["schema_version"] = "1.0"
    raw = json.dumps(older)
    parsed = parse_ai_request(raw)
    assert type(parsed) is AIRequest and "provider" not in parsed.model_dump()
    with pytest.raises(ValueError): parse_ai_request({**older, "schema_version": "3.0"})
    with pytest.raises(ValueError): parse_ai_request({**older, "provider": "codex_cli"})


@pytest.mark.parametrize("provider", ["openai_api", "codex_cli"])
def test_native_receipts_and_mode_are_checked(provider):
    req = request(provider)
    payload = synthetic(req)
    assert validate_ai_payload(payload, req) == "NEEDS_USER_INPUT"
    payload["analyses"][0]["ai"]["mode"] = "SIMULATED"
    with pytest.raises(ValueError): validate_ai_payload(payload, req)
    payload = synthetic(req)
    payload["provider"] = "wrong"
    with pytest.raises(ValueError): validate_ai_payload(payload, req)
    payload = synthetic(req)
    payload["analyses"][0]["ai"]["calls"][0]["provider"] = "wrong"
    with pytest.raises(ValueError): validate_ai_payload(payload, req)
    payload = synthetic(req)
    payload["analyses"][0]["ai"]["calls"][0].pop("response_id" if provider == "openai_api" else "terminal_event")
    with pytest.raises(ValueError): validate_ai_payload(payload, req)


def test_new_attempts_bind_consent_configuration_and_are_idempotent(settings, monkeypatch, tmp_path):
    runner = Runner(RunStore(tmp_path / "runtime"))
    intake = runner.start_file(ROOT / "demo-inputs/cmake/06_cmake.tar.gz", cve="CVE-2022-37434")
    parent = runner.analyze_offline(intake.run_id)
    parent_bytes = runner.store._run_path(parent.run_id).read_bytes()
    config_id = provider_configuration("openai_api")[1]["config_id"]
    calls = []
    def invoke(self, req, *args):
        calls.append(req.ai_id)
        return synthetic(req)
    monkeypatch.setattr(AIService, "invoke", invoke)
    inputs = dict(provider="openai_api", config_id=config_id, consent=True, ai_id=str(uuid4()))
    first = runner.investigate_ai(parent.run_id, **inputs)
    assert first["status"] == "NEEDS_USER_INPUT"
    assert runner.investigate_ai(parent.run_id, **inputs) == first
    assert calls == [inputs["ai_id"]]
    monkeypatch.setenv("OPENAI_API_KEY", "TEST_ONLY_ROTATED_KEY")
    changed = runner.investigate_ai(parent.run_id, **{**inputs, "ai_id": str(uuid4())})
    assert changed["status"] == "CONSENT_REQUIRED"
    assert changed["outcome"]["error_code"] == "PROVIDER_CONFIGURATION_CHANGED"
    assert calls == [inputs["ai_id"]]
    assert runner.read_ai(first["request"]["ai_id"]) == first
    assert runner.store._run_path(parent.run_id).read_bytes() == parent_bytes
    with pytest.raises(ValueError):
        runner.investigate_ai(parent.run_id, **{**inputs, "provider": "codex_cli"})


@pytest.mark.skipif(os.name != "posix", reason="POSIX worker control")
def test_worker_stream_limits_and_deadline():
    code, output = run_worker([sys.executable, "-c", "import sys; print(sys.stdin.read())"], b"bounded", env={}, timeout=5)
    assert code == 0 and output == b"bounded\n"
    with pytest.raises(WorkerLimitError):
        run_worker([sys.executable, "-c", "import os; os.write(1, b'x'*65536)"], b"{}", env={}, timeout=5, max_output=1024)
    with pytest.raises(subprocess.TimeoutExpired):
        run_worker([sys.executable, "-c", "import time; time.sleep(30)"], b"{}", env={}, timeout=0.15)


def test_codex_worker_never_receives_api_key(settings, monkeypatch, tmp_path):
    import cvevidence.ai_service as service
    req = request("codex_cli")
    req = req.model_copy(update={"engineering_payload_sha256": "1" * 64})
    store = SimpleNamespace(root=tmp_path, read=lambda _: SimpleNamespace(input_package=SimpleNamespace(archive_sha256="2" * 64)))
    monkeypatch.setenv("GITHUB_TOKEN", "TEST_ONLY_OTHER_SECRET")
    captured = {}
    def run(argv, payload, **kwargs):
        captured.update(kwargs)
        assert "OPENAI_API_KEY" not in kwargs["env"]
        assert "GITHUB_TOKEN" not in kwargs["env"]
        assert b"TEST_ONLY_SECRET" not in payload
        return 0, json.dumps(synthetic(req)).encode()
    monkeypatch.setattr(service, "run_worker", run)
    obj = AIService.__new__(AIService)
    obj.store = store
    obj.invoke(req, "question", {"model": "TEST_ONLY_MODEL", "OPENAI_API_KEY": "TEST_ONLY_SECRET"}, 5)
    assert captured


def test_legacy_api_caller_cannot_bypass_provider_allowlist(settings, monkeypatch):
    from cvevidence.ai_service import operator_config
    monkeypatch.setenv("CVEVIDENCE_AI_PROVIDERS", "codex_cli")
    assert provider_configuration("openai_api")[1]["reason_code"] == "PROVIDER_DISABLED"
    assert operator_config()[1]["configured"] is False


def test_operator_env_file_preserves_export_syntax(settings, monkeypatch, tmp_path):
    config = tmp_path / "operator.env"
    config.write_text('export OPENAI_API_KEY="TEST_ONLY_FILE_SECRET"\nexport OPENAI_MODEL=TEST_ONLY_FILE_MODEL\n')
    monkeypatch.delenv("OPENAI_API_KEY")
    monkeypatch.delenv("OPENAI_MODEL")
    monkeypatch.setenv("CVEVIDENCE_AI_ENV_FILE", str(config))
    private, public = provider_configuration("openai_api")
    assert public["configured"] and public["model"] == "TEST_ONLY_FILE_MODEL"
    assert private["OPENAI_API_KEY"] == "TEST_ONLY_FILE_SECRET"
    assert "TEST_ONLY_FILE_SECRET" not in json.dumps(public)


def test_v2_rejects_changed_reasoning_setting():
    req = request()
    payload = synthetic(req)
    payload["analyses"][0]["ai"]["reasoning_effort"] = "high"
    with pytest.raises(ValueError): validate_ai_payload(payload, req)
def test_worker_constructor_provider_error_remains_structured(monkeypatch, capsys):
    import io
    from cvevidence import ai_worker
    from cvevidence_core.providers import ProviderError

    def fail(request):
        raise ProviderError("CONFIG_REQUIRED", "CHATGPT_LOGIN_REQUIRED")

    monkeypatch.setattr(ai_worker, "execute", fail)
    monkeypatch.setattr(ai_worker.sys, "stdin", io.StringIO("{}"))
    assert ai_worker.main() == 0
    assert json.loads(capsys.readouterr().out) == {
        "worker_error": {"status": "CONFIG_REQUIRED", "code": "CHATGPT_LOGIN_REQUIRED"}}


def test_execution_versions_are_bound_to_saved_request():
    req = request()
    payload = synthetic(req)
    payload["versions"]["prompt_sha256"] = "8" * 64
    with pytest.raises(ValueError, match="version mismatch"):
        validate_ai_payload(payload, req)


def test_changed_worker_code_is_rejected_before_material_read(monkeypatch):
    from cvevidence import ai_worker
    from cvevidence_core.providers import ProviderError
    monkeypatch.setenv("CVEVIDENCE_AI_ENABLED", "1")
    payload = dict.fromkeys(("archive", "archive_sha256", "context_hash", "temporary_root", "engineering_blob",
                            "engineering_payload_sha256", "cve_id", "assessment_id", "user_context",
                            "config_id", "provider_config", "deadline_monotonic"))
    payload.update(provider="codex_cli", auth_type="chatgpt", consent=True, versions={})
    with pytest.raises(ProviderError) as error:
        ai_worker.execute(payload)
    assert error.value.status == "INPUT_CHANGED_OR_INVALID"
    assert error.value.code == "AI_IMPLEMENTATION_CHANGED"

@pytest.mark.parametrize('failure,status', [(subprocess.TimeoutExpired('test',1),'TIMED_OUT'), ('cancel','CANCELLED')])
def test_invalid_checkpoint_still_saves_terminal_failure(settings,monkeypatch,tmp_path,failure,status):
    from cvevidence.ai_process import WorkerCancelled
    from cvevidence.ai_jobs import path
    runner=Runner(RunStore(tmp_path/'runtime'))
    intake=runner.start_file(ROOT/'demo-inputs/cmake/06_cmake.tar.gz',cve='CVE-2022-37434')
    parent=runner.analyze_offline(intake.run_id)
    before=runner.store._run_path(parent.run_id).read_bytes()
    calls=[]
    def invoke(self,req,*args):
        calls.append(req.ai_id)
        path(self.store,req.ai_id,'.json').write_text('{invalid checkpoint')
        raise WorkerCancelled('test') if failure=='cancel' else failure
    monkeypatch.setattr(AIService,'invoke',invoke)
    inputs=dict(provider='openai_api',config_id=provider_configuration('openai_api')[1]['config_id'],consent=True,ai_id=str(uuid4()))
    result=runner.investigate_ai(parent.run_id,**inputs)
    assert result['status']==status
    assert result['outcome']['error_code']=='AI_CHECKPOINT_REJECTED'
    assert result['outcome']['payload_sha256'] is None
    assert runner.investigate_ai(parent.run_id,**inputs)==result
    assert len(calls)==1
    assert runner.store._run_path(parent.run_id).read_bytes()==before
