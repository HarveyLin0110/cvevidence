"""TEST_ONLY UI contracts and simulated records; no model/network or LIVE claims."""
from copy import deepcopy
from types import SimpleNamespace
import pytest
from streamlit.testing.v1 import AppTest
from cvevidence.ai_presenter import attempt_metadata, metadata_lines, receipt_lines
from cvevidence.ai_workspace import with_ai_result
from cvevidence.analysis_report import export_analysis

RUN = "00000000-0000-4000-8000-000000000001"


def fake_run(run_id=RUN):
    return SimpleNamespace(run_id=run_id, cve_id="CVE-2099-0001",
                           input_package=SimpleNamespace(context_hash="test-scope-" + run_id))


def fake_engineering(run_id=RUN):
    scope = fake_run(run_id).input_package.context_hash
    return {"context_hash": scope, "analyses": [{"cve_id": "CVE-2099-0001", "status": "COMPLETED",
        "assessment": {"assessment_id": "A-" + run_id, "context_hash": scope, "cve_id": "CVE-2099-0001",
                       "verdict": "NEEDS_INVESTIGATION", "conditions": [], "reason": "TEST_ONLY"},
        "ai": {"context_hash": scope, "cve_id": "CVE-2099-0001", "engineering_assessment_id": "A-" + run_id,
               "mode": "OFFLINE", "status": "OFFLINE", "tasks": []}}]}


class FakeRunner:
    def __init__(self):
        self.config = {"default_provider": "openai_api", "providers": {
            provider: {"provider": provider, "configured": True, "reason_code": None,
                       "model": provider + "_TEST_ONLY", "reasoning_effort": "medium",
                       "auth_type": auth, "config_id": char * 64, "billing_label": "", "version": "TEST_ONLY"}
            for provider, auth, char in (("openai_api", "api_key", "a"), ("codex_cli", "chatgpt", "b"))}}
        self.calls = []
        self.records = {}
        self.status = "NEEDS_USER_INPUT"
        self.wrong_parent = False

    def ai_configuration(self):
        return deepcopy(self.config)

    def investigate_ai(self, parent_run_id, **kwargs):
        if kwargs["ai_id"] in self.records:
            return deepcopy(self.records[kwargs["ai_id"]])
        self.calls.append((parent_run_id, deepcopy(kwargs)))
        provider = kwargs.get("provider", "openai_api")
        public = self.config.get("providers", {}).get(provider, self.config)
        if "providers" in self.config:
            assert kwargs["config_id"] == public["config_id"]
        request = {"schema_version": "2.0" if "providers" in self.config else "1.0",
                   "ai_id": kwargs["ai_id"], "parent_run_id": parent_run_id,
                   "created_at": "2026-09-13T00:00:00Z", "model": public["model"],
                   "context_hash": fake_run(parent_run_id).input_package.context_hash,
                   "cve_id": "CVE-2099-0001", "assessment_id": "A-" + parent_run_id}
        if "providers" in self.config:
            request.update(provider=provider, auth_type=public["auth_type"], config_id=public["config_id"])
        ai = dict(fake_engineering(parent_run_id)["analyses"][0]["ai"], mode="SIMULATED", status=self.status,
                  provider=provider, model=public["model"], record_hash="TEST_ONLY_SAVED_HASH",
                  calls=[{"thread_id": "TEST_ONLY_THREAD", "terminal_event": "turn.completed", "exit_code": 0,
                          "model": None, "usage": None}] if provider == "codex_cli" else
                        [{"response_id": "TEST_ONLY_RESPONSE", "model": "TEST_ONLY_REPORTED", "usage": None}])
        record = {"request": request, "status": self.status, "outcome": {"error_code": None},
                  "result": {"analyses": [{"ai": ai}]} if self.status == "NEEDS_USER_INPUT" else None}
        if self.wrong_parent:
            record["request"]["parent_run_id"] = "other-run"
        self.records[kwargs["ai_id"]] = deepcopy(record)
        return record

    def read_ai(self, ai_id):
        return deepcopy(self.records[ai_id])

    def ai_history(self, run_id):
        return [deepcopy(record) for record in self.records.values() if record["request"]["parent_run_id"] == run_id], []


def app_for(config=None):
    source = '''import streamlit as st
from tests.test_ai_provider_ui import FakeRunner, fake_run, fake_engineering, RUN
from cvevidence.ai_workspace import ai_workspace
if "test-runner" not in st.session_state: st.session_state["test-runner"] = FakeRunner()
run_id = st.session_state.get("test-run", RUN)
ai_workspace(st, st.session_state["test-runner"], fake_run(run_id), fake_engineering(run_id))
'''
    app = AppTest.from_string(source, default_timeout=15)
    if config is not None:
        runner = FakeRunner()
        runner.config = config
        app.session_state["test-runner"] = runner
    return app.run()


def button(app, label="開始 AI 調查"):
    return next(item for item in app.button if item.label == label)


def selector(app, label="AI 執行來源"):
    return next(item for item in app.selectbox if item.label == label)


def displayed(app):
    return "\n".join(str(item.value) for kind in (app.text, app.caption, app.info, app.warning, app.error, app.code) for item in kind)


def submit(app):
    app.checkbox[0].check()
    button(app).click().run()
    assert not app.exception


def test_unavailable_default_never_falls_back_and_explains_account_billing():
    app = app_for()
    runner = app.session_state["test-runner"]
    runner.config["providers"]["openai_api"].update(configured=False, reason_code="API_KEY_MISSING")
    app.run()
    assert not app.exception and button(app).disabled
    assert selector(app).value == "openai_api"
    assert "API_KEY_MISSING" in displayed(app) and "API 計費帳號" in displayed(app)
    selector(app).select("codex_cli").run()
    assert not button(app).disabled
    assert "後端 ChatGPT 登入帳號" in displayed(app) and not runner.calls


def test_removed_provider_stays_unavailable_instead_of_switching_accounts():
    app = app_for()
    runner = app.session_state["test-runner"]
    selector(app).select("codex_cli").run()
    del runner.config["providers"]["codex_cli"]
    app.run()
    assert not app.exception and selector(app).value == "codex_cli" and button(app).disabled
    assert not runner.calls


def test_unknown_default_requires_explicit_selection_without_api_fallback():
    config = FakeRunner().config
    config["default_provider"] = "TEST_ONLY_UNKNOWN_PROVIDER"
    app = app_for(config)
    assert not app.exception and button(app).disabled
    assert selector(app).value == "__invalid_default__"
    assert "預設來源設定無效" in displayed(app)
    selector(app).select("openai_api").run()
    assert not app.exception and not button(app).disabled
    assert not app.session_state["test-runner"].calls


@pytest.mark.parametrize("change", ["provider", "question", "config", "model", "auth"])
def test_changed_consent_identity_rotates_token_and_requires_new_consent(change):
    app = app_for()
    runner = app.session_state["test-runner"]
    submit(app)
    previous = app.session_state["ai-token-" + RUN]
    if change == "provider":
        selector(app).select("codex_cli").run()
    elif change == "question":
        app.text_area[0].input("TEST_ONLY changed question").run()
    else:
        field, changed = {"config": ("config_id", "c" * 64), "model": ("model", "TEST_ONLY_NEW"),
                          "auth": ("auth_type", "TEST_ONLY_CHANGED")}[change]
        runner.config["providers"]["openai_api"][field] = changed
        app.run()
    assert not app.exception and not app.checkbox[0].value
    assert app.session_state["ai-token-" + RUN] != previous
    button(app).click().run()
    assert len(runner.calls) == 1


def test_provider_round_trip_does_not_restore_old_consent():
    app = app_for()
    submit(app)
    old_token = app.session_state["ai-token-" + RUN]
    selector(app).select("codex_cli").run()
    selector(app).select("openai_api").run()
    assert not app.checkbox[0].value
    assert app.session_state["ai-token-" + RUN] != old_token


def test_case_round_trip_requires_new_consent_and_keeps_case_history():
    app = app_for()
    submit(app)
    old_token = app.session_state["ai-token-" + RUN]
    app.session_state["test-run"] = "00000000-0000-4000-8000-000000000002"
    app.run()
    assert not app.checkbox[0].value
    assert all(item.label != "本工程結果的 AI 調查紀錄" for item in app.selectbox)
    app.session_state["test-run"] = RUN
    app.run()
    assert not app.checkbox[0].value and app.session_state["ai-token-" + RUN] != old_token
    assert selector(app, "本工程結果的 AI 調查紀錄")


def test_provider_route_idempotency_and_explicit_new_attempt():
    app = app_for()
    runner = app.session_state["test-runner"]
    button(app).click().run()
    assert not runner.calls
    selector(app).select("codex_cli").run()
    submit(app)
    _, call = runner.calls[0]
    assert call["provider"] == "codex_cli" and call["config_id"] == "b" * 64
    assert call["timeout"] == 180 and call["consent"] is True
    assert not {"model", "cli_path", "auth_type"} & call.keys()
    button(app).click().run()
    assert len(runner.calls) == 1
    button(app, "建立新的 AI 調查").click().run()
    assert not app.checkbox[0].value
    submit(app)
    assert len(runner.calls) == 2 and runner.calls[0][1]["ai_id"] != runner.calls[1][1]["ai_id"]


def test_failed_attempt_stays_visible_without_fallback_or_automatic_retry():
    app = app_for()
    runner = app.session_state["test-runner"]
    runner.status = "FAILED"
    selector(app).select("codex_cli").run()
    submit(app)
    app.run()
    button(app).click().run()
    assert len(runner.calls) == 1 and "FAILED" in displayed(app)
    assert runner.calls[0][1]["provider"] == "codex_cli"
    assert len(runner.records) == 1


def test_wrong_parent_result_cannot_change_selection():
    app = app_for()
    runner = app.session_state["test-runner"]
    runner.wrong_parent = True
    submit(app)
    assert app.error and "selected-ai-" + RUN not in app.session_state
    assert len(runner.calls) == 1


def test_history_and_report_use_saved_provider_not_current_selector():
    app = app_for()
    runner = app.session_state["test-runner"]
    selector(app).select("codex_cli").run()
    submit(app)
    record = next(iter(runner.records.values()))
    before = deepcopy(record)
    selector(app).select("openai_api").run()
    selector(app, "本工程結果的 AI 調查紀錄").select(record["request"]["ai_id"]).run()
    assert len(runner.calls) == 1 and "Thread ID：TEST_ONLY_THREAD" in displayed(app)
    assert "實際回報模型：未知" in displayed(app) and "Usage：未知" in displayed(app)
    original = fake_engineering()
    report_payload = with_ai_result(original, record)
    report = export_analysis(report_payload, context_hash=original["context_hash"], cve_id="CVE-2099-0001", run_id=RUN)
    assert "執行來源：Codex CLI" in report and "Response ID" not in report
    assert record == before and original == fake_engineering()
    assert report_payload["analyses"][0]["ai"]["record_hash"] == "TEST_ONLY_SAVED_HASH"


def test_legacy_configuration_keeps_old_call_contract_and_labels_saved_v1():
    app = app_for()
    runner = app.session_state["test-runner"]
    runner.config = {"configured": True, "model": "TEST_ONLY_LEGACY", "provider": "OpenAI", "mode": "LIVE"}
    app.run()
    submit(app)
    assert not {"provider", "config_id"} & runner.calls[0][1].keys()
    assert "舊版 OpenAI API" in displayed(app)


def test_failed_report_metadata_and_scope_are_checked_without_rewriting_engineering():
    runner = FakeRunner()
    runner.status = "FAILED"
    record = runner.investigate_ai(RUN, provider="codex_cli", config_id="b" * 64, ai_id="TEST_ONLY")
    original = fake_engineering()
    report = with_ai_result(original, record)
    assert report["analyses"][0]["ai_attempt"]["provider"] == "codex_cli"
    text = export_analysis(report, context_hash=original["context_hash"], cve_id="CVE-2099-0001", run_id=RUN)
    assert "調查狀態：FAILED" in text and "OFFLINE" not in text
    assert original == fake_engineering()
    record["request"]["context_hash"] = "other-scope"
    with pytest.raises(ValueError, match="scope"):
        with_ai_result(original, record)


def test_unknown_history_identity_and_literal_metadata_are_not_inferred():
    assert attempt_metadata(request={"schema_version": "99.0", "model": "TEST_ONLY"})["provider_label"] == "未知來源"
    marker = '<script>TEST_ONLY</script> ![image](https://example.invalid/private)'
    metadata = attempt_metadata({"provider": "codex_cli", "model": marker, "calls": [{"model": None}]})
    assert metadata["actual_model"] is None and marker in "\n".join(metadata_lines(metadata))
    assert "Response ID" not in "\n".join(receipt_lines({"exit_code": 0}, "codex_cli"))
