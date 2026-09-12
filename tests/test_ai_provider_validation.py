"""TEST_ONLY harness controls/receipt fixtures; these tests never call a model."""
from copy import deepcopy
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

from scripts import validate_ai_providers as validation
from cvevidence_core.integrity import digest


def receipt_fixture(provider='codex_cli', *, mode='LIVE', action='LIST'):
    """Synthetic native-looking fields test validation logic, not real LIVE."""
    ai_id, parent_id = str(uuid4()), str(uuid4())
    request = {'schema_version': '2.0', 'ai_id': ai_id, 'parent_run_id': parent_id,
        'engineering_payload_sha256': '1' * 64, 'context_hash': '2' * 64, 'cve_id': validation.CVE,
        'assessment_id': 'A-TEST_ONLY', 'requested_mode': 'LIVE', 'consent': True,
        'context_text_sha256': validation.digest(validation.CONTEXT.encode()), 'model': 'TEST_ONLY',
        'reasoning_effort': 'low', 'created_at': 'TEST_ONLY', 'timeout_seconds': 180.0,
        'provider': provider, 'auth_type': 'chatgpt' if provider == 'codex_cli' else 'api_key', 'config_id': '3' * 64}
    native = {'provider': provider, 'call_number': 1, 'status': 'completed', 'model': None, 'usage': None}
    if provider == 'codex_cli':
        native.update(thread_id='TEST_ONLY_THREAD', exit_code=0, terminal_event='turn.completed', events_sha256='4' * 64)
    else:
        native['response_id'] = 'TEST_ONLY_RESPONSE'
    tasks = [{'action': action, 'status': 'COMPLETED', 'citation_verification': {'valid': True}},
             {'action': 'ASK_USER', 'status': 'COMPLETED', 'citation_verification': {'valid': True},
              'finding': 'TEST_ONLY PC1 待覆核；PC2 待覆核；PC3 缺件。', 'citations': ['E-TEST_ONLY'],
              'required_files': ['TEST_ONLY 同成品原始觀測']}]
    inner = {'schema_version': '2.0', 'provider': provider, 'auth_type': request['auth_type'], 'mode': mode,
             'status': 'NEEDS_USER_INPUT', 'context_hash': request['context_hash'], 'cve_id': validation.CVE,
             'engineering_assessment_id': request['assessment_id'], 'model': request['model'],
             'adapter_version': 'TEST_ONLY', 'calls': [native], 'tasks': tasks}
    inner['record_hash'] = digest(inner)
    payload = {'schema_version': '2.0', 'context_hash': request['context_hash'], 'mode': mode,
               'status': 'COMPLETED', 'analyses': [{'cve_id': validation.CVE,
                 'engineering_assessment_id': request['assessment_id'], 'ai': inner}]}
    record = {'request': request, 'status': 'NEEDS_USER_INPUT', 'outcome': None, 'result': payload}
    expected = {'parent_run_id': parent_id, 'context_hash': request['context_hash'],
                'assessment_id': request['assessment_id'], 'provider': provider,
                'config_id': request['config_id'], 'model': request['model'], 'flow': 2}
    return record, expected


@pytest.mark.parametrize('provider', validation.PROVIDERS)
def test_record_contract_preserves_unknown_usage_and_human_review(provider):
    record, expected = receipt_fixture(provider)
    checks, details = validation.record_checks(record, **expected)
    assert all(checks.values())
    assert details['actual_models'] == [] and details['usage']['totals']['input_tokens'] is None
    assert details['human_review'] == 'NOT_RUN' and details['semantic_support_verified'] is False


@pytest.mark.parametrize('change, failed_check', [
    ('simulated', 'live_completed'), ('no_source_tool', 'codex_source_operation'),
    ('bad_receipt', 'saved_schema_scope_and_native_receipts'), ('wrong_scope', 'original_engineering_parent'),
    ('invalid_citation', 'completed_task_citations'),
])
def test_acceptance_never_upgrades_missing_or_simulated_evidence(change, failed_check):
    record, expected = receipt_fixture(mode='SIMULATED' if change == 'simulated' else 'LIVE',
                                       action='VERIFY' if change == 'no_source_tool' else 'LIST')
    inner = record['result']['analyses'][0]['ai']
    if change == 'bad_receipt':
        inner['calls'][0]['terminal_event'] = 'turn.started'
    elif change == 'wrong_scope':
        expected['context_hash'] = '5' * 64
    elif change == 'invalid_citation':
        inner['tasks'][-1]['citation_verification']['valid'] = False
    inner['record_hash'] = digest({key: value for key, value in inner.items() if key != 'record_hash'})
    checks, _ = validation.record_checks(record, **expected)
    assert checks[failed_check] is False


@pytest.mark.parametrize('consent, ready, reason', [(False, True, 'CONSENT_REQUIRED'), (True, False, 'CODEX_ADAPTER_UNAVAILABLE')])
def test_missing_consent_or_readiness_never_invokes_model(monkeypatch, consent, ready, reason):
    monkeypatch.setattr(validation, '_configuration', lambda provider: {'configured': ready, 'reason_code': reason})
    runner = SimpleNamespace(investigate_ai=lambda *args, **kwargs: pytest.fail('Model must not be invoked'))
    row = validation.provider_case(runner, {'archive_sha256': '1' * 64}, 'codex_cli', consent,
                                   {'source_sha256': '2' * 64, 'prompt_version': 'TEST_ONLY'})
    assert row['status'] == 'NOT_RUN' and row['reason_code'] == reason and row['ai_id'] is None


def test_usage_missing_values_are_not_counted_as_zero():
    usage = validation.usage_summary([{'usage': {'input_tokens': 10, 'output_tokens': 2}}, {'usage': None}])
    assert usage['totals']['input_tokens'] is None and usage['totals']['output_tokens'] is None
    assert usage['calls_with_reported_tokens'] == 1
    assert validation.aggregate(['PASS', 'NOT_RUN']) == 'NOT_RUN'
    assert validation.aggregate(['NOT_RUN', 'FAIL']) == 'FAIL'


def test_harness_controls_each_provider_and_case_independently(tmp_path, monkeypatch):
    calls = []
    versions = {'source_sha256': '1' * 64, 'source_files': {}, 'prompt_version': 'TEST_ONLY'}
    monkeypatch.setattr(validation, 'code_version', lambda: deepcopy(versions))
    monkeypatch.setattr(validation, 'source_inventory', lambda: {})
    def engineering(entry, flow, output):
        return None, {'flow': flow}, {'status': 'PASS'}
    monkeypatch.setattr(validation, 'engineering_case', engineering)
    def provider_case(runner, baseline, name, consent, metadata):
        calls.append((baseline['flow'], name, consent))
        return {'provider': name, 'status': 'NOT_RUN' if name == 'openai_api' else 'PASS', 'human_review': 'NOT_RUN'}
    monkeypatch.setattr(validation, 'provider_case', provider_case)
    report = validation.execute(tmp_path / 'run', provider='all', consent=True)
    assert calls == [(1, 'openai_api', True), (1, 'codex_cli', True), (2, 'openai_api', True), (2, 'codex_cli', True)]
    assert report['status'] == 'NOT_RUN' and report['providers']['codex_cli']['status'] == 'PASS'
    assert report['providers']['openai_api']['automated_success_rate'] is None
    assert report['human_review'] == 'NOT_RUN'
    saved = json.loads((tmp_path / 'run/summary.json').read_text())
    assert saved == report and (tmp_path / 'run/.gitignore').read_text() == '*\n'
    with pytest.raises(FileExistsError):
        validation.execute(tmp_path / 'run')


def test_engineering_failure_blocks_only_that_case(tmp_path, monkeypatch):
    monkeypatch.setattr(validation, 'code_version', lambda: {'source_sha256': '1' * 64, 'source_files': {}, 'prompt_version': 'TEST_ONLY'})
    monkeypatch.setattr(validation, 'source_inventory', lambda: {})
    def engineering(entry, flow, output):
        if flow == 1:
            raise ValueError('TEST_ONLY failure')
        return None, {}, {'status': 'PASS'}
    monkeypatch.setattr(validation, 'engineering_case', engineering)
    monkeypatch.setattr(validation, 'provider_case', lambda *args: {'provider': 'codex_cli', 'status': 'NOT_RUN'})
    report = validation.execute(tmp_path / 'run', provider='codex_cli')
    assert report['status'] == 'FAIL'
    assert report['cases'][0]['providers'][0]['reason_code'] == 'ENGINEERING_NOT_READY'
    assert report['cases'][1]['engineering']['status'] == 'PASS'


def test_live_invocation_failure_preserves_material_checks(tmp_path, monkeypatch):
    run_id = str(uuid4())
    envelope = tmp_path / 'envelope.json'
    envelope.write_bytes(b'TEST_ONLY envelope')
    archive = tmp_path / 'archive.bin'
    archive.write_bytes(b'TEST_ONLY archive')
    store = SimpleNamespace(root=tmp_path, _run_path=lambda _: envelope, read_blob=lambda _: b'TEST_ONLY blob')
    def failed(*args, **kwargs):
        raise RuntimeError('TEST_ONLY private error that must not be logged')
    runner = SimpleNamespace(store=store, investigate_ai=failed)
    baseline = {'run': SimpleNamespace(run_id=run_id, engineering_payload_sha256='1' * 64),
        'envelope': b'TEST_ONLY envelope', 'blob': b'TEST_ONLY blob', 'archive_path': archive,
        'archive_sha256': validation.file_hash(archive)}
    monkeypatch.setattr(validation, '_configuration', lambda _: {'configured': True, 'config_id': '2' * 64})
    row = validation.provider_case(runner, baseline, 'codex_cli', True,
                                   {'source_sha256': '3' * 64, 'prompt_version': 'TEST_ONLY'})
    assert row['status'] == 'FAIL' and row['reason_code'] == 'VALIDATION_EXECUTION_OR_REOPEN_FAILED'
    assert all(row['checks'].values()) and 'private error' not in json.dumps(row)
