"""Fresh TEST_ONLY provider integration checks; no model/network/CVE claims."""
from copy import deepcopy
import json
import urllib.error

import pytest

from cvevidence_core import ai
from cvevidence_core.assessment import assess
from cvevidence_core.integrity import digest, file_hash, ingest_package, scan, IntegrityError
from cvevidence_core.providers import OpenAIAdapter, ProviderError, ProviderStep
from cvevidence_core.queries import collect_evidence
from cvevidence_core.verifier import verify
from cvevidence_core.workflow import analyze_package, investigate_after_engineering


@pytest.fixture
def case(tmp_path):
    (tmp_path / 'artifact.bin').write_bytes(b'TEST_ONLY AIP contract; never execute')
    (tmp_path / 'observation.txt').write_text('TEST_ONLY submitted observation\nNo operational conclusion.\n')
    manifest = {'schema_version': '1.0', 'package_id': 'aip-contract', 'product_id': 'TEST_ONLY',
                'release_id': 'r1', 'build_id': 'b1', 'format': 'curl',
                'primary_artifact': {'path': 'artifact.bin', 'sha256': file_hash(tmp_path / 'artifact.bin')},
                'files': scan(tmp_path)}
    (tmp_path / 'manifest.json').write_text(json.dumps(manifest))
    context = ingest_package(tmp_path)
    verified = verify(context, collect_evidence(context, 'CVE-2023-38545'))
    return context, verified, assess(context, verified)


def decision(action='LIST', **kwargs):
    data = {name: [] if field['type'] == 'array' else 1 if field['type'] == 'integer' else ''
            for name, field in ai.PROPERTIES.items()}
    return {**data, 'action': action, 'question': 'TEST_ONLY 資料是否足夠？', 'reason': 'TEST_ONLY 核對當案資料', **kwargs}


class SimulatedProvider:
    provider_id = 'codex_cli'
    model = 'TEST_ONLY_CONFIGURED_MODEL'
    reasoning_effort = 'low'
    auth_type = 'chatgpt'
    mode = 'SIMULATED'
    version = 'TEST_ONLY'

    def __init__(self, steps):
        self.steps = steps
        self.seen = []
        self.closed = 0

    def step(self, **kwargs):
        self.seen.append(deepcopy(kwargs))
        item = self.steps[len(self.seen) - 1]
        if isinstance(item, Exception):
            raise item
        item = item(kwargs) if callable(item) else item
        if isinstance(item, ProviderStep):
            return item
        return ProviderStep(item, {'provider': self.provider_id, 'status': 'completed', 'model': None, 'usage': None})

    def close(self):
        self.closed += 1


def run(case, provider, **kwargs):
    context, verified, assessment = case
    before = digest(assessment)
    result = ai.investigate(context, verified, assessment, mode='LIVE', provider=provider, **kwargs)
    assert digest(assessment) == before
    assert result['record_hash'] == digest({key: value for key, value in result.items() if key != 'record_hash'})
    assert provider.closed == 1
    return result


def completed(case, **kwargs):
    return decision('COMPLETE', finding='TEST_ONLY 原始材料仍待工程覆核。',
                    citations=[case[1].records[0]['evidence_id']], **kwargs)


@pytest.mark.parametrize('provider_id', ['openai_api', 'codex_cli'])
def test_both_providers_share_tools_and_history_without_key(case, monkeypatch, provider_id):
    monkeypatch.setattr(ai, 'settings', lambda *args: pytest.fail('Explicit provider must not load API credentials'))
    sid = case[0].by_path('observation.txt')[1]['source_id']
    def finish(kwargs):
        excerpt = kwargs['history'][-1]['result']
        return decision('COMPLETE', finding='TEST_ONLY 已讀原文，意義仍須覆核。', citations=[excerpt['excerpt_id']])
    provider = SimulatedProvider([decision('LIST'), decision('READ', source_ids=[sid], end_line=2), finish])
    provider.provider_id = provider_id
    result = run(case, provider, max_calls=3)
    assert result['schema_version'] == '2.0' and result['provider'] == provider_id
    assert result['mode'] == 'SIMULATED' and result['status'] == 'COMPLETED'
    assert result['model'] == provider.model and all(call['model'] is None for call in result['calls'])
    assert [call['call_number'] for call in result['calls']] == [1, 2, 3]
    assert provider.seen[0]['history'] == []
    assert list(provider.seen[1]['history'][0]) == ['step_number', 'decision', 'result']
    assert provider.seen[2]['history'][1]['result']['text'].startswith('TEST_ONLY')
    assert result['verified_ai_facts'][0]['engineering_inference_verified'] is False
    assert 'context' not in provider.seen[0] and 'root' not in provider.seen[0]['packet']


def test_repair_uses_shared_budget_and_retains_rejected_decision(case):
    invalid = {**completed(case), 'citations': ['X-TEST_ONLY-invalid']}
    provider = SimulatedProvider([invalid, completed(case)])
    result = run(case, provider, max_calls=2)
    assert result['status'] == 'COMPLETED'
    assert result['tasks'][0]['status'] == 'REJECTED'
    assert provider.seen[1]['history'][0]['result']['status'] == 'REJECTED'
    assert provider.seen[1]['budget']['remaining_calls_including_current'] == 1
    assert provider.seen[1]['timeout'] <= provider.seen[0]['timeout']


def test_second_bad_citation_stops_without_extra_call(case):
    invalid = {**completed(case), 'citations': ['X-TEST_ONLY-invalid']}
    provider = SimulatedProvider([invalid, invalid])
    result = run(case, provider, max_calls=4)
    assert result['status'] == 'INVALID_CITATION' and len(provider.seen) == 2


@pytest.mark.parametrize('bad', [decision('SHELL'), {**decision(), 'verdict': 'AFFECTED'}])
def test_provider_cannot_add_actions_or_verdict(case, bad):
    result = run(case, SimulatedProvider([bad]))
    assert result['status'] == 'INVALID_MODEL_OUTPUT' and not result['tasks']


def test_cross_scope_source_is_rejected_by_shared_tool(case):
    result = run(case, SimulatedProvider([decision('READ', source_ids=['../../private'])]))
    assert result['status'] == 'INPUT_CHANGED_OR_INVALID'
    assert result['tasks'][0]['status'] == 'INPUT_CHANGED_OR_INVALID'


@pytest.mark.parametrize('receipt, expected', [
    ({'provider': 'openai_api', 'status': 'completed'}, 'INVALID_MODEL_OUTPUT'),
    ({'provider': 'codex_cli', 'status': 'incomplete'}, 'INCOMPLETE'),
])
def test_receipt_provider_and_completion_are_checked(case, receipt, expected):
    result = run(case, SimulatedProvider([ProviderStep(completed(case), receipt)]))
    assert result['status'] == expected and not result['tasks']


def test_core_packet_and_receipt_limits(case, monkeypatch):
    monkeypatch.setattr(ai, 'MAX_PROVIDER_INPUT_BYTES', 10)
    provider = SimulatedProvider([])
    result = run(case, provider)
    assert result['status'] == 'BUDGET_EXHAUSTED' and not provider.seen
    monkeypatch.setattr(ai, 'MAX_PROVIDER_INPUT_BYTES', 1024 * 1024)
    monkeypatch.setattr(ai, 'MAX_PROVIDER_RECEIPT_BYTES', 10)
    result = run(case, SimulatedProvider([completed(case)]))
    assert result['status'] == 'BUDGET_EXHAUSTED'


def test_preprocessing_consumes_deadline_without_call(case, monkeypatch):
    now = [0.0]
    original = ai.pc_evidence_packet
    def delayed(*args):
        value = original(*args)
        now[0] = 3.0
        return value
    monkeypatch.setattr(ai.time, 'monotonic', lambda: now[0])
    monkeypatch.setattr(ai, 'pc_evidence_packet', delayed)
    provider = SimulatedProvider([])
    result = run(case, provider, timeout_seconds=2, analysis_depth='pc')
    assert result['status'] == 'TIMED_OUT' and not provider.seen


def test_late_response_and_close_failure_cannot_publish_success(case, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(ai.time, 'monotonic', lambda: now[0])
    def late(kwargs):
        now[0] = 3.0
        return completed(case)
    result = run(case, SimulatedProvider([late]), timeout_seconds=2)
    assert result['status'] == 'TIMED_OUT' and not result['tasks']
    now[0] = 0.0
    provider = SimulatedProvider([completed(case)])
    def fail_close():
        provider.closed += 1
        raise RuntimeError('TEST_ONLY private error')
    provider.close = fail_close
    result = run(case, provider)
    assert result['status'] == 'FAILED' and result['errors'][-1]['code'] == 'PROVIDER_CLEANUP_FAILED'
    assert 'private error' not in json.dumps(result)


def test_integrity_failure_still_closes_provider(case):
    assessment = deepcopy(case[2])
    assessment['verdict'] = 'AFFECTED'
    provider = SimulatedProvider([])
    with pytest.raises(IntegrityError):
        ai.investigate(case[0], case[1], assessment, mode='LIVE', provider=provider)
    assert provider.closed == 1 and not provider.seen


def test_structured_provider_error_is_safe_and_no_retry(case):
    provider = SimulatedProvider([ProviderError('FAILED', 'PROVIDER_RATE_OR_QUOTA_LIMIT')])
    result = run(case, provider)
    assert result['status'] == 'FAILED' and len(provider.seen) == 1
    assert result['calls'][0]['model'] is None
    assert result['errors'][0]['code'] == 'PROVIDER_RATE_OR_QUOTA_LIMIT'
    error = ProviderError('SUCCESS', 'TEST_ONLY secret / header')
    assert error.status == 'FAILED' and str(error) == 'PROVIDER_ERROR'


def test_unknown_provider_error_is_safe_and_offline_never_calls(case):
    result = run(case, SimulatedProvider([RuntimeError('TEST_ONLY private runtime detail')]))
    assert result['status'] == 'FAILED' and 'private runtime detail' not in json.dumps(result)
    provider = SimulatedProvider([])
    result = ai.investigate(*case, mode='OFFLINE', provider=provider)
    assert result['status'] == 'OFFLINE' and not provider.seen and provider.closed == 1


def api_response(args, number):
    return {'id': f'TEST_ONLY_RESPONSE_{number}', 'model': 'TEST_ONLY_RESOLVED_MODEL', 'status': 'completed',
            'usage': {'input_tokens': 1, 'output_tokens': 1},
            'output': [{'type': 'function_call', 'name': 'investigation_step',
                        'call_id': f'TEST_ONLY_CALL_{number}', 'arguments': json.dumps(args)}]}


def test_openai_adapter_keeps_native_tool_linkage_and_simulated_mode(case):
    seen = []
    def transport(config, items, timeout):
        seen.append(deepcopy(items))
        return api_response(decision('LIST') if len(seen) == 1 else completed(case), len(seen))
    provider = OpenAIAdapter({'OPENAI_API_KEY': 'TEST_ONLY_SECRET', 'OPENAI_MODEL': 'TEST_ONLY_CONFIGURED_MODEL'}, transport=transport)
    result = ai.investigate(*case, mode='LIVE', provider=provider, max_calls=2)
    assert result['mode'] == 'SIMULATED' and result['status'] == 'COMPLETED'
    assert seen[1][-1]['type'] == 'function_call_output' and seen[1][-1]['call_id'] == 'TEST_ONLY_CALL_1'
    assert json.loads(seen[1][-1]['output'])['sources']
    assert result['model'] == 'TEST_ONLY_CONFIGURED_MODEL'
    assert result['calls'][0]['model'] == 'TEST_ONLY_RESOLVED_MODEL'
    assert result['calls'][0]['response_id'] == 'TEST_ONLY_RESPONSE_1'
    assert 'TEST_ONLY_SECRET' not in json.dumps(result) and provider._closed


@pytest.mark.parametrize('native_error, status, code', [
    (urllib.error.HTTPError('TEST_ONLY', 401, 'secret', {}, None), 'CONFIG_REQUIRED', 'PROVIDER_AUTHENTICATION_FAILED'),
    (urllib.error.HTTPError('TEST_ONLY', 429, 'secret', {}, None), 'FAILED', 'PROVIDER_RATE_OR_QUOTA_LIMIT'),
    (urllib.error.URLError('TEST_ONLY private connection info'), 'CONNECTION_ERROR', 'PROVIDER_CONNECTION_FAILED'),
    (TimeoutError('TEST_ONLY private timeout'), 'TIMED_OUT', 'REQUEST_TIMEOUT'),
])
def test_openai_errors_are_normalized_without_native_text(case, native_error, status, code):
    def transport(*args):
        raise native_error
    provider = OpenAIAdapter({'OPENAI_API_KEY': 'TEST_ONLY_SECRET', 'OPENAI_MODEL': 'TEST_ONLY'}, transport=transport)
    result = ai.investigate(*case, mode='LIVE', provider=provider)
    assert result['status'] == status and result['errors'][0]['code'] == code
    assert 'private' not in json.dumps(result) and 'secret' not in json.dumps(result)


def test_workflow_v2_scope_and_original_bytes_are_preserved(case):
    saved = analyze_package(case[0], [case[1].cve_id])
    original = digest(saved)
    provider = SimulatedProvider([completed(case)])
    result = investigate_after_engineering(case[0], saved, provider=provider, timeout_seconds=30)
    assert result['schema_version'] == '2.0' and result['provider'] == 'codex_cli'
    assert result['mode'] == 'SIMULATED' and result['status'] == 'COMPLETED'
    assert result['analyses'][0]['engineering_assessment_id'] == case[2]['assessment_id']
    assert digest(saved) == original and provider.closed == 1


def test_workflow_validation_failure_closes_without_call(case):
    saved = analyze_package(case[0], [case[1].cve_id])
    saved['context_hash'] = 'TEST_ONLY_WRONG_SCOPE'
    provider = SimulatedProvider([])
    with pytest.raises(IntegrityError):
        investigate_after_engineering(case[0], saved, provider=provider)
    assert provider.closed == 1 and not provider.seen


@pytest.mark.parametrize('stage', ['verify', 'reassessment'])
def test_workflow_pre_and_post_processing_share_deadline(case, monkeypatch, stage):
    from cvevidence_core import workflow
    saved = analyze_package(case[0], [case[1].cve_id])
    now = [0.0]
    monkeypatch.setattr(workflow, 'monotonic', lambda: now[0])
    monkeypatch.setattr(ai.time, 'monotonic', lambda: now[0])
    name = 'verify' if stage == 'verify' else 'reassess_after_investigation'
    original = getattr(workflow, name)
    def delayed(*args):
        value = original(*args)
        now[0] = 3.0
        return value
    monkeypatch.setattr(workflow, name, delayed)
    provider = SimulatedProvider([completed(case)])
    result = investigate_after_engineering(case[0], saved, provider=provider, timeout_seconds=2)
    inner = result['analyses'][0]['ai']
    assert result['status'] == 'INCOMPLETE' and inner['status'] == 'TIMED_OUT'
    assert result['analyses'][0]['investigation_verification'] is None
    assert inner['record_hash'] == digest({key: value for key, value in inner.items() if key != 'record_hash'})
    assert len(provider.seen) == (0 if stage == 'verify' else 1) and provider.closed == 1


def test_openai_private_native_history_is_also_bounded(case, monkeypatch):
    from cvevidence_core import providers
    monkeypatch.setattr(providers, 'MAX_PROVIDER_INPUT_BYTES', 10)
    provider = OpenAIAdapter({'OPENAI_API_KEY': 'TEST_ONLY', 'OPENAI_MODEL': 'TEST_ONLY'},
                             transport=lambda *args: pytest.fail('Oversized input must not call the model'))
    result = ai.investigate(*case, mode='LIVE', provider=provider)
    assert result['status'] == 'BUDGET_EXHAUSTED' and provider._closed

@pytest.mark.parametrize('provider_id',['openai_api','codex_cli'])
def test_shared_token_threshold_handles_nullable_total(case,provider_id):
    from cvevidence_core.investigation_control import control
    receipt={'provider':provider_id,'status':'completed','model':None,
             'usage':{'input_tokens':900,'output_tokens':200,'total_tokens':None}}
    provider=SimulatedProvider([ProviderStep(decision('LIST'),receipt)])
    provider.provider_id=provider_id
    token=control.set({'token_limit':1000})
    try:result=run(case,provider,max_calls=3)
    finally:control.reset(token)
    assert result['status']=='BUDGET_EXHAUSTED'
    assert len(provider.seen)==1
    assert result['usage_summary']['total_tokens']==1100
    assert result['calls'][0]['usage']['total_tokens'] is None
