"""Bounded AI checks with separate mock, native Live, and live-API fault injection records."""
from __future__ import annotations
import argparse
import copy
import datetime
import json
import pathlib
import shutil
import time
from unittest.mock import patch
import sys
import unittest
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from cvevidence_core import ai
from cvevidence_core.assessment import assess
from cvevidence_core.integrity import digest, file_hash, ingest_package, safe_extract, scan
from cvevidence_core.queries import collect_evidence
from cvevidence_core.verifier import verify, verify_citations
from cvevidence_core.supplements import interpret_statement, validate_supplement
from cvevidence_core.workflow import analyze_package, investigate_after_engineering

CASES = {
    'missing': ('09_curl', '更新下載經 SOCKS5，偶爾握手慢。我不知道 DNS 在哪裡解析，請先查現有資料，再指出最小缺件。不要把尚未提供的執行設定當成已知事實。'),
    'early': ('07_curl', 'launcher、download.conf 與正常 SOCKS5 觀測已經在提交資料中。請直接檢查現有原文的 DNS、傳輸速率設定與握手觀測；分開說明程式有受影響條件和正常測試是否已重現漏洞。'),
}


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n')


def run_mock(folder):
    suite = unittest.defaultTestLoader.discover(str(ROOT/'tests'), pattern='test_ai_reliability.py')
    with (folder/'unittest.log').open('w') as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    summary = {'validation_kind': 'MOCK_TRANSPORT', 'formal_live_eligible': False, 'api_calls': 0,
               'tests_run': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
               'passed': result.wasSuccessful()}
    write_json(folder/'summary.json', summary)
    return summary['passed']


def run_live(folder, options):
    # Only the existing trusted config reader touches the key; never serialize config.
    try:
        config = ai.settings(options.env_file)
        configured = bool(config.get('OPENAI_API_KEY') and config.get('OPENAI_MODEL'))
    except (OSError, UnicodeError):
        configured = False
    if not configured:
        write_json(folder/'summary.json', {'status': 'CONFIG_REQUIRED', 'api_calls': 0, 'passed': False})
        return False
    catalog = json.loads((ROOT/'demo-inputs/catalog.json').read_text())
    selected = list(CASES) if options.case == 'all' else [options.case]
    rows = []
    for name in selected:
        package, user_context = CASES[name]
        catalog_entry = next(x for x in catalog['packages'] if x['package_id'] == package)
        archive = ROOT/catalog_entry['archive']['repo_path']
        if file_hash(archive) != catalog_entry['archive']['sha256']:
            raise ValueError('Demo archive hash mismatch')
        case_folder = folder/name
        case_folder.mkdir()
        unpacked = case_folder/'input'
        safe_extract(archive, unpacked)
        manifests = list(unpacked.rglob('manifest.json'))
        if len(manifests) != 1:
            raise ValueError('Expected exactly one input manifest')
        context = ingest_package(manifests[0].parent, expected_manifest_hash=catalog_entry['manifest_sha256'])
        verified = verify(context, collect_evidence(context, 'CVE-2023-38545'))
        assessment = assess(context, verified)
        assessment_before = digest(assessment)
        fault = {'validation_kind': 'LIVE_API_FAULT_INJECTION', 'formal_live_eligible': False,
                 'note': '每次模型回應均來自真實 API；僅首次回應的 citations 被測試程式改成不存在的 ID。調查依既有 API 標為 SIMULATED，不計正式 Live。',
                 'api_responses': [], 'injected': False}

        def fault_transport(config, items, timeout):
            original = ai._request(config, items, timeout)
            fault['api_responses'].append({'response_id': original.get('id'), 'status': original.get('status'),
                                           'model': original.get('model'), 'usage': original.get('usage')})
            changed = copy.deepcopy(original)
            calls = [x for x in changed.get('output', []) if x.get('type') == 'function_call']
            if not fault['injected'] and original.get('status') == 'completed' and len(calls) == 1:
                args = json.loads(calls[0]['arguments'])
                fault['original_arguments'] = copy.deepcopy(args)
                args['citations'] = ['X-validation-invalid-reference']
                fault['injected_arguments'] = args
                calls[0]['arguments'] = json.dumps(args, ensure_ascii=False)
                fault['injected'] = True
            write_json(case_folder/'fault-injection.json', fault)
            return changed

        injected = options.mode == 'live-fault'
        investigation = ai.investigate(context, verified, assessment, user_context, mode='LIVE',
                                       env_file=options.env_file, max_calls=options.max_calls,
                                       timeout_seconds=options.timeout_seconds,
                                       transport=fault_transport if injected else None)
        record = {'validation_kind': 'LIVE_API_FAULT_INJECTION' if injected else 'NATIVE_LIVE',
                  'formal_live_eligible': not injected, 'context_hash': context.context_hash,
                  'assessment': assessment, 'ai': investigation}
        write_json(case_folder/'result.json', record)
        completed = [t for t in investigation['tasks'] if t['status'] == 'COMPLETED']
        citation_gate = all(t['citation_verification']['valid'] and t['source_grounding']['valid'] for t in completed)
        recovery = investigation.get('rejected_proposals', 0) > 0 and investigation['status'] in ('COMPLETED', 'NEEDS_USER_INPUT')
        row = {'case': name, 'package_id': package, 'validation_kind': record['validation_kind'],
               'formal_live_eligible': not injected, 'mode': investigation['mode'],
               'model': investigation['model'], 'reasoning_effort': investigation['reasoning_effort'],
               'status': investigation['status'], 'elapsed_seconds': investigation['elapsed_seconds'],
               'api_attempts': len(investigation['calls']), 'actions': [t['action'] for t in investigation['tasks']],
               'rejected_proposals': investigation.get('rejected_proposals', 0), 'accepted_citations_valid': citation_gate,
               'engineering_unchanged': digest(assessment) == assessment_before,
               'fault_injected': fault['injected'] if injected else False,
               'recovery_observed': recovery if injected else None,
               'semantic_review': '待人工核對問題、結論與原文；此 gate 不把引用存在當語意正確。'}
        row['passed'] = (investigation['status'] in ('COMPLETED', 'NEEDS_USER_INPUT') and citation_gate
                         and row['engineering_unchanged'] and bool(investigation['calls'])
                         and investigation['mode'] == ('SIMULATED' if injected else 'LIVE')
                         and (not injected or (fault['injected'] and recovery)))
        rows.append(row)
        write_json(folder/'summary.json', rows)
        print(json.dumps(row, ensure_ascii=False), flush=True)
    return all(row['passed'] for row in rows)



R2_BASE = '44efc7bdcc533760ab167a2a005b0111b9758483'
R2_CVE = 'CVE-2014-0160'
R2_QUESTION = ('已補齊同一 ROM 的 SDK/source、每個 object 的編譯與預處理材料。'
               '請查看現有原文，核對 heartbeat 函式與 TLS record dispatch 兩處的排除是否一致，'
               '並分開說明這項建置結論與實際部署是否暴露；不要重複要求已提交材料。')


def prepare_rom_r2(folder):
    """Make only QA snapshots from today's original archives, not new products."""
    catalog = json.loads((ROOT/'demo-inputs/catalog.json').read_text())
    packages = {}
    for package in ['03_rom', 'supplement_03_rom']:
        entry = next(x for x in catalog['packages'] if x['package_id'] == package)
        archive = ROOT/entry['archive']['repo_path']
        if file_hash(archive) != entry['archive']['sha256']:
            raise ValueError('ROM archive hash mismatch')
        target = folder/package
        safe_extract(archive, target)
        if file_hash(target/'manifest.json') != entry['manifest_sha256']:
            raise ValueError('ROM manifest hash mismatch')
        packages[package] = target
    base = ingest_package(packages['03_rom'])
    history = interpret_statement('已提供這次使用的檔案，請查核。', base.context_hash)
    before = analyze_package(base, [R2_CVE], statements=[history], mode='OFFLINE')
    write_json(folder/'engineering-before-supplement.json', before)
    plan = validate_supplement(base, packages['supplement_03_rom'])
    write_json(folder/'supplement-plan.json', plan)
    if not plan['can_merge']:
        raise ValueError('Same-build ROM supplement was rejected')
    merged = folder/'rom-supplemented'
    shutil.copytree(base.root, merged, symlinks=True)
    for row in plan['added_files']:
        target = merged/row['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        if row['kind'] == 'symlink':
            target.symlink_to(row['target'])
        else:
            shutil.copy2(packages['supplement_03_rom']/row['path'], target)
    manifest = copy.deepcopy(base.manifest)
    manifest['files'] = scan(merged)
    write_json(merged/'manifest.json', manifest)
    context = ingest_package(merged)
    engineering = analyze_package(context, [R2_CVE], statements=[history], mode='OFFLINE')
    write_json(folder/'engineering-saved.json', engineering)
    assessment = engineering['analyses'][0]['assessment']
    checks = {
        'partial_needs_investigation': before['analyses'][0]['assessment']['verdict'] == 'NEEDS_INVESTIGATION',
        'supplement_not_affected': assessment['verdict'] == 'NOT_AFFECTED',
        'same_artifact': context.manifest['primary_artifact'] == base.manifest['primary_artifact'],
        'same_build': context.manifest['build_id'] == base.manifest['build_id'],
        'new_context': context.context_hash != base.context_hash,
        'history_source_retained': assessment['statement_context'][0]['source_context_hash'] == base.context_hash,
        'history_material_retained': assessment['statement_context'][0]['statement_id'] == history['material_id'],
        'history_assessed_on_new_context': assessment['statement_context'][0]['assessed_context_hash'] == context.context_hash,
        'neutral_does_not_block': not assessment['statement_reviews'] and not assessment['statement_context'][0]['blocks_verdict'],
    }
    write_json(folder/'engineering-readiness.json', {'checks': checks, 'status': 'PASS' if all(checks.values()) else 'FAIL'})
    if not all(checks.values()):
        raise AssertionError('ROM engineering/history readiness failed; see engineering-readiness.json')
    print(json.dumps({'stage': 'ENGINEERING_READY', 'status': 'PASS', 'checks': len(checks),
                      'assessment_id': assessment['assessment_id'], 'verdict': assessment['verdict']}, ensure_ascii=False), flush=True)
    return context, engineering


def _r2_mock_transport(context, scenario):
    source_id = context.by_path('build/build-record.json')[1]['source_id']
    attempts = []
    def transport(config, items, timeout):
        attempts.append(len(items))
        if len(attempts) > 1 and scenario == 'timeout':
            raise TimeoutError('QA simulated timeout')
        args = {k: [] if value['type'] == 'array' else 1 if value['type'] == 'integer' else ''
                for k, value in ai.PROPERTIES.items()}
        args.update(action='READ', question='同 build 紀錄提供哪些原文？', reason='驗證失敗前已取得的原文仍保留',
                    source_ids=[source_id], end_line=60)
        if len(attempts) > 1:
            args.update(action='COMPLETE', source_ids=[], finding='此無效引用不得成功完成。', citations=['X-r2-invalid-reference'])
        return {'id': 'SIMULATED-R2-'+str(len(attempts)), 'model': 'SIMULATED_ONLY', 'status': 'completed',
                'output': [{'type': 'function_call', 'name': 'investigation_step', 'call_id': 'r2-'+str(len(attempts)),
                            'arguments': json.dumps(args, ensure_ascii=False)}]}
    return transport


def run_r2_case(folder, context, engineering, scenario, env_file, question=R2_QUESTION):
    case_folder = folder/scenario
    case_folder.mkdir()
    write_json(case_folder/'request-context.json', {'user_context': question, 'max_calls': 8, 'timeout_seconds': 90})
    simulated = scenario != 'live'
    original = copy.deepcopy(engineering)
    saved_hash = file_hash(folder/'engineering-saved.json')
    events = []
    def event_callback(event):
        events.append(event)
        write_json(case_folder/'events.json', events)
    started = time.monotonic()
    try:
        if simulated:
            transport = _r2_mock_transport(context, scenario)
            original_investigate = ai.investigate
            def injected(*args, **kwargs):
                return original_investigate(*args, **kwargs, transport=transport)
            with patch('cvevidence_core.workflow.investigate', side_effect=injected), \
                 patch('cvevidence_core.ai.settings', return_value={'OPENAI_API_KEY': 'TEST_NOT_A_KEY', 'OPENAI_MODEL': 'SIMULATED_ONLY'}), \
                 patch('cvevidence_core.ai._request', side_effect=AssertionError('Mock must not call network')):
                later = investigate_after_engineering(context, engineering, question, event_callback=event_callback)
        else:
            later = investigate_after_engineering(context, engineering, question, env_file=env_file, event_callback=event_callback)
    except Exception as exc:
        row = {'scenario': scenario, 'status': 'FAIL', 'exception_type': type(exc).__name__, 'message': str(exc),
               'engineering_dict_unchanged': engineering == original,
               'saved_engineering_file_unchanged': file_hash(folder/'engineering-saved.json') == saved_hash,
               'elapsed_seconds': round(time.monotonic()-started, 3)}
        write_json(case_folder/'exception.json', row)
        return row
    elapsed = round(time.monotonic()-started, 3)
    write_json(case_folder/'later-result.json', later)
    investigation = later['analyses'][0]['ai']
    followup = later['analyses'][0]['investigation_verification']
    write_json(case_folder/'ai-record.json', investigation)
    write_json(case_folder/'reassessment.json', followup)
    write_json(case_folder/'engineering-after-ai.json', engineering)
    verified = verify(context, collect_evidence(context, R2_CVE))
    completed = [t for t in investigation['tasks'] if t['status'] == 'COMPLETED']
    citation_checks = [verify_citations(context, verified, t['citations'], investigation['excerpts']) for t in completed]
    write_json(case_folder/'citation-rechecks.json', citation_checks)
    checks = {
        'engineering_dict_unchanged': engineering == original,
        'saved_engineering_file_unchanged': file_hash(folder/'engineering-saved.json') == saved_hash,
        'record_hash_valid': investigation.get('record_hash') == digest({k: v for k, v in investigation.items() if k != 'record_hash'}),
        'completed_citations_valid': bool(completed) and all(c['valid'] for c in citation_checks),
        'completed_original_retained': any((t['action'] == 'READ' and t['result'].get('excerpt_id')) or (t['action'] == 'SEARCH' and t['result'].get('matches')) for t in completed),
        'mode_truthful': investigation['mode'] == ('SIMULATED' if simulated else 'LIVE'),
        'engineering_binding_retained': investigation['engineering_assessment_id'] == original['analyses'][0]['assessment']['assessment_id'],
        'events_include_final_ai_status': any(e['status'] == investigation['status'] for e in events),
    }
    if simulated:
        expected = 'TIMED_OUT' if scenario == 'timeout' else 'INVALID_CITATION'
        checks.update(expected_failure_visible=investigation['status'] == expected,
                      wrapper_incomplete=later['status'] == 'INCOMPLETE',
                      failure_has_no_reassessment=followup is None,
                      error_records_visible=bool(investigation['errors']))
        if scenario == 'invalid-citation':
            checks['both_rejected_proposals_retained'] = investigation['rejected_proposals'] == 2
    else:
        history = original['analyses'][0]['assessment']['statement_context']
        checks.update(live_completed=investigation['status'] in ('COMPLETED', 'NEEDS_USER_INPUT'),
                      actual_api_response=any(c.get('response_id') for c in investigation['calls']),
                      originals_reverified=bool(followup and followup['new_evidence']),
                      reassessment_completed=bool(followup and followup['status'] == 'REVERIFIED_AND_REASSESSED'),
                      verdict_preserved=bool(followup and followup['assessment']['verdict'] == 'NOT_AFFECTED' and not followup['verdict_changed']),
                      history_preserved=bool(followup and followup['assessment'].get('statement_context') == history),
                      no_free_text_condition_promotion=bool(followup and all(not x['condition_inference_verified'] for x in followup['new_evidence'])))
    row = {'scenario': scenario, 'validation_kind': 'MOCK_TRANSPORT' if simulated else 'NATIVE_LIVE',
           'formal_live_eligible': not simulated, 'status': 'PASS' if all(checks.values()) else 'FAIL',
           'ai_status': investigation['status'], 'wrapper_status': later['status'], 'model': investigation['model'],
           'reasoning_effort': investigation['reasoning_effort'], 'elapsed_seconds': elapsed,
           'ai_elapsed_seconds': investigation['elapsed_seconds'], 'api_call_count': 0 if simulated else len(investigation['calls']),
           'simulated_call_count': len(investigation['calls']) if simulated else 0,
           'actions': [t['action'] for t in investigation['tasks']], 'rejected_proposals': investigation.get('rejected_proposals', 0),
           'checks': checks, 'limitations': ['引用存在不等於語意已證明；需工程師覆核。',
               '延後入口固定使用既有 8 次／90 秒預算；沒有 Runner/UI/報告驗收。']}
    if investigation['status'] == 'CONFIG_REQUIRED':
        row['status'] = 'NOT_RUN'
    if simulated:
        row['limitations'].append('workflow 外層 mode 固定為 LIVE；本 QA 明確標 MOCK_TRANSPORT，內層 AI mode=SIMULATED，實際 API 呼叫為 0。')
    row['phase_results'] = {'engineering_retained': 'PASS' if checks['engineering_dict_unchanged'] and checks['saved_engineering_file_unchanged'] else 'FAIL',
                            'ai_expected_outcome': 'PASS' if checks.get('expected_failure_visible', checks.get('live_completed')) else 'FAIL',
                            'reassessment': 'NOT_RUN' if followup is None else 'PASS' if checks.get('history_preserved') and checks.get('verdict_preserved') else 'FAIL'}
    write_json(case_folder/'summary.json', row)
    return row


def run_r2(folder, options):
    started = time.monotonic()
    if options.r2_from_run:
        source = options.r2_from_run.resolve()
        if not source.is_relative_to((ROOT/'var/validation/parallel-ai-r2').resolve()):
            raise ValueError('R2 reuse must stay inside this worktree validation directory')
        context = ingest_package(source/'rom-supplemented')
        engineering = json.loads((source/'engineering-saved.json').read_text())
        if engineering['context_hash'] != context.context_hash:
            raise ValueError('Saved engineering context mismatch')
        write_json(folder/'engineering-saved.json', engineering)
        write_json(folder/'reused-snapshot.json', {'source_run': str(source), 'context_hash': context.context_hash, 'engineering_file_sha256': file_hash(source/'engineering-saved.json')})
    else:
        context, engineering = prepare_rom_r2(folder)
    rows = []
    scenarios = ['timeout', 'invalid-citation'] if options.mode == 'r2-mock' else ['live']
    for scenario in scenarios:
        row = run_r2_case(folder, context, engineering, scenario, options.env_file, options.r2_question)
        rows.append(row)
        summary = {'base_commit': R2_BASE, 'scope': 'ROM same-build supplement plus historical neutral statement, later AI and reassessment',
                   'cases': rows, 'status': 'PASS' if all(r['status'] == 'PASS' for r in rows) else 'FAIL',
                   'elapsed_seconds': round(time.monotonic()-started, 3), 'result_directory': str(folder)}
        write_json(folder/'summary.json', summary)
        print(json.dumps(row, ensure_ascii=False), flush=True)
    return all(row['status'] == 'PASS' for row in rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['mock', 'live', 'live-fault', 'r2-mock', 'r2-live'], default='mock')
    parser.add_argument('--case', choices=['all', *CASES], default='all')
    parser.add_argument('--env-file', type=pathlib.Path)
    parser.add_argument('--r2-from-run', type=pathlib.Path)
    parser.add_argument('--r2-question', default=R2_QUESTION)
    parser.add_argument('--max-calls', type=int, default=8)
    parser.add_argument('--timeout-seconds', type=int, default=90)
    options = parser.parse_args()
    if not 1 <= options.max_calls <= 12 or not 1 <= options.timeout_seconds <= 180:
        parser.error('Investigation budgets exceed allowed bounds')
    if options.mode.startswith('r2-') and (options.max_calls != 8 or options.timeout_seconds != 90):
        parser.error('The later engineering entry point uses its fixed 8-call / 90-second defaults')
    if options.mode == 'live-fault' and options.case == 'all':
        options.case = 'early'  # One fault-injection scenario per invocation.
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%f')
    folder = ROOT/'var/validation'/('parallel-ai-r2' if options.mode.startswith('r2-') else 'parallel-ai')/(stamp+'-'+options.mode+'-'+uuid.uuid4().hex[:8])
    folder.mkdir(parents=True, exist_ok=False)
    print(str(folder), flush=True)
    passed = run_r2(folder, options) if options.mode.startswith('r2-') else run_mock(folder) if options.mode == 'mock' else run_live(folder, options)
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
