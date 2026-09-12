"""Reproducible two-case provider acceptance; LIVE requires explicit --consent.

PASS refers to automated workflow checks, never human semantic review or an
authentication guarantee from locally stored IDs/hashes. Raw data stay in the
chosen private runtime; the summary stores bounded metadata and check outcomes.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from time import monotonic
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))

from cvevidence.ai_config import provider_configuration
from cvevidence.ai_store import parse_ai_request, validate_ai_payload
from cvevidence.runner import Runner
from cvevidence.storage import RunStore
from cvevidence_core.ai import SYSTEM, PC_REVIEW_INSTRUCTIONS, TOOL
from scripts.validate_two_demo_flows import CONTEXT

PROVIDERS = ('openai_api', 'codex_cli')
CVE = 'CVE-2022-37434'
CATALOG = 'data/catalogs/fresh-demo-two-flows-v2.json'
SUCCESS = {'COMPLETED', 'NEEDS_USER_INPUT'}
SOURCE_ACTIONS = {'LIST', 'SEARCH', 'READ', 'COMPARE'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False).encode()


def file_hash(path):
    hasher = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            hasher.update(block)
    return hasher.hexdigest()


def source_inventory():
    files = list((ROOT / 'src').rglob('*.py')) + list((ROOT / 'src').rglob('*.json'))
    files += list((ROOT / 'contracts/schemas').glob('*.json'))
    files += [Path(__file__), ROOT / 'scripts/validate_two_demo_flows.py', ROOT / CATALOG]
    return {path.relative_to(ROOT).as_posix(): file_hash(path) for path in sorted(set(files))
            if path.is_file() and '__pycache__' not in path.parts}


def code_version():
    try:
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT,
                                         text=True, stderr=subprocess.DEVNULL, timeout=5).strip()
    except (OSError, subprocess.SubprocessError):
        commit = None
    files = source_inventory()
    return {'commit': commit, 'source_sha256': digest(encoded(files)), 'source_files': files,
            'prompt_version': 'sha256:' + digest(encoded({'system': SYSTEM, 'pc': PC_REVIEW_INSTRUCTIONS, 'tool': TOOL})),
            'question_sha256': digest(CONTEXT.encode())}


def aggregate(statuses):
    values = list(statuses)
    if 'FAIL' in values:
        return 'FAIL'
    return 'PASS' if values and all(status == 'PASS' for status in values) else 'NOT_RUN'


def usage_summary(calls):
    """Missing usage remains unknown, including totals with missing calls."""
    fields = ('input_tokens', 'cached_input_tokens', 'output_tokens', 'total_tokens')
    rows = []
    for call in calls:
        usage = call.get('usage') if isinstance(call, dict) and isinstance(call.get('usage'), dict) else {}
        rows.append({key: value for key in fields if type(value := usage.get(key)) is int and value >= 0})
    totals = {key: sum(row[key] for row in rows) if rows and all(key in row for row in rows) else None
              for key in fields}
    return {'per_call': rows, 'totals': totals, 'calls_with_reported_tokens': sum(bool(row) for row in rows)}


def record_checks(record, *, parent_run_id, context_hash, assessment_id, provider, config_id, model, flow):
    """Use the product's stored-record validator; add acceptance-specific checks."""
    if not isinstance(record, dict):
        raise ValueError('AI record must be an object')
    request = record.get('request') or {}
    payload = record.get('result') or {}
    entries = payload.get('analyses') or []
    ai = entries[0].get('ai', {}) if len(entries) == 1 and isinstance(entries[0], dict) else {}
    if not isinstance(request, dict) or not isinstance(payload, dict) or not isinstance(ai, dict):
        raise ValueError('Invalid AI record fields')
    calls = ai.get('calls', []) if isinstance(ai.get('calls', []), list) else []
    tasks = ai.get('tasks', []) if isinstance(ai.get('tasks', []), list) else []
    completed = [task for task in tasks if isinstance(task, dict) and task.get('status') == 'COMPLETED']
    final = completed[-1] if completed else {}
    source_operations = [task for task in completed if task.get('action') in SOURCE_ACTIONS]
    try:
        valid_payload = validate_ai_payload(payload, parse_ai_request(request)) == record.get('status')
    except (ValueError, OSError, TypeError, KeyError):
        valid_payload = False
    checks = {
        'saved_schema_scope_and_native_receipts': valid_payload,
        'requested_provider_and_configuration': request.get('schema_version') == '2.0'
            and request.get('provider') == provider and request.get('config_id') == config_id
            and request.get('model') == model and request.get('consent') is True,
        'original_engineering_parent': request.get('parent_run_id') == parent_run_id
            and request.get('context_hash') == context_hash and request.get('assessment_id') == assessment_id
            and request.get('cve_id') == CVE,
        'live_completed': record.get('status') in SUCCESS and ai.get('mode') == 'LIVE' and bool(calls),
        'completed_task_citations': bool(completed) and all(
            isinstance(task.get('citation_verification'), dict)
            and task['citation_verification'].get('valid') is True for task in completed),
        'terminal_pc_summary_and_citations': final.get('action') in {'COMPLETE', 'ASK_USER'}
            and bool(final.get('citations')) and isinstance(final.get('finding'), str)
            and all(layer in final['finding'] for layer in ('PC1', 'PC2', 'PC3')),
        'codex_source_operation': provider != 'codex_cli' or bool(source_operations),
        'flow_2_stops_with_guidance': flow != 2 or record.get('status') == 'NEEDS_USER_INPUT'
            and final.get('action') == 'ASK_USER' and bool(final.get('required_files')),
    }
    return checks, {'mode': ai.get('mode'), 'model': ai.get('model'),
        'actual_models': sorted({call['model'] for call in calls if isinstance(call, dict) and isinstance(call.get('model'), str)}),
        'adapter_version': ai.get('adapter_version'), 'record_hash': ai.get('record_hash'),
        'calls': len(calls), 'usage': usage_summary(calls),
        'source_operations': len(source_operations), 'actions': [task.get('action') for task in completed],
        'citation_status': 'PASS' if checks['completed_task_citations'] else 'FAIL',
        'human_review': 'NOT_RUN', 'semantic_support_verified': False}


def _runner(path):
    return Runner(RunStore(path))


def _configuration(provider):
    # Do not log the private half of the operator configuration.
    return provider_configuration(provider)[1]


def provider_case(runner, baseline, provider, consent, versions):
    row = {'provider': provider, 'status': 'NOT_RUN', 'reason_code': None, 'ai_id': None,
           'human_review': 'NOT_RUN', 'checks': {}, 'calls': 0, 'elapsed_seconds': None,
           'code_sha256': versions['source_sha256'], 'prompt_version': versions['prompt_version'],
           'archive_sha256': baseline['archive_sha256']}
    try:
        config = _configuration(provider)
    except (OSError, ValueError, RuntimeError):
        row['reason_code'] = 'READINESS_CHECK_FAILED'
        return row
    row.update({key: config.get(key) for key in ('model', 'reasoning_effort', 'auth_type', 'version')})
    if not consent:
        row['reason_code'] = 'CONSENT_REQUIRED'
        return row
    if not config.get('configured'):
        row['reason_code'] = config.get('reason_code') or 'PROVIDER_NOT_READY'
        return row
    run = baseline['run']
    ai_id = str(uuid4())
    row.update(ai_id=ai_id, status='FAIL')
    started = monotonic()
    record = None
    try:
        record = runner.investigate_ai(run.run_id, user_context=CONTEXT, consent=True,
            provider=provider, config_id=config['config_id'], ai_id=ai_id, timeout=180)
        row['checks'], details = record_checks(record, parent_run_id=run.run_id,
            context_hash=baseline['context_hash'], assessment_id=baseline['assessment_id'],
            provider=provider, config_id=config['config_id'], model=config.get('model'), flow=baseline['flow'])
        row.update(details, ai_status=record.get('status'))
        reopened = _runner(runner.store.root)
        row['checks']['reopened_ai_identical'] = reopened.read_ai(ai_id) == record
        row['checks']['reopened_engineering_identical'] = reopened.read_engineering(run.run_id) == baseline['payload']
        if record.get('status') in {'CONFIG_REQUIRED', 'CONSENT_REQUIRED'} and not row['calls']:
            row.update(status='NOT_RUN', reason_code=(record.get('outcome') or {}).get('error_code') or record['status'])
        else:
            row['status'] = 'PASS' if all(row['checks'].values()) else 'FAIL'
    except (ValueError, OSError, RuntimeError, TypeError, KeyError):
        # Never include raw exception text, commands, credentials or upload text.
        row['reason_code'] = 'VALIDATION_EXECUTION_OR_REOPEN_FAILED'
    finally:
        row['elapsed_seconds'] = round(monotonic() - started, 3)
        try:
            row['checks']['original_envelope_bytes'] = runner.store._run_path(run.run_id).read_bytes() == baseline['envelope']
            row['checks']['original_engineering_blob_bytes'] = runner.store.read_blob(run.engineering_payload_sha256) == baseline['blob']
            row['checks']['input_archive_unchanged'] = file_hash(baseline['archive_path']) == baseline['archive_sha256']
        except (ValueError, OSError, TypeError, KeyError):
            row['checks']['original_materials_readable'] = False
        if any(value is False for key, value in row['checks'].items() if key.startswith(('original_', 'input_'))):
            row['status'] = 'FAIL'
        if row['status'] == 'FAIL' and not row['reason_code']:
            row['reason_code'] = ((record or {}).get('outcome') or {}).get('error_code') or 'AUTOMATED_CHECK_FAILED'
    return row


def engineering_case(entry, flow, output):
    archive = (ROOT / entry['archive']['repo_path']).resolve()
    approved_root = (ROOT / 'demo-inputs/two-flows').resolve()
    if not archive.is_relative_to(approved_root) or file_hash(archive) != entry['archive']['sha256']:
        raise ValueError('Approved demo archive integrity failed')
    runner = _runner(output / 'cases' / str(flow) / 'runtime')
    intake = runner.start_file(archive, cve=CVE, symptom=CONTEXT, archive_sha256=entry['archive']['sha256'])
    run = runner.analyze_offline(intake.run_id)
    if run.status != 'COMPLETED' or run.engineering_status != 'COMPLETED':
        raise ValueError('Engineering analysis failed')
    payload = runner.read_engineering(run.run_id)
    assessment = payload['analyses'][0]['assessment']
    states = {condition['condition_id']: condition['state'] for condition in assessment['conditions']}
    checks = {'engineering_verdict': assessment['verdict'] == ('AFFECTED' if flow == 1 else 'NEEDS_INVESTIGATION'),
              'runtime_condition': states.get('runtime_observation') == ('SUPPORTED' if flow == 1 else 'UNKNOWN'),
              'catalog_artifact': payload['input']['primary_artifact'] == entry['primary_artifact'],
              'input_archive_hash': run.input_package.archive_sha256 == entry['archive']['sha256']}
    if not all(checks.values()):
        raise ValueError('Engineering baseline did not match approved demo checks')
    baseline = {'flow': flow, 'run': run, 'payload': payload, 'context_hash': payload['context_hash'],
                'assessment_id': assessment['assessment_id'], 'archive_path': archive,
                'archive_sha256': entry['archive']['sha256'], 'envelope': runner.store._run_path(run.run_id).read_bytes(),
                'blob': runner.store.read_blob(run.engineering_payload_sha256)}
    summary = {'status': 'PASS', 'checks': checks, 'intake_run_id': intake.run_id, 'run_id': run.run_id,
               'context_hash': baseline['context_hash'], 'assessment_id': baseline['assessment_id'],
               'verdict': assessment['verdict'], 'profile_version': assessment['profile_version'],
               'envelope_sha256': digest(baseline['envelope']), 'engineering_payload_sha256': run.engineering_payload_sha256,
               'primary_artifact': payload['input']['primary_artifact']}
    return runner, baseline, summary


def execute(output_dir, *, provider='all', consent=False):
    if provider not in (*PROVIDERS, 'all') or type(consent) is not bool:
        raise ValueError('Invalid validation options')
    output = Path(output_dir).resolve()
    if output.is_relative_to(ROOT) and not output.is_relative_to(ROOT / 'var'):
        raise ValueError('Repository validation output must be under ignored var/')
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    (output / '.gitignore').write_text('*\n', encoding='utf-8')
    selected = PROVIDERS if provider == 'all' else (provider,)
    versions = code_version()
    started = monotonic()
    report = {'schema_version': '1.0', 'started_at': datetime.now(timezone.utc).isoformat(),
              'consent': consent, 'versions': versions, 'cases': [], 'providers': {}, 'status': 'NOT_RUN',
              'human_review': 'NOT_RUN',
              'scope': 'PASS 僅指自動流程驗收；不代表人工語意覆核、來源認證、全面漏洞驗證或已部署。'}
    def save():
        (output / 'summary.json').write_text(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + '\n', encoding='utf-8')
    save()
    entries = json.loads((ROOT / CATALOG).read_text(encoding='utf-8'))['packages']
    if len(entries) != 2:
        raise ValueError('Expected the two approved initial uploads')
    for flow, entry in enumerate(entries, 1):
        case = {'flow': flow, 'archive_sha256': entry['archive']['sha256'], 'providers': []}
        report['cases'].append(case)
        try:
            runner, baseline, case['engineering'] = engineering_case(entry, flow, output)
        except (ValueError, OSError, RuntimeError, TypeError, KeyError):
            case['engineering'] = {'status': 'FAIL', 'reason_code': 'ENGINEERING_VALIDATION_FAILED'}
            case['providers'] = [{'provider': name, 'status': 'NOT_RUN', 'reason_code': 'ENGINEERING_NOT_READY',
                                  'human_review': 'NOT_RUN'} for name in selected]
        else:
            for name in selected:
                print(json.dumps({'flow': flow, 'provider': name, 'event': 'VALIDATING', 'consent': consent}), flush=True)
                case['providers'].append(provider_case(runner, baseline, name, consent, versions))
                save()
        save()
    for name in selected:
        rows = [row for case in report['cases'] for row in case['providers'] if row['provider'] == name]
        attempted = [row for row in rows if row['status'] != 'NOT_RUN']
        report['providers'][name] = {'status': aggregate(row['status'] for row in rows),
            'passed_cases': sum(row['status'] == 'PASS' for row in rows), 'attempted_cases': len(attempted),
            'not_run_cases': sum(row['status'] == 'NOT_RUN' for row in rows),
            'automated_success_rate': sum(row['status'] == 'PASS' for row in attempted) / len(attempted) if attempted else None,
            'human_review': 'NOT_RUN'}
    report['source_unchanged'] = source_inventory() == versions['source_files']
    report['status'] = aggregate([case['engineering']['status'] for case in report['cases']]
        + [item['status'] for item in report['providers'].values()] + ['PASS' if report['source_unchanged'] else 'FAIL'])
    report['finished_at'] = datetime.now(timezone.utc).isoformat()
    report['elapsed_seconds'] = round(monotonic() - started, 3)
    save()
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description='兩個核准 Demo 的 OpenAI API／Codex CLI 真實流程驗收')
    parser.add_argument('--provider', choices=(*PROVIDERS, 'all'), default='all')
    parser.add_argument('--output-dir', type=Path, required=True, help='新的獨立 runtime；repo 內須位於 var/')
    parser.add_argument('--consent', action='store_true', help='授權向所選已配置來源外送核准 Demo 片段；會使用 API 費用／Codex 額度')
    args = parser.parse_args(argv)
    try:
        report = execute(args.output_dir, provider=args.provider, consent=args.consent)
    except (ValueError, OSError, RuntimeError, TypeError, KeyError):
        print(json.dumps({'status': 'FAIL', 'reason_code': 'VALIDATION_SETUP_FAILED'}))
        return 1
    print(json.dumps({'status': report['status'], 'providers': report['providers'],
                      'human_review': report['human_review'], 'summary': str(args.output_dir / 'summary.json')}, ensure_ascii=False))
    # Distinguish missing prerequisites from a successful or failed live run.
    return 0 if report['status'] == 'PASS' else 2 if report['status'] == 'NOT_RUN' else 1


if __name__ == '__main__':
    raise SystemExit(main())
