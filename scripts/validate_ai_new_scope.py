"""Live acceptance: a new, unsubmitted product entry must remain unresolved."""
import argparse
import datetime
import json
import pathlib
import subprocess
import sys
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from cvevidence_core.ai import replay_investigation
from cvevidence_core.integrity import file_hash, ingest_package, safe_extract
from cvevidence_core.workflow import analyze_package


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', type=pathlib.Path, required=True)
    args = parser.parse_args()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    folder = ROOT / 'var/validation' / ('ai-new-scope-' + stamp + '-' + uuid.uuid4().hex[:6])
    folder.mkdir(parents=True)
    def save(name, value):
        (folder / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    entry = next(x for x in json.loads((ROOT / 'demo-inputs/catalog.json').read_text())['packages']
                 if x['package_id'] == '05_cmake')
    archive = ROOT / entry['archive']['repo_path']
    if file_hash(archive) != entry['archive']['sha256']:
        raise ValueError('Archive hash mismatch')
    safe_extract(archive, folder / 'input')
    context = ingest_package(folder / 'input', entry['manifest_sha256'])
    cve = 'CVE-2022-37434'
    baseline = analyze_package(context, [cve], mode='OFFLINE')
    save('baseline.json', baseline)
    statement = '產品另有尚未交付的網路更新入口，會接收 gzip；這個入口的程式與編譯資料尚未提供。'
    save('provenance.json', {
        'tested_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'archive_sha256': entry['archive']['sha256'], 'context_hash': context.context_hash,
        'statement': statement, 'mode': 'NATIVE_LIVE',
        'core_files': {p.name: file_hash(p) for p in sorted((ROOT / 'src/cvevidence_core').glob('*.py'))}})
    events = []
    def event(row):
        events.append(row)
        save('events.json', events)
        if row['stage'] == 'AI':
            print(json.dumps(row, ensure_ascii=False), flush=True)
    print(str(folder), flush=True)
    result = analyze_package(context, [cve], symptom='請依我補充的另一個產品入口，判斷還需要調查什麼。',
                             statements=[statement], mode='LIVE', env_file=args.env_file, event_callback=event)
    save('result.json', result)
    analysis = result['analyses'][0]
    record = analysis['ai']
    replay = replay_investigation(context, record) if record.get('record_hash') else None
    save('replay.json', replay)
    grouping = analysis['condition_groups']
    grouped_ids = set(grouping['shared_prerequisite_ids'])
    grouped_ids.update(k for g in grouping['groups'] for k in g['condition_ids'])
    checks = {
        'baseline_not_affected': baseline['analyses'][0]['assessment']['verdict'] == 'NOT_AFFECTED',
        'new_scope_stays_unresolved': analysis['assessment']['verdict'] == 'NEEDS_INVESTIGATION',
        'verified_conditions_unchanged': analysis['assessment']['conditions'] == baseline['analyses'][0]['assessment']['conditions'],
        'new_scope_review_retained': bool(analysis['assessment']['statement_reviews']),
        'asks_for_missing_material': record['status'] == 'NEEDS_USER_INPUT' and bool(record['tasks'][-1]['required_files']),
        'native_live': record['mode'] == 'LIVE' and bool(record['calls']),
        'replay_keeps_original_times': bool(replay and replay['mode'] == 'REPLAY' and replay['original_time_available']
            and replay['original_started_at'] == record['started_at'] and replay['original_finished_at'] == record['finished_at']),
        'grouping_covers_current_conditions': grouped_ids == {c['condition_id'] for c in analysis['assessment']['conditions']},
    }
    summary = {'status': 'PASS' if all(checks.values()) else 'FAIL', 'checks': checks,
               'ai_status': record['status'], 'model': record['model'], 'calls': len(record['calls']),
               'ai_seconds': record['elapsed_seconds'], 'started_at': record.get('started_at'),
               'finished_at': record.get('finished_at'),
               'questions': [t['question'] for t in record['tasks']],
               'required_files': record['tasks'][-1]['required_files'] if record['tasks'] else [],
               'limits': ['核心 Live／Replay 驗收，未涵蓋正式網頁或 Runner 保存。', '語意合理性另人工核對，不以字串測試取代。']}
    save('summary.json', summary)
    print(json.dumps(summary, ensure_ascii=False), flush=True)
    return 0 if all(checks.values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
