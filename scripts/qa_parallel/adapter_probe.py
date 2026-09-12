"""Independent, serial Git-demo archive acceptance; no Runner or live API calls."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from cvevidence_core.frankie_adapter import analyze_archive_for_runner
from cvevidence_core.integrity import digest, file_hash

BASE_COMMIT = 'b89059fdd1f751b43559187fd488844c9eeb3336'
OUTPUT_ROOT = ROOT / 'var/validation/parallel-qa'
EXPECTED = {
    '01_rom': 'AFFECTED', '02_rom': 'NOT_AFFECTED', '03_rom': 'NEEDS_INVESTIGATION',
    '04_cmake': 'AFFECTED', '05_cmake': 'NOT_AFFECTED', '06_cmake': 'NEEDS_INVESTIGATION',
    '07_curl': 'AFFECTED', '08_curl': 'NOT_AFFECTED', '09_curl': 'NEEDS_INVESTIGATION',
}
CVES = {'rom': 'CVE-2014-0160', 'cmake': 'CVE-2022-37434', 'curl': 'CVE-2023-38545'}


def write_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + '\n')


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()


def new_output(label):
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    output = OUTPUT_ROOT / f'{label}-{stamp}'
    output.mkdir(parents=True, exist_ok=False)
    # Core subprocess temporaries must also remain beneath this QA output.
    temporary = output / 'temporary'
    temporary.mkdir()
    os.environ['TMPDIR'] = str(temporary)
    import tempfile
    tempfile.tempdir = str(temporary)
    return output


def provenance():
    return {
        'base_commit': BASE_COMMIT, 'tested_commit': git('rev-parse', 'HEAD'),
        'branch': git('branch', '--show-current'), 'worktree': str(ROOT),
        'python': platform.python_version(), 'command': sys.argv,
        'tools': {name: shutil.which(name) for name in ('readelf', 'unsquashfs')},
        'core_files_sha256': {
            str(path.relative_to(ROOT)): file_hash(path)
            for path in sorted((ROOT / 'src/cvevidence_core').glob('*.py'))
        },
        'catalog_sha256': file_hash(ROOT / 'demo-inputs/catalog.json'),
        'created_at': dt.datetime.now(dt.timezone.utc).isoformat(),
        'scope': '真實 Git archive → 核心 adapter；OFFLINE；網頁未驗',
    }


def catalog():
    return {row['package_id']: row for row in json.loads(
        (ROOT / 'demo-inputs/catalog.json').read_text())['packages']}


def check_archive(entry):
    relative = entry['archive']['repo_path']
    path = ROOT / relative
    tracked = bool(git('ls-files', '--', relative))
    if not tracked or not path.resolve().is_relative_to(ROOT / 'demo-inputs'):
        raise AssertionError('Input must be a tracked Git demo-inputs archive')
    if path.stat().st_size != entry['archive']['size_bytes']:
        raise AssertionError('Catalog archive size mismatch')
    if file_hash(path) != entry['archive']['sha256']:
        raise AssertionError('Catalog archive hash mismatch')
    return path


def observe(archive, entry, expected, output, label, expected_context_hash=None):
    events = []
    cve = CVES[entry['format']]
    started = time.monotonic()
    result = analyze_archive_for_runner(
        archive, {'requested_cves': [cve], 'mode': 'OFFLINE'},
        expected_archive_sha256=file_hash(archive),
        expected_context_hash=expected_context_hash,
        temporary_root=output / 'temporary' / label, event_callback=events.append,
    )
    elapsed = round(time.monotonic() - started, 3)
    serialized = json.dumps(result, ensure_ascii=False, allow_nan=False)
    write_json(output / f'{label}.result.json', result)
    write_json(output / f'{label}.events.json', events)
    analysis = result['analyses'][0]
    assessment = analysis['assessment']
    expected_events = [
        ('INGEST', 'STARTED', None), ('INGEST', 'COMPLETED', None),
        ('QUERIES', 'STARTED', cve), ('QUERIES', 'COMPLETED', cve),
        ('VERIFY', 'STARTED', cve), ('VERIFY', 'COMPLETED', cve),
        ('ASSESS', 'COMPLETED', cve), ('AI', 'STARTED', cve), ('AI', 'OFFLINE', cve),
    ]
    checks = {
        'json_roundtrip': json.loads(serialized) == result,
        'completed': result['status'] == analysis['status'] == 'COMPLETED',
        'engineering_completed': result['engineering_status'] == 'COMPLETED',
        'ai_offline': result['ai_status'] == analysis['ai']['status'] == 'OFFLINE',
        'verdict': assessment['verdict'] == expected,
        'five_queries': len(analysis['queries']) == 5,
        'context_consistent': len(result['context_hash']) == 64 and
            result['context_hash'] == result['input']['context_hash'] ==
            assessment['context_hash'] == analysis['ai']['context_hash'],
        'archive_hash': result['archive_sha256'] == file_hash(archive),
        'identity': all(result['input'][key] == entry[key]
                        for key in ('build_id', 'release_id', 'primary_artifact')),
        'stage_sequence': [(e['stage'], e['status'], e['cve_id']) for e in events] == expected_events,
        'temporary_cleaned': not any((output / 'temporary' / label).iterdir()),
    }
    row = {
        'package_id': label, 'input_archive': str(archive.relative_to(ROOT)),
        'expected': expected, 'observed': assessment['verdict'], 'checks': checks,
        'pass': all(checks.values()), 'elapsed_seconds': elapsed,
        'context_hash': result['context_hash'], 'archive_sha256': result['archive_sha256'],
        'assessment_id': assessment['assessment_id'], 'sources': len(result['input']['sources']),
        'evidence_count': len(analysis['evidence']), 'event_count': len(events),
        'condition_states': {x['condition_id']: x['state'] for x in assessment['conditions']},
        'result_file': f'{label}.result.json', 'events_file': f'{label}.events.json',
    }
    print(json.dumps(row, ensure_ascii=False), flush=True)
    return row, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases', nargs='+', choices=list(EXPECTED), default=['03_rom'])
    args = parser.parse_args()
    output = new_output('archive')
    report = {**provenance(), 'cases': [], 'output': str(output)}
    print(str(output), flush=True)
    entries = catalog()
    for name in args.cases:
        try:
            row, _ = observe(check_archive(entries[name]), entries[name], EXPECTED[name], output, name)
        except Exception as error:
            row = {'package_id': name, 'pass': False, 'error_type': type(error).__name__, 'error': str(error)}
            print(json.dumps(row, ensure_ascii=False), flush=True)
        report['cases'].append(row)
        report['pass'] = all(row['pass'] for row in report['cases'])
        write_json(output / 'report.json', report)
    print(str(output / 'report.json'), flush=True)
    return 0 if report['pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
