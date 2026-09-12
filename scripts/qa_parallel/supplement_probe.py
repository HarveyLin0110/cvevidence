"""Verify existing same-build material merge through the archive adapter, serially."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import time

from adapter_probe import (
    CVES, EXPECTED, OUTPUT_ROOT, ROOT, catalog, check_archive, new_output,
    observe, provenance, write_json,
)
from cvevidence_core.integrity import file_hash, ingest_package, safe_extract, scan
from cvevidence_core.supplements import validate_supplement

AFTER = {'03_rom': 'NOT_AFFECTED', '06_cmake': 'AFFECTED', '09_curl': 'AFFECTED'}


def prior_results(paths, current):
    results = {}
    for value in paths:
        path = Path(value).resolve()
        if not path.is_relative_to(OUTPUT_ROOT):
            raise ValueError('Prior QA reports must be inside this worktree QA output')
        report = json.loads(path.read_text())
        if report['core_files_sha256'] != current['core_files_sha256']:
            raise ValueError('Core changed: run only affected initial cases again')
        if report['catalog_sha256'] != current['catalog_sha256']:
            raise ValueError('Demo catalog changed')
        for row in report['cases']:
            if not row['pass']:
                raise ValueError('Cannot reuse a failing prior case')
            result_path = (path.parent / row['result_file']).resolve()
            if not result_path.is_relative_to(path.parent):
                raise ValueError('Invalid prior result path')
            result = json.loads(result_path.read_text())
            results[row['package_id']] = (result, str(path.relative_to(ROOT)))
    return results


def supplement(name, entries, output, previous):
    started = time.monotonic()
    entry = entries[name]
    added_entry = entries['supplement_' + name]
    original_archive = check_archive(entry)
    delta_archive = check_archive(added_entry)
    if name in previous:
        before, previous_report = previous[name]
    else:
        row, before = observe(original_archive, entry, EXPECTED[name], output, name)
        if not row['pass']:
            raise AssertionError('Initial archive case failed')
        previous_report = None
    with tempfile.TemporaryDirectory(prefix=f'{name}-merge-', dir=output / 'temporary') as value:
        scratch = Path(value)
        base, delta, merged = (scratch / part for part in ('base', 'delta', 'snapshot'))
        safe_extract(original_archive, base)
        safe_extract(delta_archive, delta)
        context = ingest_package(base, expected_manifest_hash=entry['manifest_sha256'])
        if file_hash(delta / 'manifest.json') != added_entry['manifest_sha256']:
            raise AssertionError('Supplement catalog manifest mismatch')
        if (context.context_hash != before['context_hash'] or
                before['archive_sha256'] != entry['archive']['sha256'] or
                before['analyses'][0]['assessment']['verdict'] != EXPECTED[name]):
            raise AssertionError('Previous result does not match this base archive/context')
        plan = validate_supplement(context, delta)
        write_json(output / f'{name}.supplement-plan.json', plan)
        if plan['status'] != 'READY_FOR_NEW_SNAPSHOT' or not plan['can_merge']:
            raise AssertionError('Expected same-build supplement was rejected')
        # Same material-only method as validate_engineering.py, in disposable QA storage.
        shutil.copytree(base, merged, symlinks=True)
        for row in plan['added_files']:
            source, destination = delta / row['path'], merged / row['path']
            destination.parent.mkdir(parents=True, exist_ok=True)
            if source.is_symlink():
                destination.symlink_to(source.readlink())
            else:
                shutil.copy2(source, destination)
        manifest = {**context.manifest, 'package_id': f'qa-{name}-snapshot', 'files': scan(merged)}
        write_json(merged / 'manifest.json', manifest)
        after_context = ingest_package(merged)
        archive = scratch / 'snapshot.tar'
        # Uncompressed tar avoids another expensive gzip pass; no product build occurs.
        with tarfile.open(archive, 'w', dereference=False) as handle:
            for path in sorted(merged.rglob('*')):
                handle.add(path, arcname=path.relative_to(merged).as_posix(), recursive=False)
        adapter_row, after = observe(
            archive, entry, AFTER[name], output, name + '-supplemented',
            expected_context_hash=after_context.context_hash,
        )
        context.assert_current()
        after_context.assert_current()
        checks = {
            'adapter': adapter_row['pass'],
            'same_build': before['input']['build_id'] == after['input']['build_id'],
            'same_artifact': before['input']['primary_artifact'] == after['input']['primary_artifact'],
            'same_artifact_bytes': file_hash(base / entry['primary_artifact']['path']) ==
                file_hash(merged / entry['primary_artifact']['path']) == entry['primary_artifact']['sha256'],
            'new_context': before['context_hash'] != after['context_hash'],
            'independent_context': after['context_hash'] == after_context.context_hash,
            'new_assessment': before['analyses'][0]['assessment']['assessment_id'] !=
                after['analyses'][0]['assessment']['assessment_id'],
            'source_snapshot_unchanged': file_hash(base / 'manifest.json') == entry['manifest_sha256'],
            'supplement_unchanged': file_hash(delta / 'manifest.json') == added_entry['manifest_sha256'],
            'input_archives_unchanged': file_hash(original_archive) == entry['archive']['sha256'] and
                file_hash(delta_archive) == added_entry['archive']['sha256'],
        }
        result = {
            'base': name, 'before': before['analyses'][0]['assessment']['verdict'],
            'after': after['analyses'][0]['assessment']['verdict'], 'expected': AFTER[name],
            'pass': all(checks.values()), 'checks': checks,
            'before_context': before['context_hash'], 'after_context': after['context_hash'],
            'build_id': after['input']['build_id'], 'primary_artifact': after['input']['primary_artifact'],
            'added_files': len(plan['added_files']), 'prior_initial_report': previous_report,
            'adapter_seconds': adapter_row['elapsed_seconds'],
            'elapsed_seconds': round(time.monotonic() - started, 3),
            'after_result_file': adapter_row['result_file'],
        }
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases', nargs='+', choices=list(AFTER), default=['03_rom'])
    parser.add_argument('--initial-report', action='append', default=[])
    args = parser.parse_args()
    output = new_output('supplements')
    report = {**provenance(), 'supplements': [], 'output': str(output)}
    entries = catalog()
    previous = prior_results(args.initial_report, report)
    print(str(output), flush=True)
    for name in args.cases:
        try:
            row = supplement(name, entries, output, previous)
        except Exception as error:
            row = {'base': name, 'pass': False, 'error_type': type(error).__name__, 'error': str(error)}
            print(json.dumps(row, ensure_ascii=False), flush=True)
        report['supplements'].append(row)
        report['pass'] = all(row['pass'] for row in report['supplements'])
        write_json(output / 'report.json', report)
    print(str(output / 'report.json'), flush=True)
    return 0 if report['pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
