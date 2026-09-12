"""Round 2: real ROM archive/delta, retained statements, and failure isolation; OFFLINE."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import time

from adapter_probe import ROOT, catalog, check_archive, new_output, provenance, write_json
from cvevidence_core.frankie_adapter import analyze_archive_for_runner
from cvevidence_core.integrity import IntegrityError, digest, file_hash, ingest_package, safe_extract, scan
from cvevidence_core.investigation_evidence import reassess_after_investigation
from cvevidence_core.supplements import interpret_statement, validate_supplement
from cvevidence_core.workflow import analyze_package, investigate_after_engineering

BASE = '44efc7bdcc533760ab167a2a005b0111b9758483'
CVE = 'CVE-2014-0160'


def main():
    started = time.monotonic()
    output = new_output('merged-rom-r2')
    report = {**provenance(), 'base_commit': BASE, 'cases': [], 'output': str(output),
              'not_run': ['Live API', 'UI/Runner/persistence/download', '75 existing unit tests',
                          'CMake Live flow', 'full 3x3/performance reruns']}
    report['qa_script_sha256'] = file_hash(Path(__file__))
    print(str(output), flush=True)

    def record(name, checks, seconds, **details):
        row = {'name': name, 'status': 'PASS' if all(checks.values()) else 'FAIL',
               'checks': checks, 'elapsed_seconds': round(seconds, 3), **details}
        report['cases'].append(row)
        report['status'] = 'FAIL' if any(r['status'] == 'FAIL' for r in report['cases']) else 'RUNNING'
        write_json(output / 'report.json', report)
        print(json.dumps(row, ensure_ascii=False), flush=True)
        return row

    def analyze(name, context, archive, notes, expected, previous_conditions=None):
        begin = time.monotonic()
        events = []
        if archive:
            result = analyze_archive_for_runner(
                archive, {'requested_cves': [CVE], 'mode': 'OFFLINE', 'statements': notes},
                expected_archive_sha256=file_hash(archive), expected_context_hash=context.context_hash,
                temporary_root=output / 'temporary' / name, event_callback=events.append)
        else:
            result = analyze_package(context, [CVE], statements=notes, mode='OFFLINE', event_callback=events.append)
        write_json(output / f'{name}.result.json', result)
        write_json(output / f'{name}.events.json', events)
        analysis = result['analyses'][0]
        assessment = analysis['assessment']
        history = assessment.get('statement_context', [])
        checks = {
            'verdict': assessment['verdict'] == expected,
            'json_roundtrip': json.loads(json.dumps(result, allow_nan=False)) == result,
            'offline_no_api_calls': analysis['ai']['status'] == 'OFFLINE' and analysis['ai']['calls'] == [],
            'context_bound': result['context_hash'] == context.context_hash == assessment['context_hash'] == analysis['ai']['context_hash'],
            'history_retained': len(history) == len(notes) and all(
                row['statement_id'] == note['material_id'] and row['text'] == note['text'] and
                row['source_context_hash'] == note['source_context_hash'] and
                row['assessed_context_hash'] == context.context_hash and not row['verified_engineering_fact']
                for row, note in zip(history, notes)),
            'workflow_offline_no_followup': analysis['investigation_verification'] is None,
            'stage_sequence': [(e['stage'], e['status']) for e in events] == [
                ('INGEST', 'STARTED'), ('INGEST', 'COMPLETED'), ('QUERIES', 'STARTED'), ('QUERIES', 'COMPLETED'),
                ('VERIFY', 'STARTED'), ('VERIFY', 'COMPLETED'), ('ASSESS', 'COMPLETED'), ('AI', 'STARTED'), ('AI', 'OFFLINE')],
        }
        if previous_conditions is not None:
            checks['conditions_unchanged_by_text'] = assessment['conditions'] == previous_conditions
        statuses = [check['status'] for row in history for check in row['checks']]
        record(name, checks, time.monotonic() - begin, expected=expected, observed=assessment['verdict'],
               context_hash=context.context_hash, assessment_id=assessment['assessment_id'],
               statement_statuses=statuses, pending_reviews=len(assessment['statement_reviews']),
               result_file=f'{name}.result.json', events_file=f'{name}.events.json')
        return result

    try:
        entries = catalog()
        entry, delta_entry = entries['03_rom'], entries['supplement_03_rom']
        original_archive, delta_archive = check_archive(entry), check_archive(delta_entry)
        with tempfile.TemporaryDirectory(prefix='rom-material-', dir=output / 'temporary') as folder:
            scratch = Path(folder)
            base, delta, merged = (scratch / part for part in ('base', 'delta', 'merged'))
            safe_extract(original_archive, base)
            safe_extract(delta_archive, delta)
            base_context = ingest_package(base, entry['manifest_sha256'])
            if file_hash(delta / 'manifest.json') != delta_entry['manifest_sha256']:
                raise IntegrityError('Supplement catalog manifest mismatch')
            notes = [interpret_statement(text, base_context.context_hash) for text in (
                '已提供這次使用的檔案，請查核。', '已停用 heartbeat，請查核。')]
            before = analyze('01-original-with-statements', base_context, original_archive, notes, 'NEEDS_INVESTIGATION')
            begin = time.monotonic()
            plan = validate_supplement(base_context, delta)
            write_json(output / 'supplement-plan.json', plan)
            if plan['status'] != 'READY_FOR_NEW_SNAPSHOT' or not plan['can_merge']:
                raise AssertionError('Expected valid same-build delta')
            shutil.copytree(base, merged, symlinks=True)
            for row in plan['added_files']:
                source, target = delta / row['path'], merged / row['path']
                target.parent.mkdir(parents=True, exist_ok=True)
                if source.is_symlink():
                    target.symlink_to(source.readlink())
                else:
                    shutil.copy2(source, target)
            manifest = {**base_context.manifest, 'package_id': 'qa-r2-rom03-merged', 'files': scan(merged)}
            write_json(merged / 'manifest.json', manifest)
            merged_context = ingest_package(merged)
            merged_archive = scratch / 'merged.tar'
            with tarfile.open(merged_archive, 'w', dereference=False) as handle:
                for path in sorted(merged.rglob('*')):
                    handle.add(path, arcname=path.relative_to(merged).as_posix(), recursive=False)
            after = analyze('02-supplemented-history', merged_context, merged_archive, notes, 'NOT_AFFECTED')
            assessment = after['analyses'][0]['assessment']
            conditions = assessment['conditions']
            record('03-delta-identity-and-history-transition', {
                'same_build': before['input']['build_id'] == after['input']['build_id'],
                'same_primary_artifact': before['input']['primary_artifact'] == after['input']['primary_artifact'],
                'same_artifact_bytes': file_hash(base / entry['primary_artifact']['path']) ==
                    file_hash(merged / entry['primary_artifact']['path']) == entry['primary_artifact']['sha256'],
                'new_context': before['context_hash'] != after['context_hash'],
                'historical_claim_now_verified': before['analyses'][0]['assessment']['statement_reviews'][0]['checks'][0]['status'] ==
                    'UNVERIFIED_ENGINEERING_CLAIM' and assessment['statement_context'][1]['checks'][0]['status'] == 'CONSISTENT_WITH_VERIFIED_EVIDENCE',
                'no_pending_reviews': assessment['statement_reviews'] == [],
                'implementation_blocked': next(c for c in conditions if c['condition_id'] == 'vulnerable_implementation')['state'] == 'BLOCKED',
                'old_origin_retained': all(r['source_context_hash'] == before['context_hash'] and
                    r['assessed_context_hash'] == after['context_hash'] for r in assessment['statement_context']),
            }, time.monotonic() - begin, added_files=len(plan['added_files']),
                before_json='01-original-with-statements.result.json', after_json='02-supplemented-history.result.json')

            fresh_note = interpret_statement('已提供同 build 的檔案，請重新分析。', merged_context.context_hash)
            analyze('04-fresh-neutral-workflow', merged_context, None, [fresh_note], 'NOT_AFFECTED', conditions)
            variants = {}
            for name, text, status in [
                ('05-historical-conflict', 'heartbeat 已啟用。', 'CONFLICTS_WITH_VERIFIED_EVIDENCE'),
                ('06-historical-uncovered-entry', '已提供檔案。另有未交付的網路入口。', 'UNRESOLVED_SCOPE'),
            ]:
                note = interpret_statement(text, base_context.context_hash)
                result = analyze(name, merged_context, None, [note], 'NEEDS_INVESTIGATION', conditions)
                actual = result['analyses'][0]['assessment']
                checks = [c for row in actual['statement_reviews'] for c in row['checks']]
                report['cases'][-1]['checks']['specific_review_retained'] = any(c['status'] == status and c['blocks_verdict'] for c in checks)
                report['cases'][-1]['status'] = 'PASS' if all(report['cases'][-1]['checks'].values()) else 'FAIL'
                variants[name] = result

            # Directly exercise the merged mainline helper with actual OFFLINE records.
            # This is an OFFLINE re-verification boundary, never a synthetic Live success.
            for name, result in [('07-reassess-history', after), ('08-reassess-conflict', variants['05-historical-conflict']),
                                 ('09-reassess-uncovered-entry', variants['06-historical-uncovered-entry'])]:
                begin = time.monotonic()
                original = copy.deepcopy(result)
                analysis = result['analyses'][0]
                reassessed = reassess_after_investigation(merged_context, analysis['assessment'], analysis['ai'])
                write_json(output / f'{name}.result.json', reassessed)
                record(name, {
                    'verdict_preserved': reassessed['assessment']['verdict'] == analysis['assessment']['verdict'],
                    'history_and_pending_preserved': all(reassessed['assessment'].get(k) == analysis['assessment'].get(k)
                        for k in ('statement_context', 'statement_reviews', 'conditions')),
                    'input_result_unchanged': result == original,
                    'no_fabricated_ai_evidence': reassessed['new_evidence'] == [] and analysis['ai']['calls'] == [],
                }, time.monotonic() - begin, observed=reassessed['assessment']['verdict'],
                    route='reassess_after_investigation(actual OFFLINE record)', result_file=f'{name}.result.json')

            protected = {path: file_hash(path) for path in (original_archive, delta_archive, merged_archive,
                output / '01-original-with-statements.result.json', output / '02-supplemented-history.result.json')}
            saved_before, saved_after = digest(before), digest(after)
            delta_manifest = (delta / 'manifest.json').read_bytes()

            def isolation():
                base_context.assert_current()
                merged_context.assert_current()
                return all(file_hash(path) == sha for path, sha in protected.items()) and digest(before) == saved_before and digest(after) == saved_after

            def reject(name, call, expected_message):
                begin = time.monotonic()
                caught = None
                try:
                    returned = call()
                except IntegrityError as error:
                    caught = error
                record(name, {'rejected': caught is not None and expected_message in str(caught),
                              'original_inputs_and_results_unchanged': isolation()}, time.monotonic() - begin,
                       error_type=type(caught).__name__ if caught else None, error=str(caught) if caught else None)

            begin = time.monotonic()
            wrong = json.loads(delta_manifest)
            wrong['build_id'] += '-other-build'
            try:
                write_json(delta / 'manifest.json', wrong)
                rejected = validate_supplement(base_context, delta)
            finally:
                (delta / 'manifest.json').write_bytes(delta_manifest)
            record('10-different-build-delta', {
                'different_build_rejected': rejected['status'] == 'DIFFERENT_BUILD' and not rejected['can_merge'],
                'original_inputs_and_results_unchanged': isolation(),
            }, time.monotonic() - begin, observed=rejected)

            wrong = json.loads(delta_manifest)
            wrong['files'][0]['sha256'] = '0' * 64
            try:
                write_json(delta / 'manifest.json', wrong)
                reject('11-delta-inventory-hash-mismatch', lambda: validate_supplement(base_context, delta), 'inventory or hash mismatch')
            finally:
                (delta / 'manifest.json').write_bytes(delta_manifest)

            extra = next(row['path'] for row in base_context.manifest['files']
                         if row['kind'] == 'file' and not (delta / row['path']).exists())
            extra_path = delta / extra
            try:
                extra_path.parent.mkdir(parents=True, exist_ok=True)
                extra_path.write_bytes(b'QA conflicting replacement; never merged into the base.\n')
                wrong = json.loads(delta_manifest)
                wrong['files'] = scan(delta)
                write_json(delta / 'manifest.json', wrong)
                reject('12-conflicting-same-build-delta', lambda: validate_supplement(base_context, delta), 'Conflicting replacement')
            finally:
                extra_path.unlink()
                (delta / 'manifest.json').write_bytes(delta_manifest)

            for name, kwargs, message in [
                ('13-archive-sha-mismatch', {'expected_archive_sha256': '0' * 64}, '工程壓縮包 hash 不一致'),
                ('14-stale-context-on-new-snapshot', {'expected_context_hash': base_context.context_hash}, '分析快照與原 run 不一致'),
            ]:
                reject(name, lambda kwargs=kwargs: analyze_archive_for_runner(merged_archive,
                    {'requested_cves': [CVE], 'mode': 'OFFLINE'}, temporary_root=output / 'temporary' / name, **kwargs), message)
            # This mismatch is rejected before the hardcoded LIVE stage or settings lookup.
            reject('15-saved-engineering-wrong-context', lambda: investigate_after_engineering(base_context, after), 'AI 階段不屬於已保存的工程快照')
            record('16-final-input-and-result-preservation', {
                'all_originals_unchanged': isolation(),
                'valid_delta_restored': file_hash(delta / 'manifest.json') == delta_entry['manifest_sha256'] and
                    validate_supplement(base_context, delta)['status'] == 'READY_FOR_NEW_SNAPSHOT',
            }, 0)
    except Exception as error:
        record('unexpected_failure', {'no_unexpected_failure': False}, time.monotonic() - started,
               error_type=type(error).__name__, error=str(error))
    report['elapsed_seconds'] = round(time.monotonic() - started, 3)
    report['counts'] = {status: sum(row['status'] == status for row in report['cases']) for status in ('PASS', 'FAIL')}
    report['status'] = 'PASS' if len(report['cases']) == 16 and not report['counts']['FAIL'] else 'FAIL'
    write_json(output / 'report.json', report)
    print(json.dumps({'status': report['status'], 'counts': report['counts'], 'elapsed_seconds': report['elapsed_seconds'],
                      'report': str(output / 'report.json')}, ensure_ascii=False), flush=True)
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
