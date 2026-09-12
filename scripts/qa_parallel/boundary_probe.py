"""Small real adapter rejection/status probes; no simulated analysis or API transport."""
from __future__ import annotations

import json
import tarfile
import time

from adapter_probe import catalog, check_archive, new_output, provenance, write_json
from cvevidence_core.frankie_adapter import analyze_archive_for_runner
from cvevidence_core.integrity import IntegrityError, UnsupportedError
from cvevidence_core.workflow import analyze_package


def main():
    output = new_output('boundaries')
    report = {**provenance(), 'cases': [], 'integration_notes': []}
    entry = catalog()['03_rom']
    archive = check_archive(entry)
    fixture = output / 'temporary' / 'negative-inputs'
    fixture.mkdir()
    empty, malformed, link = (fixture / name for name in ('empty.tar', 'malformed.tar', 'symlink.tar'))
    empty.write_bytes(b'')
    malformed.write_bytes(b'This deliberately invalid archive is a negative QA input.\n')
    link.symlink_to(archive)
    known_options = {'requested_cves': ['CVE-2014-0160'], 'mode': 'OFFLINE'}

    def reject(name, path, exception_type, message, options=None, **kwargs):
        events = []
        started = time.monotonic()
        temporary = output / 'temporary' / name
        row = {'name': name, 'expected_exception': exception_type.__name__, 'returned_result': False}
        try:
            analyze_archive_for_runner(
                path, options if options is not None else known_options,
                temporary_root=temporary, event_callback=events.append, **kwargs,
            )
        except Exception as error:
            row.update(error_type=type(error).__name__, error=str(error),
                       normalized_core_error=isinstance(error, (IntegrityError, UnsupportedError)),
                       pass_exception=isinstance(error, exception_type) and message in str(error))
        else:
            row.update(returned_result=True, pass_exception=False)
        row.update(events=events, elapsed_seconds=round(time.monotonic() - started, 3))
        row['temporary_cleaned'] = not temporary.exists() or not any(temporary.iterdir())
        row['pass'] = row['pass_exception'] and not row['returned_result'] and not events and row['temporary_cleaned']
        report['cases'].append(row)
        print(json.dumps(row, ensure_ascii=False), flush=True)
        write_json(output / 'report.json', report)

    reject('missing_archive', fixture / 'missing.tar', IntegrityError, '無效的工程壓縮包')
    reject('empty_archive', empty, IntegrityError, '無效的工程壓縮包')
    reject('symlink_archive', link, IntegrityError, '無效的工程壓縮包')
    reject('archive_hash_mismatch', archive, IntegrityError, '工程壓縮包 hash 不一致',
           expected_archive_sha256='0' * 64)
    reject('context_hash_mismatch', archive, IntegrityError, '分析快照與原 run 不一致',
           expected_archive_sha256=entry['archive']['sha256'], expected_context_hash='0' * 64)
    reject('unsupported_option', archive, ValueError, '不支援的分析選項',
           options={**known_options, 'untrusted_path': '/not-used'})
    # The baseline exposes tarfile.ReadError. Record the actual interface, not a fabricated status.
    reject('malformed_archive', malformed, tarfile.ReadError, 'file could not be opened successfully')
    report['integration_notes'].append(
        'Malformed tar returns tarfile.ReadError, not IntegrityError/UnsupportedError; '
        'all pre-ingest rejections return no result or stage event. Runner error mapping is untested.'
    )
    events = []
    started = time.monotonic()
    try:
        result = analyze_archive_for_runner(
            archive, {'requested_cves': ['CVE-2099-99999'], 'mode': 'OFFLINE'},
            expected_archive_sha256=entry['archive']['sha256'],
            temporary_root=output / 'temporary' / 'unsupported_cve', event_callback=events.append,
        )
        write_json(output / 'unsupported_cve.result.json', result)
        write_json(output / 'unsupported_cve.events.json', events)
        analysis = result['analyses'][0]
        checks = {
            'json_roundtrip': json.loads(json.dumps(result, allow_nan=False)) == result,
            'unsupported_cve': analysis['status'] == 'UNSUPPORTED_CVE',
            'no_assessment': analysis['assessment'] is None and analysis['ai'] is None,
            'not_run': result['engineering_status'] == result['ai_status'] == 'NOT_RUN',
            'ingest_events_only': [(e['stage'], e['status']) for e in events] ==
                [('INGEST', 'STARTED'), ('INGEST', 'COMPLETED')],
        }
        row = {'name': 'unsupported_cve', 'checks': checks, 'pass': all(checks.values()),
               'outer_status': result['status'], 'analysis_status': analysis['status'],
               'engineering_status': result['engineering_status'], 'ai_status': result['ai_status']}
    except Exception as error:
        row = {'name': 'unsupported_cve', 'pass': False, 'error_type': type(error).__name__, 'error': str(error)}
    row['elapsed_seconds'] = round(time.monotonic() - started, 3)
    report['cases'].append(row)
    print(json.dumps(row, ensure_ascii=False), flush=True)
    try:
        result = analyze_package(None, symptom='更新匯入失敗', mode='OFFLINE')
        write_json(output / 'awaiting_input.result.json', result)
        checks = {
            'awaiting_input': result['status'] == 'AWAITING_INPUT',
            'no_analysis': result['analyses'] == [],
            'not_run': result['engineering_status'] == result['ai_status'] == 'NOT_RUN',
            'json_roundtrip': json.loads(json.dumps(result, allow_nan=False)) == result,
        }
        row = {'name': 'awaiting_input_workflow', 'checks': checks, 'pass': all(checks.values())}
    except Exception as error:
        row = {'name': 'awaiting_input_workflow', 'pass': False, 'error_type': type(error).__name__, 'error': str(error)}
    report['cases'].append(row)
    print(json.dumps(row, ensure_ascii=False), flush=True)
    report['pass'] = all(row['pass'] for row in report['cases'])
    write_json(output / 'report.json', report)
    print(str(output / 'report.json'), flush=True)
    return 0 if report['pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
