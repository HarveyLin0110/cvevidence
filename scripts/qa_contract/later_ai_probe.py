"""Read completed B records and check consumer attachment; no API or product edits."""
from __future__ import annotations
import argparse
from copy import deepcopy
import datetime as dt
import json
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
from probe import CORE, OUTPUT, RecordingStreamlit, consumers, save
from acceptance import copied


def checked_attachment(engineering, later):
    """QA-only reference projection, not a shipped Runner or persistence feature.

    Do not repair IDs. An actual Runner must additionally authenticate and load
    the immutable saved run, verify lineage, and persist a separate AI stage.
    """
    if engineering['context_hash'] != later['context_hash']:
        raise ValueError('Different context')
    result = deepcopy(engineering)
    for incoming in later['analyses']:
        matches = [e for e in result['analyses'] if e['cve_id'] == incoming['cve_id']]
        if len(matches) != 1:
            raise ValueError('Ambiguous CVE')
        entry = matches[0]
        assessment = entry['assessment']
        ai = incoming['ai']
        if (incoming['engineering_assessment_id'] != assessment['assessment_id']
                or ai['engineering_assessment_id'] != assessment['assessment_id']
                or ai['context_hash'] != engineering['context_hash']
                or ai['cve_id'] != entry['cve_id']):
            raise ValueError('Different AI binding')
        entry['ai'] = deepcopy(ai)
        entry['investigation_verification'] = deepcopy(incoming['investigation_verification'])
    # Preserve the real wrapper aggregate, not a fabricated successful status.
    result['ai_status'] = later['status']
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--b-run', type=Path, action='append', required=True)
    args = parser.parse_args()
    started = time.monotonic()
    output = OUTPUT / ('later-ai-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    output.mkdir(parents=True, exist_ok=False)
    view, report, _ = consumers(output / 'objects')
    records, cases = [], []
    for source in args.b_run:
        summary = json.loads((source / 'summary.json').read_text())
        assert summary['base_commit'] == CORE and summary['status'] in {'PASS', 'FAIL'}
        target = output / source.name
        for name in ('summary.json', 'engineering-saved.json', 'engineering-before-supplement.json'):
            copied(source / name, target / name, records)
        engineering = json.loads((target / 'engineering-saved.json').read_text())
        parent = json.loads((target / 'engineering-before-supplement.json').read_text())
        for case in summary['cases']:
            scenario = case['scenario']
            for name in ('summary.json', 'later-result.json'):
                copied(source / scenario / name, target / scenario / name, records)
            later = json.loads((target / scenario / 'later-result.json').read_text())
            before = deepcopy((engineering, later))
            projection = checked_attachment(engineering, later)
            analysis = projection['analyses'][0]
            cve = analysis['cve_id']
            ai = analysis['ai']
            st = RecordingStreamlit()
            view.render_analysis(st, projection, context_hash=projection['context_hash'], cve_id=cve, key='qa-later')
            text = report.export_analysis(projection, context_hash=projection['context_hash'], cve_id=cve, run_id='QA_ONLY_NOT_RUNNER')
            save(target / scenario / 'qa-projection.json', projection)
            save(target / scenario / 'renderer-calls.json', st.calls)
            (target / scenario / 'report.txt').write_text(text)
            rejected = False
            try:
                checked_attachment(parent, later)
            except ValueError:
                rejected = True
            raw = RecordingStreamlit()
            view.render_analysis(raw, later, context_hash=later['context_hash'], cve_id=cve, key='qa-raw-later')
            save(target / scenario / 'raw-wrapper-renderer.json', raw.calls)
            checks = {
                'source_engineering_and_ai_unchanged': (engineering, later) == before,
                'engineering_assessment_unchanged': projection['analyses'][0]['assessment'] == engineering['analyses'][0]['assessment'],
                'projection_has_no_renderer_scope_error': not any(c['method'] == 'error' for c in st.calls),
                'projection_has_no_report_scope_error': 'AI_SCOPE_MISMATCH' not in text,
                'actual_ai_status_visible_in_both': ai['status'] in st.displayed() and ai['status'] in text,
                'original_verdict_visible_in_both': view.VERDICTS[analysis['assessment']['verdict']] in st.displayed() and view.VERDICTS[analysis['assessment']['verdict']] in text,
                'renderer_keeps_call_ids': all(c['response_id'] in st.displayed() for c in ai['calls'] if c.get('response_id')),
                'new_ai_rejected_for_parent_context': rejected,
                'raw_later_wrapper_is_not_full_engineering_payload': any(c['method'] == 'error' for c in raw.calls),
                'failure_does_not_fabricate_reassessment': analysis['investigation_verification'] is None,
            }
            cases.append({'scenario': scenario, 'source_kind': case['validation_kind'],
                'source_validation_status': case['status'], 'source_api_calls': case['api_call_count'],
                'ai_mode': ai['mode'], 'ai_status': ai['status'], 'wrapper_status': later['status'],
                'engineering_verdict': analysis['assessment']['verdict'],
                'engineering_assessment_id': analysis['assessment']['assessment_id'],
                'context_hash': later['context_hash'], 'calls': len(ai['calls']),
                'investigation_reassessment': 'NOT_RUN', 'checks': checks,
                'consumer_interface': 'PASS' if all(checks.values()) else 'FAIL'})
    result = {'core_sha': CORE, 'cases': cases, 'checks_count': sum(len(x['checks']) for x in cases),
        'passed_checks': sum(sum(x['checks'].values()) for x in cases),
        'elapsed_seconds': round(time.monotonic() - started, 3), 'output': str(output),
        'd_api_calls': 0, 'runner_attachment': 'QA_ONLY_REFERENCE_NOT_PRODUCT', 'browser_e2e': 'NOT_RUN'}
    save(output / 'provenance.json', {'argv': sys.argv, 'copied': records})
    save(output / 'summary.json', result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if all(x['consumer_interface'] == 'PASS' for x in cases) else 1


if __name__ == '__main__':
    raise SystemExit(main())
