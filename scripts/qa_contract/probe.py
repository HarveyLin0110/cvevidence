"""Real archive -> pinned display/report consumers; QA only, never calls Live AI."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import types

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
CORE = '44efc7bdcc533760ab167a2a005b0111b9758483'
VIEW = '40802c865ee74046938d67b3b6f7715bdc3cb188'
REPORT = '184145cc80fd145c47f1a4464538e05bca675d73'
INTEGRATION = 'a47a1a342ec86a9b6b26f9dedb318b6490250d28'
OUTPUT = ROOT / 'var/validation/parallel-contract'


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT).decode().strip()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n')


def git_file(sha, name, destination):
    content = subprocess.check_output(['git', 'show', f'{sha}:{name}'], cwd=ROOT)
    path = destination / sha / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


def consumers(scratch):
    # Report imports analysis_view. Load its own commit's dependency, then prove
    # that the separately requested renderer has identical bytes.
    vp = git_file(VIEW, 'src/cvevidence/analysis_view.py', scratch)
    rp = git_file(REPORT, 'src/cvevidence/analysis_report.py', scratch)
    dependency = git_file(REPORT, 'src/cvevidence/analysis_view.py', scratch)
    assert vp.read_bytes() == dependency.read_bytes(), 'Report renderer dependency changed'
    pkg = types.ModuleType('qa_contract_pinned_report')
    pkg.__path__ = [str(rp.parent)]
    sys.modules[pkg.__name__] = pkg
    view = module('qa_contract_pinned_view', vp)
    module(pkg.__name__ + '.analysis_view', dependency)
    report = module(pkg.__name__ + '.analysis_report', rp)
    return view, report, hashlib.sha256(vp.read_bytes()).hexdigest()


class RecordingStreamlit:
    """Only records renderer calls; explicitly not browser or Streamlit E2E."""
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def __getattr__(self, name):
        if name not in {'subheader', 'text', 'caption', 'info', 'warning', 'error', 'code', 'expander', 'button'}:
            raise AttributeError(name)
        def record(*args, **kwargs):
            self.calls.append({'method': name, 'args': args, 'kwargs': kwargs})
            return self if name == 'expander' else False
        return record

    def displayed(self):
        return '\n'.join(str(a) for c in self.calls for a in c['args'])


def initial(output):
    from cvevidence_core.frankie_adapter import analyze_archive_for_runner
    from cvevidence_core.integrity import file_hash
    started = time.monotonic()
    entry = next(x for x in json.loads((ROOT / 'demo-inputs/catalog.json').read_text())['packages']
                 if x['package_id'] == '03_rom')
    archive = ROOT / entry['archive']['repo_path']
    assert file_hash(archive) == entry['archive']['sha256']
    events = []
    payload = analyze_archive_for_runner(archive,
        {'requested_cves': ['CVE-2014-0160', 'CVE-2022-37434', 'CVE-2099-99999'], 'mode': 'OFFLINE'},
        expected_archive_sha256=entry['archive']['sha256'], temporary_root=output / 'temporary',
        event_callback=events.append)
    save(output / 'engineering.json', payload)
    save(output / 'events.json', events)
    view, report, view_sha256 = consumers(output / 'objects')
    results = []
    for analysis in payload['analyses']:
        cve = analysis['cve_id']
        st = RecordingStreamlit()
        view.render_analysis(st, json.loads(json.dumps(payload)), context_hash=payload['context_hash'],
                             cve_id=cve, key=cve)
        save(output / (cve + '.renderer.json'), st.calls)
        exported = report.export_analysis(payload, context_hash=payload['context_hash'], cve_id=cve,
                                         run_id='QA_ONLY_NOT_A_RUNNER_RUN')
        (output / (cve + '.report.txt')).write_text(exported)
        assessment, ai = analysis.get('assessment'), analysis.get('ai')
        results.append({'cve_id': cve, 'status': analysis['status'],
            'verdict': assessment['verdict'] if assessment else None,
            'assessment_id': assessment['assessment_id'] if assessment else None,
            'queries': len(analysis.get('queries', [])), 'evidence': len(analysis.get('evidence', [])),
            'ai_identity': {k: ai.get(k) for k in ('cve_id', 'context_hash', 'engineering_assessment_id', 'status')} if ai else None,
            'renderer_errors': [c for c in st.calls if c['method'] == 'error'],
            'report_ai_mismatch': 'AI_SCOPE_MISMATCH' in exported,
            'conditions_displayed': all(x['state'] in st.displayed() for x in (assessment or {}).get('conditions', []))})
    summary = {'scope': 'real archive / recording fake Streamlit; NOT browser E2E',
        'core_sha': CORE, 'renderer_sha': VIEW, 'report_sha': REPORT, 'integration_sha': INTEGRATION,
        'dependency_renderer_sha256': view_sha256, 'archive_sha256': file_hash(archive),
        'context_hash': payload['context_hash'], 'engineering': payload['engineering_status'],
        'ai': payload['ai_status'], 'analyses': results,
        'live_interface': 'NOT_RUN', 'runner_connected': 'NOT_RUN', 'browser_e2e': 'NOT_RUN',
        'elapsed_seconds': round(time.monotonic() - started, 3), 'output': str(output)}
    save(output / 'summary.json', summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    return payload, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    assert not git('diff', CORE, '--', 'src/cvevidence_core', 'demo-inputs'), 'Core/input differs from pinned baseline'
    assert git('branch', '--show-current') == 'codex/parallel-contract-qa'
    output = OUTPUT / ('run-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    output.mkdir(parents=True, exist_ok=False)
    # Both core subprocess tools and Python tempfiles stay within this QA run.
    (output / 'temporary').mkdir()
    os.environ['TMPDIR'] = str(output / 'temporary')
    import tempfile
    tempfile.tempdir = str(output / 'temporary')
    save(output / 'provenance.json', {'argv': sys.argv, 'cwd': str(ROOT), 'head': git('rev-parse', 'HEAD'),
         'core_sha': CORE, 'renderer_sha': VIEW, 'report_sha': REPORT, 'integration_sha': INTEGRATION,
         'python': sys.version, 'started_at': dt.datetime.now(dt.timezone.utc).isoformat(),
         'core_tree': git('rev-parse', CORE + ':src/cvevidence_core')})
    sys.path.insert(0, str(ROOT / 'src'))
    initial(output)


if __name__ == '__main__':
    main()
