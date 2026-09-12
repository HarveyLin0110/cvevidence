"""Execute the exact integration SHA in an isolated process/store, without AI."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time

sys.dont_write_bytecode = True
from probe import ROOT, CORE, INTEGRATION, OUTPUT, git, save


def child(output, engineering_file):
    # PYTHONPATH is exclusively the pinned integration's entire src tree.
    from cvevidence.runner import Runner
    from cvevidence.storage import RunStore
    from cvevidence.contracts import RunEnvelope, Assessment, EvidenceRecord, AIProposal
    from pydantic import ValidationError
    import pydantic

    started = time.monotonic()
    payload = json.loads(engineering_file.read_text())
    catalog = json.loads((ROOT / 'demo-inputs/catalog.json').read_text())
    entry = next(x for x in catalog['packages'] if x['package_id'] == '03_rom')
    runner = Runner(RunStore(output / 'store'))
    run = runner.start_file(ROOT / entry['archive']['repo_path'], cve='CVE-2014-0160',
                            archive_sha256=entry['archive']['sha256'],
                            manifest_sha256=entry['manifest_sha256'], timeout=120)
    save(output / 'runner-return.json', run.model_dump())
    reread = runner.store.read(run.run_id)
    assert reread.model_dump() == run.model_dump()
    analysis = payload['analyses'][0]
    tests = {
        'engineering_status': (RunEnvelope, {**run.model_dump(), 'engineering_status': payload['engineering_status']}),
        'ai_status': (RunEnvelope, {**run.model_dump(), 'ai_status': payload['ai_status']}),
        'multi_cve_analyses': (RunEnvelope, {**run.model_dump(), 'analyses': payload['analyses']}),
        'core_assessment': (Assessment, analysis['assessment']),
        'core_evidence': (EvidenceRecord, analysis['evidence'][0]),
        'core_ai': (AIProposal, analysis['ai']),
    }
    validation = {}
    for name, (model, data) in tests.items():
        try:
            model.model_validate(data)
            validation[name] = {'accepted': True}
        except ValidationError as error:
            validation[name] = {'accepted': False, 'errors': [
                {'loc': e['loc'], 'type': e['type'], 'msg': e['msg']}
                for e in error.errors(include_input=False)]}
    save(output / 'direct-mapping-errors.json', validation)
    excerpt = next(ex for e in analysis['evidence'] for ex in e.get('excerpts', []))
    reread_excerpt = runner.source_tool(run.run_id, 'excerpt', source_id=excerpt['source_id'],
        start_line=excerpt['start_line'], end_line=excerpt['end_line'])
    save(output / 'runner-excerpt.json', reread_excerpt)
    try:
        from cvevidence.core_service import CoreService
        CoreService(runner.store).invoke('analyze', run.input_package.archive_sha256,
                                        run.input_package.context_hash, timeout=120)
        analyze_operation = 'ACCEPTED'
    except ValueError as error:
        analyze_operation = str(error)
    result = {'integration_sha': INTEGRATION,
        'runtime_source_policy': 'Entire src tree from integration SHA, including its own older core; no source overlay',
        'comparison_core_sha': CORE, 'pydantic': pydantic.__version__,
        'runner_module': sys.modules['cvevidence.runner'].__file__,
        'core_module': str(output / 'snapshot/src/cvevidence_core'),
        'actual_status': run.status, 'engineering_status': run.engineering_status,
        'ai_status': run.ai_status, 'assessment': run.assessment,
        'source_count': len(run.sources), 'persisted_roundtrip': True,
        'context_equals_new_core': run.input_package.context_hash == payload['context_hash'],
        'excerpt_matches_core': reread_excerpt == excerpt,
        'analysis_operation': analyze_operation,
        'direct_mappings_accepted': {k: v['accepted'] for k, v in validation.items()},
        'first_full_analysis_connected': 'FAIL', 'intake_and_source_tool': 'PASS',
        'browser_e2e': 'NOT_RUN', 'live_api_calls': 0,
        'elapsed_seconds': round(time.monotonic() - started, 3), 'output': str(output)}
    save(output / 'summary.json', result)
    print(json.dumps(result, ensure_ascii=False, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engineering', required=True, type=Path)
    parser.add_argument('--child-output', type=Path)
    args = parser.parse_args()
    if args.child_output:
        child(args.child_output, args.engineering)
        return
    output = OUTPUT / ('integration-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    output.mkdir(parents=True, exist_ok=False)
    snapshot = output / 'snapshot'
    snapshot.mkdir()
    archive = subprocess.check_output(['git', 'archive', INTEGRATION, 'src', 'requirements.txt'], cwd=ROOT)
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        source.extractall(snapshot, filter='data')
    env = {k: os.environ[k] for k in ('PATH', 'LANG') if k in os.environ}
    env.update(PYTHONPATH=str(snapshot / 'src'), PYTHONDONTWRITEBYTECODE='1', TMPDIR=str(output))
    command = [sys.executable, str(Path(__file__).resolve()), '--engineering', str(args.engineering.resolve()),
               '--child-output', str(output)]
    save(output / 'provenance.json', {'argv': sys.argv, 'child_command': command, 'integration_sha': INTEGRATION,
         'integration_src_tree': git('rev-parse', INTEGRATION + ':src'),
         'engineering_file': str(args.engineering.resolve()),
         'engineering_sha256': hashlib.sha256(args.engineering.read_bytes()).hexdigest()})
    process = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=180)
    (output / 'stdout.txt').write_text(process.stdout)
    (output / 'stderr.txt').write_text(process.stderr)
    print(process.stdout)
    if process.returncode:
        print(process.stderr, file=sys.stderr)
    raise SystemExit(process.returncode)


if __name__ == '__main__':
    main()
