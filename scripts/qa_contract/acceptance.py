"""Run focused consumer checks from immutable real core outputs; no core rerun/API."""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
from probe import ROOT, CORE, OUTPUT, save


def copied(source, target, records):
    value = source.read_bytes()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(value)
    assert source.read_bytes() == value, 'Source changed during QA snapshot'
    records.append({'source': str(source.resolve()), 'copy': str(target.resolve()),
                    'sha256': hashlib.sha256(value).hexdigest()})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engineering', type=Path, required=True)
    parser.add_argument('--b-run', type=Path, required=True)
    args = parser.parse_args()
    started = time.monotonic()
    output = OUTPUT / ('acceptance-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    output.mkdir(parents=True, exist_ok=False)
    records = []
    copied(args.engineering, output / 'engineering.json', records)
    # Require B's completed engineering and completed scenario summaries. Reuse
    # engineering bytes only as real core data; never label mock transport Live.
    summary = json.loads((args.b_run / 'summary.json').read_text())
    readiness = json.loads((args.b_run / 'engineering-readiness.json').read_text())
    assert summary['base_commit'] == CORE and summary['status'] == readiness['status'] == 'PASS'
    for name in ('summary.json', 'engineering-readiness.json', 'engineering-saved.json', 'engineering-before-supplement.json'):
        copied(args.b_run / name, output / 'b' / name, records)
    for case in summary['cases']:
        folder = args.b_run / case['scenario']
        if folder.exists():
            for name in ('summary.json', 'later-result.json'):
                if (folder / name).exists():
                    copied(folder / name, output / 'b' / case['scenario'] / name, records)
    save(output / 'provenance.json', {'argv': sys.argv, 'copied': records, 'core_sha': CORE,
         'scope': 'Consumer tests; B real engineering reused; scenario AI modes preserved; no API call'})
    command = [sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', 'tests/qa_contract',
               '--junitxml=' + str(output / 'junit.xml')]
    env = dict(os.environ, QA_CONTRACT_INPUT=str(output), PYTHONDONTWRITEBYTECODE='1')
    run = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    (output / 'pytest.stdout.txt').write_text(run.stdout)
    (output / 'pytest.stderr.txt').write_text(run.stderr)
    suite = ET.parse(output / 'junit.xml').getroot().find('testsuite')
    counts = {k: int(suite.get(k, '0')) for k in ('tests', 'failures', 'errors', 'skipped')}
    counts['passed'] = counts['tests'] - counts['failures'] - counts['errors'] - counts['skipped']
    findings = [{'name': c.get('name'), 'failure': c.find('failure').get('message')}
                for c in suite.findall('testcase') if c.find('failure') is not None]
    save(output / 'summary.json', {'command': command, 'exit_code': run.returncode, 'counts': counts,
         'elapsed_seconds': round(time.monotonic() - started, 3), 'pytest_seconds': float(suite.get('time')),
         'findings': findings, 'output': str(output), 'browser_e2e': 'NOT_RUN', 'api_calls': 0})
    print(run.stdout)
    print(output)
    raise SystemExit(run.returncode)


if __name__ == '__main__':
    main()
