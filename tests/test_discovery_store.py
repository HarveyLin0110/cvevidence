"""TEST_ONLY query receipts; no public network or model used."""
import json
from pathlib import Path
import pytest
from streamlit.testing.v1 import AppTest
from cvevidence.runner import Runner
from cvevidence.storage import RunStore
from cvevidence.discovery_store import save, latest, directory
from cvevidence_core.partial_intake import create


def setup_case(tmp_path):
    create([('sbom.json', b'{"components":[]}')], tmp_path / 'p.tgz')
    runner = Runner(RunStore(tmp_path / 'runtime'))
    run = runner.start_file(tmp_path / 'p.tgz')
    data = {'context_hash': run.input_package.context_hash, 'status': 'COMPLETED',
            'scope': 'TEST_ONLY', 'candidates': [{'cve_id': 'CVE-2099-1234',
                'status': 'CANDIDATE_ONLY', 'summary': 'TEST_ONLY summary'}]}
    return runner, run, data


def test_saved_candidates_reopen_without_network_and_keep_old_receipts(tmp_path):
    runner, run, data = setup_case(tmp_path)
    original = runner.store.read(run.run_id).model_dump_json()
    first = save(runner.store, run.run_id, data)
    assert Runner(RunStore(tmp_path / 'runtime')).public_discovery(run.run_id) == first
    save(runner.store, run.run_id, {**data, 'candidates': []})
    assert latest(runner.store, run.run_id)['discovery']['candidates'] == []
    assert len(list(directory(runner.store, run.run_id).glob('*.json'))) == 2
    assert runner.store.read_blob(first['record_sha256'])
    assert runner.store.read(run.run_id).model_dump_json() == original


def test_cross_scope_and_corrupted_public_receipts_rejected(tmp_path):
    runner, run, data = setup_case(tmp_path)
    with pytest.raises(ValueError): save(runner.store, run.run_id, {**data, 'context_hash': 'wrong'})
    other = runner.start_file(tmp_path / 'p.tgz')
    first = save(runner.store, run.run_id, data)
    receipt = directory(runner.store, other.run_id, create=True) / 'newest.json'
    receipt.write_text(json.dumps({'record_sha256': first['record_sha256']}))
    with pytest.raises(ValueError): latest(runner.store, other.run_id)
    (runner.store.root / 'blobs' / first['record_sha256']).write_text('{}')
    with pytest.raises(ValueError): latest(runner.store, run.run_id)


def test_fresh_web_session_restores_candidate_choices(tmp_path, monkeypatch):
    runner, run, data = setup_case(tmp_path)
    save(runner.store, run.run_id, data)
    monkeypatch.setenv('CVEVIDENCE_STORE', str(runner.store.root))
    app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / 'runner_app.py')).run()
    app.session_state['selected_run'] = run.run_id
    app.session_state['step'] = '03 分析進度與結果'
    app.run()
    assert not app.exception
    selector = next(x for x in app.selectbox if x.label == '選擇一個 CVE 進行分析')
    assert 'CVE-2099-1234' in selector.options
