"""Controller lifecycle tests; no model calls or product verdict claims."""
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from types import SimpleNamespace
from uuid import uuid4
import gc
import weakref

import pytest
from cvevidence import ai_jobs


@pytest.fixture
def jobs(monkeypatch):
    with ThreadPoolExecutor(max_workers=2) as pool:
        monkeypatch.setattr(ai_jobs, '_pool', pool)
        monkeypatch.setattr(ai_jobs, '_jobs', {})
        monkeypatch.setattr(ai_jobs, '_finished', ai_jobs.OrderedDict())
        yield ai_jobs


def runner(tmp_path, invoke):
    return SimpleNamespace(store=SimpleNamespace(root=tmp_path), investigate_ai=invoke)


def finish(jobs, service, ai_id):
    key=(str(service.store.root.resolve()), ai_id)
    future=jobs._jobs.get(key)
    if future is not None:future.result(timeout=5)
    return jobs.state(service.store, ai_id)


def test_success_does_not_retain_full_record_and_duplicate_does_not_rerun(jobs, tmp_path):
    class Payload:pass
    refs=[]
    def invoke(run_id, **kwargs):
        payload=Payload()
        refs.append(weakref.ref(payload))
        return {'request':{'parent_run_id':run_id}, 'payload':payload}
    service=runner(tmp_path, invoke)
    ai_id=str(uuid4())
    jobs.start(service, 'run', ai_id=ai_id)
    assert finish(jobs, service, ai_id)=='DONE'
    gc.collect()
    assert refs[0]() is None
    jobs.start(service, 'run', ai_id=ai_id)
    assert len(refs)==1
    assert not jobs._jobs


def test_failure_releases_traceback_material_and_remains_visible(jobs, tmp_path):
    class Payload:pass
    refs=[]
    def invoke(run_id, **kwargs):
        uploaded=Payload()
        refs.append(weakref.ref(uploaded))
        raise ValueError('sensitive uploaded contents')
    service=runner(tmp_path, invoke)
    ai_id=str(uuid4())
    jobs.start(service, 'run', ai_id=ai_id)
    with pytest.raises(RuntimeError, match='^AI_BACKGROUND_JOB_FAILED$'):
        finish(jobs, service, ai_id)
    gc.collect()
    assert refs[0]() is None
    assert list(jobs._finished.values())==['FAILED']
    jobs.start(service, 'run', ai_id=ai_id)
    assert len(refs)==1


def test_history_bounded_and_evicted_job_is_unknown_not_restarted(jobs, tmp_path, monkeypatch):
    monkeypatch.setattr(jobs, '_history_limit', 2)
    calls=[]
    def invoke(run_id, **kwargs):
        calls.append(kwargs['ai_id'])
        return {'request':{'parent_run_id':run_id}}
    service=runner(tmp_path, invoke)
    ids=[str(uuid4()) for _ in range(4)]
    for ai_id in ids:
        jobs.start(service, 'run', ai_id=ai_id)
        assert finish(jobs, service, ai_id)=='DONE'
    assert len(jobs._finished)==2
    assert jobs.state(service.store, ids[0])=='UNKNOWN'
    assert len(calls)==4


def test_two_active_jobs_enforced_and_status_scoped_by_store(jobs, tmp_path):
    release=Event()
    def invoke(run_id, **kwargs):
        assert release.wait(5)
        return {'request':{'parent_run_id':run_id}}
    service=runner(tmp_path, invoke)
    ids=[str(uuid4()) for _ in range(3)]
    try:
        for ai_id in ids[:2]:jobs.start(service, 'run', ai_id=ai_id)
        assert jobs.state(service.store, ids[0])=='RUNNING'
        assert jobs.state(SimpleNamespace(root=tmp_path/'other'), ids[0])=='UNKNOWN'
        with pytest.raises(RuntimeError, match='兩個 AI'):
            jobs.start(service, 'run', ai_id=ids[2])
    finally:release.set()
    for ai_id in ids[:2]:assert finish(jobs, service, ai_id)=='DONE'


def test_parent_mismatch_is_controller_failure(jobs, tmp_path):
    service=runner(tmp_path, lambda *args, **kwargs:{'request':{'parent_run_id':'other'}})
    ai_id=str(uuid4())
    jobs.start(service, 'run', ai_id=ai_id)
    with pytest.raises(RuntimeError, match='AI_BACKGROUND_JOB_FAILED'):
        finish(jobs, service, ai_id)
