"""Local UI job lifecycle. A rerender never repeats an API attempt."""
from concurrent.futures import ThreadPoolExecutor
from collections import OrderedDict
from threading import Lock
from uuid import UUID
import json
_pool=ThreadPoolExecutor(max_workers=2,thread_name_prefix='cve-ai')
_jobs={};_lock=Lock()
_finished=OrderedDict()
_history_limit=128


def _collect_finished():
    """Called under the lock; never retain full results or exception frames."""
    for key, future in list(_jobs.items()):
        if not future.done():continue
        _finished[key]=future.result()
        del _jobs[key]
    while len(_finished)>_history_limit:
        _finished.popitem(last=False)


def path(store,ai_id,suffix):
    if str(UUID(ai_id))!=ai_id:raise ValueError('Canonical AI id required')
    root=store.root/'ai-progress'
    if root.is_symlink():raise ValueError('Invalid progress root')
    root.mkdir(mode=0o700,exist_ok=True)
    target=root/(ai_id+suffix)
    if target.is_symlink():raise ValueError('Invalid progress file')
    return target


def start(runner,run_id,**kwargs):
    key=(str(runner.store.root.resolve()),kwargs['ai_id'])
    with _lock:
        _collect_finished()
        if key in _jobs or key in _finished:return
        if len(_jobs)>=2:raise RuntimeError('目前已有兩個 AI 調查，請等待或取消。')
        def invoke():
            try:
                record=runner.investigate_ai(run_id,**kwargs)
                if record['request']['parent_run_id']!=run_id:raise ValueError('AI result parent mismatch')
                return 'DONE'
            except Exception:
                # Durable service receipts contain detailed outcomes when available.
                # Do not retain uploaded content via a Future traceback or message.
                return 'FAILED'
        _jobs[key]=_pool.submit(invoke)


def cancel(store,ai_id):
    p=path(store,ai_id,'.cancel')
    try:p.open('x').close()
    except FileExistsError:pass


def progress(store,ai_id):
    p=path(store,ai_id,'.json')
    if not p.exists():return None
    if p.stat().st_size>16*1024*1024:raise ValueError('Progress size limit')
    row=json.loads(p.read_text())
    from cvevidence_core.integrity import digest
    if not isinstance(row,dict):raise ValueError('Progress must be an object')
    if row.get('record_hash')!=digest({k:v for k,v in row.items() if k!='record_hash'}):raise ValueError('Progress hash mismatch')
    return row


def state(store,ai_id):
    key=(str(store.root.resolve()),ai_id)
    with _lock:
        _collect_finished()
        if key in _jobs:return 'RUNNING'
        result=_finished.get(key,'UNKNOWN')
    if result=='FAILED':raise RuntimeError('AI_BACKGROUND_JOB_FAILED')
    return result
