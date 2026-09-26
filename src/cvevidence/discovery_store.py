"""Immutable public-query receipts, scoped to one saved material snapshot."""
import json
from datetime import datetime, timezone
from uuid import uuid4


def directory(store, run_id, *, create=False):
    store.read(run_id)  # Canonical ID and immutable run validation.
    root = store.root / 'public-discovery'
    target = root / run_id
    for path in (root, target):
        if path.is_symlink():
            raise ValueError('Public discovery directory cannot be a symlink')
        if create:
            path.mkdir(exist_ok=True, mode=0o700)
    return target


def save(store, run_id, discovery):
    run = store.read(run_id)
    if not run.input_package or discovery.get('context_hash') != run.input_package.context_hash:
        raise ValueError('Public discovery context mismatch')
    receipt = {'parent_run_id': run_id, 'discovery': discovery}
    sha = store.put_blob(json.dumps(receipt, ensure_ascii=False, sort_keys=True).encode())
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    target = directory(store, run_id, create=True) / (stamp + '-' + uuid4().hex + '.json')
    store._atomic_new(target, json.dumps({'record_sha256': sha}).encode())
    return {**receipt, 'record_sha256': sha}


def latest(store, run_id):
    run = store.read(run_id)
    target = directory(store, run_id)
    if not target.exists():
        return None
    newest = max(target.glob('*.json'), default=None)
    if newest is None:
        return None
    if newest.is_symlink():
        raise ValueError('Public discovery receipt cannot be a symlink')
    sha = json.loads(newest.read_bytes())['record_sha256']
    receipt = json.loads(store.read_blob(sha))
    if (receipt.get('parent_run_id') != run_id or not run.input_package
            or receipt.get('discovery', {}).get('context_hash') != run.input_package.context_hash):
        raise ValueError('Public discovery context mismatch')
    return {**receipt, 'record_sha256': sha}
