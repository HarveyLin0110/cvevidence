"""Immutable local operator reviews bound to one saved AI dossier and run."""
import json
from datetime import datetime, timezone
from uuid import uuid4, UUID
from cvevidence_core.integrity import digest
from .ai_store import AIStore
from .core_service import CoreService


class ReviewStore:
    def __init__(self, store):
        self.store = store
        self.root = store.root / 'condition-reviews'
        if self.root.is_symlink():
            raise ValueError('Invalid review store')
        self.root.mkdir(mode=0o700, exist_ok=True)

    def path(self, review_id):
        if str(UUID(review_id)) != review_id:
            raise ValueError('Canonical review ID required')
        return self.root / (review_id + '.json')

    def subject(self, run_id, ai_id):
        run = self.store.read(run_id)
        record = AIStore(self.store).read(ai_id)
        if record['request']['parent_run_id'] != run_id or not record.get('result'):
            raise ValueError('Review requires saved AI from this exact run')
        ai = record['result']['analyses'][0]['ai']
        dossier = ai.get('condition_dossier')
        if not dossier or dossier.get('context_hash') != run.input_package.context_hash or dossier.get('cve_id') != run.cve_id:
            raise ValueError('This AI has no matching condition dossier')
        if dossier.get('dossier_hash') != digest({k:v for k,v in dossier.items() if k != 'dossier_hash'}):
            raise ValueError('Dossier integrity mismatch')
        return run, record, ai, dossier

    def save(self, run_id, ai_id, decision, *, review_id=None):
        run, record, ai, dossier = self.subject(run_id, ai_id)
        review_id = review_id or str(uuid4())
        target = self.path(review_id)
        identity = dict(run_id=run_id, ai_id=ai_id, context_hash=run.input_package.context_hash,
                        cve_id=run.cve_id, ai_payload_sha256=record['outcome']['payload_sha256'],
                        dossier_hash=dossier['dossier_hash'], decision_hash=digest(decision))
        if target.exists():
            existing = self.read(review_id, run_id, ai_id)
            if any(existing.get(k) != v for k,v in identity.items()):
                raise ValueError('Review ID already belongs to different input')
            return existing
        # The worker reopens the immutable product archive and checks original bytes.
        raw = json.dumps({'ai':ai, 'decision':decision}, ensure_ascii=False, allow_nan=False).encode()
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError('Review input limit')
        payload_sha = self.store.put_blob(raw)
        receipt = CoreService(self.store).invoke('review_conditions',run.input_package.archive_sha256,
            run.input_package.context_hash, review_payload_sha256=payload_sha)
        if receipt.get('dossier_hash') != dossier['dossier_hash'] or receipt.get('context_hash') != identity['context_hash'] or receipt.get('cve_id') != run.cve_id:
            raise ValueError('Review result scope mismatch')
        result = dict(schema_version='1.0', review_id=review_id, created_at=datetime.now(timezone.utc).isoformat(),
                      **identity, receipt=receipt)
        result['record_hash'] = digest(result)
        try:
            self.store._atomic_new(target, json.dumps(result,ensure_ascii=False,sort_keys=True).encode())
        except FileExistsError:
            existing = self.read(review_id, run_id, ai_id)
            if any(existing.get(k) != v for k,v in identity.items()):
                raise ValueError('Concurrent review ID conflict')
            return existing
        return self.read(review_id, run_id, ai_id)

    def read(self, review_id, run_id, ai_id):
        path = self.path(review_id)
        if path.is_symlink() or path.stat().st_size > 1024 * 1024:
            raise ValueError('Invalid review file')
        row = json.loads(path.read_bytes())
        if not isinstance(row,dict):
            raise ValueError('Review must be an object')
        if row.get('record_hash') != digest({k:v for k,v in row.items() if k != 'record_hash'}):
            raise ValueError('Review integrity mismatch')
        run, record, ai, dossier = self.subject(run_id, ai_id)
        expected = dict(review_id=review_id, run_id=run_id, ai_id=ai_id, context_hash=run.input_package.context_hash,
                        cve_id=run.cve_id, ai_payload_sha256=record['outcome']['payload_sha256'], dossier_hash=dossier['dossier_hash'])
        if any(row.get(k) != v for k,v in expected.items()):
            raise ValueError('Review scope mismatch')
        receipt = row['receipt']
        if not isinstance(receipt,dict):
            raise ValueError('Invalid review receipt')
        if receipt.get('receipt_hash') != digest({k:v for k,v in receipt.items() if k != 'receipt_hash'}):
            raise ValueError('Review receipt changed')
        if any(receipt.get(k) != expected[k] for k in ('context_hash','cve_id','dossier_hash')):
            raise ValueError('Review receipt scope mismatch')
        if receipt.get('formal_verdict_unchanged') is not True or receipt.get('reviewer_authenticated') is not False:
            raise ValueError('Unsupported review authority')
        return row

    def history(self, run_id, ai_id):
        self.subject(run_id, ai_id)
        valid, rejected = [], []
        for path in self.root.glob('*.json'):
            try:
                if path.is_symlink() or path.stat().st_size > 1024 * 1024:
                    raise ValueError('Invalid review file')
                row = json.loads(path.read_bytes())
                if not isinstance(row,dict):
                    raise ValueError('Review must be an object')
                if row.get('run_id') != run_id or row.get('ai_id') != ai_id:
                    continue
                valid.append(self.read(path.stem, run_id, ai_id))
            except (ValueError, OSError, KeyError, TypeError):
                rejected.append(path.name)
        return sorted(valid,key=lambda r:r['created_at'],reverse=True), rejected
