"""Immutable requests, fixed archive snapshots and replay-safe submissions."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
from time import monotonic
from uuid import UUID, uuid4
from .core_service import CoreService
from .request_contracts import RequestSpec, RequestResult, RequestRun

class RequestBusy(ValueError):
    pass

def parse_cves(text):
    if not isinstance(text,str) or len(text)>1000:
        raise ValueError("Invalid CVE input")
    values=list(dict.fromkeys(c.upper() for c in re.split(r"[,，;；\s]+",text.strip()) if c))
    # Use the same constraints in UI/CLI as persistent requests.
    RequestSpec(request_id=str(uuid4()),cves=values,symptom="validation")
    return values

class RequestStore:
    def __init__(self, run_store):
        self.store=run_store
        self.root=run_store.root/"requests"
        if self.root.is_symlink(): raise ValueError("Request root cannot be a symlink")
        self.root.mkdir(exist_ok=True,mode=0o700)

    def path(self, request_id, suffix=".json"):
        if str(UUID(request_id))!=request_id: raise ValueError("Canonical request UUID required")
        return self.root/(request_id+suffix)

    def read(self, request_id):
        path=self.path(request_id)
        if path.is_symlink(): raise ValueError("Request cannot be a symlink")
        result=RequestResult.model_validate_json(path.read_bytes())
        if result.spec.request_id!=request_id: raise ValueError("Request identity mismatch")
        for child in result.runs:
            run=self.store.read(child.run_id)
            if run.cve_id!=child.cve_id or run.status!=child.status:
                raise ValueError("Child scope/status mismatch")
            if run.input_package and run.input_package.archive_sha256!=result.spec.archive_sha256:
                raise ValueError("Child archive mismatch")
        return result

    def history(self):
        valid,rejected=[],[]
        for path in self.root.glob("*.json"):
            try: valid.append(self.read(path.stem))
            except (ValueError,OSError): rejected.append(path.name)
        return sorted(valid,key=lambda r:r.created_at,reverse=True),rejected

    def save(self, result):
        result=RequestResult.model_validate_json(result.model_dump_json())
        self.store._atomic_new(self.path(result.spec.request_id),result.model_dump_json(indent=2).encode())

def submit(runner, *, cves=None, symptom="", path=None, stream=None, request_id=None,
           parent_request_id=None, archive_sha256=None, manifest_sha256=None, timeout=120):
    if not 0 < timeout <= 300: raise ValueError("Invalid request deadline")
    deadline=monotonic()+timeout
    request_id=request_id or str(uuid4())
    # Validate metadata before retaining a submitted archive.
    requested=cves if cves is not None else []
    RequestSpec(request_id=request_id,parent_request_id=parent_request_id,cves=requested,
        symptom=symptom,archive_sha256=archive_sha256 or ("0"*64 if path is not None or stream is not None else None),
        manifest_sha256=manifest_sha256)
    if path is not None and stream is not None: raise ValueError("Choose one material source")
    if path is None and stream is None and archive_sha256:
        raise ValueError("A digest alone is not an input file")
    store=RequestStore(runner.store)
    if parent_request_id: store.read(parent_request_id)
    core=CoreService(runner.store)
    sha=(core.retain_stream(stream,archive_sha256) if stream is not None else
         core.retain(path,archive_sha256) if path is not None else None)
    spec=RequestSpec(request_id=request_id,parent_request_id=parent_request_id,cves=requested,
        symptom=symptom,archive_sha256=sha,manifest_sha256=manifest_sha256)
    target=store.path(request_id)
    if target.exists():
        old=store.read(request_id)
        if old.spec!=spec: raise ValueError("Request ID already belongs to different input")
        return old
    lock=store.path(request_id,".lock")
    try:
        runner.store._atomic_new(lock,spec.model_dump_json().encode())
    except FileExistsError:
        if target.exists():
            old=store.read(request_id)
            if old.spec==spec: return old
        raise RequestBusy("Request is active or interrupted; inspect it before creating a new request")
    # On an unexpected crash leave the lock in place. Never silently rerun an ambiguous request.
    if sha is None:
        from cvevidence_core.catalog import discover_candidates
        result=RequestResult(spec=spec,created_at=datetime.now(timezone.utc).isoformat(),
            status="DRAFT",discovery=discover_candidates(symptom=symptom,requested_cves=requested))
    else:
        rows=[]
        frozen=runner.store.root/"blobs"/sha
        for cve in requested or [""]:
            remaining=deadline-monotonic()
            if remaining<=0:
                run=core.failed(cve,subprocess.TimeoutExpired("request",timeout))
                runner.store.save(run)
            else:
                run=runner.start_file(frozen,cve=cve,symptom=symptom,archive_sha256=sha,
                    manifest_sha256=manifest_sha256,timeout=remaining)
            rows.append(RequestRun(cve_id=cve,run_id=run.run_id,status=run.status))
        failed=sum(r.status in ("FAILED","TIMED_OUT") for r in rows)
        result=RequestResult(spec=spec,created_at=datetime.now(timezone.utc).isoformat(),
            status="FAILED" if failed==len(rows) else "PARTIAL" if failed else "COLLECTED",runs=rows)
    store.save(result)
    lock.unlink()
    return result
