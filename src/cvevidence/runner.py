"""UI and CLI share this runner. No CVE decision is inferred from intake."""
from datetime import datetime, timezone
import subprocess
from time import monotonic
from uuid import uuid4
from .adapters import MAX_UPLOAD as MAX_ZIP, IntakeRejected as IntakeError, CoreUnavailable
from .adapters import CoreAdapter
from .contracts import InputPackage, EvidenceRecord, RunEnvelope, RunError
from .storage import RunStore

class Runner:
    def submit_request(self, **kwargs):
        from .requests import submit
        return submit(self, **kwargs)

    def read_request(self, request_id):
        from .requests import RequestStore
        return RequestStore(self.store).read(request_id)

    def start_file(self, path=None, **kwargs):
        from .core_service import CoreService
        return CoreService(self.store).start(path, **kwargs)

    def source_tool(self, run_id, operation, **arguments):
        from .events import invoke_with_receipt
        return invoke_with_receipt(self, run_id, operation, arguments)

    def tool_history(self, run_id):
        from .events import EventStore
        return EventStore(self.store).read(run_id)

    def supplement_file(self, parent_id, **kwargs):
        from .core_service import CoreService
        return CoreService(self.store).supplement(parent_id, **kwargs)

    def __init__(self, store: RunStore, adapter=None):
        self.store = store
        self.adapter = adapter or CoreAdapter()

    def _collect(self, payload: bytes, product_id: str, cve_id: str,
              mode="OFFLINE", timeout=30.0):
        if not 0 < timeout <= 300:
            raise ValueError("timeout must be between 0 and 300 seconds")
        # Validate caller metadata before doing work or saving anything.
        from pydantic import TypeAdapter
        from typing import Annotated
        from pydantic import StringConstraints
        TypeAdapter(Annotated[str, StringConstraints(min_length=1, max_length=100)]).validate_python(product_id, strict=True)
        TypeAdapter(Annotated[str, StringConstraints(pattern=r"^CVE-\d{4}-\d{4,}$")]).validate_python(cve_id, strict=True)
        if mode not in ("OFFLINE", "LIVE"):
            raise ValueError("unknown analysis mode")
        run_id = str(uuid4())
        created = datetime.now(timezone.utc).isoformat()
        base = dict(run_id=run_id, created_at=created, cve_id=cve_id, mode=mode)
        started = monotonic()
        try:
            if mode == "LIVE":
                run = RunEnvelope(**base, status="FAILED",
                    error=RunError(code="CORE_UNAVAILABLE", message="LIVE core is not connected; start a separate OFFLINE run."))
            else:
                if len(payload) > MAX_ZIP:
                    raise IntakeError("ZIP exceeds 20 MiB")
                collected = self.adapter.collect(payload, timeout)
                if monotonic() - started >= timeout:
                    raise subprocess.TimeoutExpired("intake", timeout)
                package = InputPackage(product_id=product_id, release_id=collected.release_id,
                    declared_build_id=collected.declared_build_id, package_id=collected.package_id,
                    archive_sha256=collected.archive_sha256)
                run = RunEnvelope(**base, status="COLLECTED", input_package=package,
                    evidence=[EvidenceRecord(**e.model_dump()) for e in collected.evidence],
                    missing=collected.missing, limitations=collected.limitations + [
                        "Q1-Q5, PC rules and runtime AI await the core adapter. assessment is null."])
                digest = self.store.put_blob(payload)
                if digest != package.archive_sha256:
                    raise ValueError("adapter archive digest mismatch")
        except CoreUnavailable:
            run = RunEnvelope(**base, status="FAILED",
                error=RunError(code="CORE_UNAVAILABLE", message="Horace core adapter is not connected. No analysis was performed."))
        except IntakeError:
            run = RunEnvelope(**base, status="FAILED",
                error=RunError(code="INTAKE_REJECTED", message="Package failed bounded intake validation. No assessment was performed."))
        except subprocess.TimeoutExpired:
            run = RunEnvelope(**base, status="TIMED_OUT",
                error=RunError(code="TIMEOUT", message="Intake worker exceeded deadline and was terminated."))
        except Exception:
            run = RunEnvelope(**base, status="FAILED",
                error=RunError(code="SYSTEM_ERROR", message="Integration failed. No partial result is published."))
        return run

    def start(self, payload, product_id, cve_id, mode='OFFLINE', timeout=30.0):
        run = self._collect(payload, product_id, cve_id, mode, timeout)
        self.store.save(run)
        return run

    def supplement(self, parent_run_id, payload=None, note="", timeout=30.0):
        from .contracts import Supplement
        parent = self.store.read(parent_run_id)
        if parent.error or parent.input_package is None:
            raise ValueError("cannot supplement a failed intake; create a new run")
        if payload is None and not note.strip():
            raise ValueError("provide replacement snapshot or a note")
        metadata = Supplement(parent_run_id=parent_run_id,
            kind="NOTE" if payload is None else "REPLACEMENT_SNAPSHOT", note=note)
        if payload is None:
            # A note is pending material, not new verified facts or a copied verdict.
            values = parent.model_dump()
            values.update(run_id=str(uuid4()), created_at=datetime.now(timezone.utc).isoformat(),
                          status="COLLECTED", assessment=None, advice=None, mode="OFFLINE")
            values["limitations"] = list(parent.limitations) + ["Text supplement is unverified; no rules rerun."]
            run = RunEnvelope.model_validate(values)
        else:
            run = self._collect(payload, parent.input_package.product_id, parent.cve_id, "OFFLINE", timeout)
            if not run.error:
                old, new = parent.input_package, run.input_package
                previous = {e.path: e.sha256 for e in parent.evidence}
                incoming = {e.path: e.sha256 for e in run.evidence}
                compatible = (old.release_id == new.release_id and
                              old.declared_build_id == new.declared_build_id and
                              all(incoming.get(path) == sha for path, sha in previous.items()))
                if not compatible:
                    run = RunEnvelope(run_id=run.run_id, created_at=run.created_at,
                        cve_id=parent.cve_id, status="FAILED",
                        error=RunError(code="INTEGRITY_ERROR", message="Replacement changes release/build or removes/changes existing evidence."))
        values = run.model_dump()
        values.update(parent_run_id=parent_run_id, supplement=metadata.model_dump())
        run = RunEnvelope.model_validate(values)
        self.store.save(run)
        return run

    # Names requested in the shared integration proposal.
    run_analysis = start
    save_supplement = supplement
