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
    def __init__(self, store: RunStore, adapter=None):
        self.store = store
        self.adapter = adapter or CoreAdapter()

    def start(self, payload: bytes, product_id: str, cve_id: str,
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
        # Save errors propagate: never claim success if persistence failed.
        self.store.save(run)
        return run
