"""Account-scoped, immutable AI attempts; engineering envelopes stay unchanged."""
import hashlib
import json
from uuid import UUID
from typing import Literal
from pydantic import Field, model_validator
from .contracts import Model

AIStatus = Literal["COMPLETED", "NEEDS_USER_INPUT", "TIMED_OUT", "API_ERROR", "CONNECTION_ERROR",
    "INCOMPLETE", "INVALID_CITATION", "BUDGET_EXHAUSTED", "CONFIG_REQUIRED", "CONSENT_REQUIRED",
    "INPUT_CHANGED_OR_INVALID", "INVALID_MODEL_OUTPUT", "FAILED", "NOT_RUN"]


class AIRequest(Model):
    schema_version: Literal["1.0"] = "1.0"
    ai_id: str
    parent_run_id: str
    engineering_payload_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    context_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    assessment_id: str = Field(min_length=1)
    requested_mode: Literal["LIVE"] = "LIVE"
    consent: bool
    context_text_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    model: str | None = None
    reasoning_effort: str | None = Field(default=None, max_length=30)
    created_at: str
    timeout_seconds: float = Field(gt=0, le=300)

    @model_validator(mode="after")
    def canonical_ids(self):
        for value in (self.ai_id, self.parent_run_id):
            if str(UUID(value)) != value: raise ValueError("Canonical UUID required")
        return self


class AIOutcome(Model):
    ai_id: str
    status: AIStatus
    completed_at: str
    payload_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    error_code: str | None = None

    @model_validator(mode="after")
    def completed_payload(self):
        if self.status in ("COMPLETED", "NEEDS_USER_INPUT") and not self.payload_sha256:
            raise ValueError("Successful AI stage requires a saved result")
        return self


def validate_ai_payload(payload, request):
    if not isinstance(payload, dict) or payload.get("context_hash") != request.context_hash or payload.get("mode") != "LIVE":
        raise ValueError("AI context or mode mismatch")
    entries = payload.get("analyses")
    if not isinstance(entries, list) or len(entries) != 1: raise ValueError("One AI CVE required")
    entry = entries[0]
    if not isinstance(entry, dict) or entry.get("cve_id") != request.cve_id or entry.get("engineering_assessment_id") != request.assessment_id:
        raise ValueError("AI parent assessment mismatch")
    ai = entry.get("ai")
    if not isinstance(ai, dict) or any(ai.get(key) != expected for key, expected in (
        ("context_hash", request.context_hash), ("cve_id", request.cve_id),
        ("engineering_assessment_id", request.assessment_id), ("mode", "LIVE"), ("model", request.model))):
        raise ValueError("AI result scope mismatch")
    status = ai.get("status")
    # Pydantic validates the finite status set, without treating unknown values as success.
    AIOutcome(ai_id=request.ai_id, status=status, completed_at="validation", payload_sha256="0" * 64)
    expected = "COMPLETED" if status in ("COMPLETED", "NEEDS_USER_INPUT") else "INCOMPLETE"
    if payload.get("status") != expected: raise ValueError("AI aggregate status mismatch")
    if status in ("COMPLETED", "NEEDS_USER_INPUT"):
        calls = ai.get("calls")
        if (not request.consent or not ai.get("record_hash") or not isinstance(calls, list) or not calls
                or not all(isinstance(call, dict) and isinstance(call.get("response_id"), str) and call["response_id"] for call in calls)):
            raise ValueError("Completed LIVE requires consent and call receipts")
    record_hash = ai.get("record_hash")
    if record_hash:
        data = {k: v for k, v in ai.items() if k != "record_hash"}
        actual = hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        if record_hash != actual: raise ValueError("AI record digest mismatch")
    followup = entry.get("investigation_verification")
    if followup is not None:
        if not isinstance(followup, dict) or followup.get("context_hash") != request.context_hash or followup.get("cve_id") != request.cve_id:
            raise ValueError("AI followup scope mismatch")
        reassessment = followup.get("assessment") or {}
        if (not isinstance(reassessment, dict) or followup.get("status") != "REVERIFIED_AND_REASSESSED" or reassessment.get("context_hash") != request.context_hash
                or reassessment.get("cve_id") != request.cve_id
                or reassessment.get("verdict") not in ("AFFECTED", "NOT_AFFECTED", "NEEDS_INVESTIGATION")):
            raise ValueError("AI followup assessment mismatch")
    return status


class AIStore:
    def __init__(self, store):
        self.store = store
        self.root = store.root / "ai"
        if self.root.is_symlink(): raise ValueError("AI directory cannot be a symlink")
        self.root.mkdir(exist_ok=True, mode=0o700)

    def path(self, ai_id, suffix):
        if str(UUID(ai_id)) != ai_id: raise ValueError("Canonical AI UUID required")
        path = self.root / (ai_id + "." + suffix + ".json")
        if path.is_symlink(): raise ValueError("AI receipt cannot be a symlink")
        return path

    def begin(self, request):
        self.store._atomic_new(self.path(request.ai_id, "start"), request.model_dump_json(indent=2).encode())

    def finish(self, outcome):
        outcome = AIOutcome.model_validate_json(outcome.model_dump_json())
        self.store._atomic_new(self.path(outcome.ai_id, "end"), outcome.model_dump_json(indent=2).encode())

    def read(self, ai_id):
        from .engineering import read_engineering
        request = AIRequest.model_validate_json(self.path(ai_id, "start").read_bytes())
        if request.ai_id != ai_id: raise ValueError("AI receipt identity mismatch")
        parent = self.store.read(request.parent_run_id)
        engineering = read_engineering(self.store, parent.run_id)
        assessment = engineering["analyses"][0].get("assessment") or {}
        if (parent.engineering_payload_sha256 != request.engineering_payload_sha256
                or parent.cve_id != request.cve_id or parent.input_package.context_hash != request.context_hash
                or assessment.get("assessment_id") != request.assessment_id):
            raise ValueError("AI attempt no longer matches engineering parent")
        result = {"request": request.model_dump(), "status": "NO_TERMINAL_RECEIPT", "outcome": None, "result": None}
        end = self.path(ai_id, "end")
        if end.exists():
            outcome = AIOutcome.model_validate_json(end.read_bytes())
            if outcome.ai_id != ai_id: raise ValueError("AI outcome identity mismatch")
            payload = json.loads(self.store.read_blob(outcome.payload_sha256)) if outcome.payload_sha256 else None
            if payload is not None and validate_ai_payload(payload, request) != outcome.status:
                raise ValueError("AI outcome status mismatch")
            result.update(status=outcome.status, outcome=outcome.model_dump(), result=payload)
        return result

    def history(self, parent_run_id):
        self.store.read(parent_run_id)
        valid, rejected = [], []
        for path in self.root.glob("*.start.json"):
            try:
                if path.is_symlink(): raise ValueError("AI receipt cannot be a symlink")
                request = AIRequest.model_validate_json(path.read_bytes())
                if request.parent_run_id != parent_run_id: continue
                valid.append(self.read(path.name.removesuffix(".start.json")))
            except (ValueError, OSError, KeyError, TypeError):
                rejected.append({"file": path.name, "status": "UNREADABLE_OR_INCOMPATIBLE"})
        return sorted(valid, key=lambda row: row["request"]["created_at"], reverse=True), rejected
