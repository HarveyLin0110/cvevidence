"""Integration contract v0.2; semantics require joint review with the core owner."""
from __future__ import annotations
from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, model_validator

class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

class InputPackage(Model):
    product_id: str = Field(min_length=1, max_length=100)
    release_id: str = Field(min_length=1, max_length=100)
    declared_build_id: str = Field(min_length=1, max_length=100)
    package_id: str = Field(min_length=1, max_length=100)
    archive_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    format: Literal["core-adapter-v0.2", "rom", "cmake", "curl", "partial"] = "core-adapter-v0.2"
    context_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    provenance_verified: Literal[False] = False

class EvidenceRecord(Model):
    evidence_id: str = Field(min_length=1)
    path: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size: int = Field(ge=0)
    kind: str
    verification: Literal["HASH_MATCH"] = "HASH_MATCH"

class AIProposal(Model):
    mode: Literal["OFFLINE", "LIVE"]
    explanation: str = Field(max_length=4000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=30)
    questions: list[str] = Field(default_factory=list, max_length=100)

class SourceRecord(Model):
    source_id: str
    path: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size: int = Field(ge=0)
    kind: Literal["file", "symlink"]
    target: str | None = None

class Supplement(Model):
    parent_run_id: str
    kind: Literal["REPLACEMENT_SNAPSHOT", "NOTE", "DELTA"]
    note: str = Field(default="", max_length=4000)
    review_required: Literal[True] = True

class Condition(Model):
    condition_id: str
    state: Literal["TRUE", "FALSE", "UNKNOWN"]
    evidence_ids: list[str] = Field(default_factory=list)

class Assessment(Model):
    verdict: Literal["AFFECTED", "NOT_AFFECTED", "NEEDS_INVESTIGATION"]
    reason: str
    conditions: list[Condition] = Field(min_length=1)
    evidence_ids: list[str] = Field(default_factory=list)
    review_required: Literal[True] = True

class RunError(Model):
    code: Literal["INTAKE_REJECTED", "CORE_UNAVAILABLE", "INTEGRITY_ERROR", "TIMEOUT", "SYSTEM_ERROR"]
    message: str

class RunEnvelope(Model):
    schema_version: Literal["0.2"] = "0.2"
    run_id: str
    parent_run_id: str | None = None
    created_at: str
    cve_id: str = Field(pattern=r"^(CVE-\d{4}-\d{4,})?$")
    mode: Literal["OFFLINE", "LIVE"] = "OFFLINE"
    status: Literal["COLLECTED", "COMPLETED", "FAILED", "TIMED_OUT"]
    input_package: InputPackage | None = None
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    sources: list[SourceRecord] = Field(default_factory=list)
    engineering_status: Literal["NOT_RUN", "COMPLETED", "UNSUPPORTED_CVE"] = "NOT_RUN"
    ai_status: Literal["NOT_RUN", "OFFLINE"] = "NOT_RUN"
    engineering_payload_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    candidates: dict = Field(default_factory=dict)
    missing: list[str] = Field(default_factory=list)
    assessment: Assessment | None = None
    advice: AIProposal | None = None
    supplement: Supplement | None = None
    error: RunError | None = None
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def consistent(self):
        UUID(self.run_id)
        if self.parent_run_id:
            UUID(self.parent_run_id)
            if self.parent_run_id == self.run_id:
                raise ValueError("run cannot parent itself")
        ids = [e.evidence_id for e in self.evidence]
        source_ids = [s.source_id for s in self.sources]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("duplicate source IDs")
        if self.sources and (not self.input_package or not self.input_package.context_hash):
            raise ValueError("sources require bound context hash")
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate evidence IDs")
        legal = set(ids)
        refs = []
        if self.advice:
            if self.advice.mode != self.mode:
                raise ValueError("AI mode differs from run")
            refs += self.advice.evidence_ids
        if self.assessment:
            if not self.cve_id:
                raise ValueError("assessment requires a selected CVE")
            refs += self.assessment.evidence_ids
            for condition in self.assessment.conditions:
                refs += condition.evidence_ids
            if self.status != "COMPLETED":
                raise ValueError("assessment requires completed core analysis")
        if not set(refs) <= legal:
            raise ValueError("evidence reference outside run")
        failed = self.status in ("FAILED", "TIMED_OUT")
        if self.engineering_payload_sha256:
            if (self.status != "COMPLETED" or not self.cve_id or not self.parent_run_id
                    or not self.input_package or not self.input_package.context_hash
                    or self.mode != "OFFLINE" or self.assessment is not None
                    or self.engineering_status == "NOT_RUN"):
                raise ValueError("engineering payload requires scoped completed OFFLINE child")
        elif self.engineering_status != "NOT_RUN" or self.ai_status != "NOT_RUN":
            raise ValueError("engineering stages require saved payload")
        if failed != (self.error is not None):
            raise ValueError("execution failure must carry an error")
        if failed and (self.assessment is not None or self.evidence or self.sources or self.candidates):
            raise ValueError("failed run cannot expose partial evidence or verdict")
        if not failed and self.input_package is None:
            raise ValueError("successful intake requires package metadata")
        if self.supplement and self.supplement.parent_run_id != self.parent_run_id:
            raise ValueError("supplement parent differs from run")
        return self
