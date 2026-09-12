"""Request grouping only. Engineering/AI semantics stay in core run contracts."""
from typing import Literal
from uuid import UUID
from pydantic import Field, field_validator, model_validator
from .contracts import Model

class RequestSpec(Model):
    request_id: str
    parent_request_id: str | None = None
    symptom: str = Field(default="", max_length=4000)
    cves: list[str] = Field(default_factory=list, max_length=5)
    archive_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    manifest_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")

    @field_validator("request_id", "parent_request_id")
    @classmethod
    def canonical_id(cls, value):
        if value is not None and str(UUID(value)) != value:
            raise ValueError("Canonical UUID required")
        return value

    @field_validator("cves")
    @classmethod
    def valid_cves(cls, values):
        import re
        if len(values) != len(set(values)) or any(not re.fullmatch(r"CVE-\d{4}-\d{4,}", c) for c in values):
            raise ValueError("Unique valid CVE IDs required")
        return values

    @model_validator(mode="after")
    def valid_request(self):
        if self.parent_request_id == self.request_id:
            raise ValueError("Request cannot parent itself")
        if not self.archive_sha256 and not (self.symptom.strip() or self.cves):
            raise ValueError("Provide material, a symptom, or a CVE")
        return self

class RequestRun(Model):
    cve_id: str
    run_id: str
    status: Literal["COLLECTED", "COMPLETED", "FAILED", "TIMED_OUT"]

class RequestResult(Model):
    schema_version: Literal["1.0"] = "1.0"
    spec: RequestSpec
    created_at: str
    status: Literal["DRAFT", "COLLECTED", "PARTIAL", "FAILED"]
    runs: list[RequestRun] = Field(default_factory=list, max_length=5)
    discovery: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def scoped_runs(self):
        if not self.spec.archive_sha256:
            if self.status != "DRAFT" or self.runs:
                raise ValueError("No-file request is a draft, not an analysis")
        else:
            expected = self.spec.cves or [""]
            if [r.cve_id for r in self.runs] != expected:
                raise ValueError("One run per requested CVE is required")
            failed = sum(r.status in ("FAILED", "TIMED_OUT") for r in self.runs)
            status = "FAILED" if failed == len(self.runs) else "PARTIAL" if failed else "COLLECTED"
            if self.status != status:
                raise ValueError("Request status differs from child executions")
        if len({r.run_id for r in self.runs}) != len(self.runs):
            raise ValueError("Child runs must be independent")
        for child in self.runs:
            if str(UUID(child.run_id)) != child.run_id:
                raise ValueError("Invalid child run ID")
        return self
