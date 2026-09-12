from uuid import uuid4
import pytest
from pydantic import ValidationError
from cvevidence.contracts import RunEnvelope

def envelope():
    return dict(run_id=str(uuid4()), created_at="2026-09-12T00:00:00Z",
        cve_id="CVE-2014-0160", status="COLLECTED",
        input_package=dict(product_id="TEST", release_id="test", declared_build_id="test",
            package_id="test", archive_sha256="a"*64),
        evidence=[dict(evidence_id="E-001", path="x", sha256="a"*64, size=1, kind="source")])

def test_collected_has_no_verdict():
    run = RunEnvelope.model_validate(envelope())
    assert run.assessment is None
    assert not run.input_package.provenance_verified

@pytest.mark.parametrize("change", [
    {"advice": dict(mode="OFFLINE", explanation="test", evidence_ids=["OTHER"])},
    {"advice": dict(mode="LIVE", explanation="test")},
    {"status":"FAILED"},
    {"status":"FAILED", "error":dict(code="SYSTEM_ERROR",message="test")},
    {"assessment":dict(verdict="NOT_AFFECTED",reason="test",
        conditions=[dict(condition_id="PC1",state="FALSE")])},
    {"extra":"forbidden"},
])
def test_invalid_contracts(change):
    with pytest.raises(ValidationError):
        RunEnvelope.model_validate(envelope() | change)

def test_duplicate_ids():
    data=envelope()
    data["evidence"] *= 2
    with pytest.raises(ValidationError):
        RunEnvelope.model_validate(data)

def test_ai_cannot_supply_verdict():
    data=envelope()
    data["advice"]=dict(mode="OFFLINE",explanation="test",verdict="NOT_AFFECTED")
    with pytest.raises(ValidationError):
        RunEnvelope.model_validate(data)
