"""TEST ONLY. Synthetic adapter responses; not a parser or CVE engine."""
import hashlib
import json
from cvevidence.adapters import IntakeRejected

def collect_for_runner(payload):
    try:
        value=json.loads(payload)
        if value.get("marker")!="TEST_ONLY": raise ValueError()
        content=value["content"].encode()
        missing=value["missing"]
        build=value["build"]
    except (ValueError,KeyError,TypeError):
        raise IntakeRejected("synthetic input rejected")
    return dict(package_id="TEST",release_id="test-release",declared_build_id=build,
        archive_sha256=hashlib.sha256(payload).hexdigest(),
        evidence=[] if missing else [dict(evidence_id="E-001",path="test.txt",
            sha256=hashlib.sha256(content).hexdigest(),size=len(content),kind="source")],
        missing=["test.txt"] if missing else [],
        limitations=["TEST ONLY adapter. No real material or vulnerability validation."])
