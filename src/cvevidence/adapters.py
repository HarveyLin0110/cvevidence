"""Fresh process boundary for Horace's trusted Python adapter."""
import os
from pathlib import Path
import subprocess
import sys
from pydantic import Field
from .contracts import Model, EvidenceRecord

MAX_UPLOAD=20*1024*1024

class IntakeRejected(ValueError): pass
class CoreUnavailable(RuntimeError): pass

class CollectedPackage(Model):
    package_id: str
    release_id: str
    declared_build_id: str
    archive_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    evidence: list[EvidenceRecord]
    missing: list[str]
    limitations: list[str]

class CoreAdapter:
    def collect(self, payload, timeout):
        if not os.environ.get("CVEVIDENCE_CORE_MODULE"):
            raise CoreUnavailable("core adapter not configured")
        source=Path(__file__).resolve().parents[1]
        env=dict(os.environ)
        env["PYTHONPATH"]=os.pathsep.join((str(source),str(source.parent)))
        result=subprocess.run([sys.executable,"-m","cvevidence.worker"],
            input=payload,capture_output=True,timeout=timeout,env=env)
        if result.returncode==2: raise IntakeRejected("core rejected input")
        if result.returncode: raise RuntimeError("core worker failed")
        return CollectedPackage.model_validate_json(result.stdout)
