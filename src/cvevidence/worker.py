"""Trusted adapter is operator-configured; never taken from submitted material."""
import importlib
import os
import sys
from .contracts import EvidenceRecord
from .adapters import CollectedPackage, MAX_UPLOAD, IntakeRejected

def main():
    payload=sys.stdin.buffer.read(MAX_UPLOAD+1)
    if len(payload)>MAX_UPLOAD: return 2
    module=importlib.import_module(os.environ["CVEVIDENCE_CORE_MODULE"])
    if len(sys.argv)>1:
        record=EvidenceRecord.model_validate_json(sys.argv[1])
        content=module.read_evidence_for_runner(payload,record.model_dump())
        if not isinstance(content,bytes) or len(content)>1024*1024:
            return 2
        sys.stdout.buffer.write(content)
        return 0
    try:
        result=module.collect_for_runner(payload)
        collected=CollectedPackage.model_validate(result)
    except IntakeRejected:
        return 2
    sys.stdout.write(collected.model_dump_json())
    return 0

if __name__=="__main__":
    raise SystemExit(main())
