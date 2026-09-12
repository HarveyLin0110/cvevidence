"""Trusted adapter is operator-configured; never taken from submitted material."""
import importlib
import os
import sys
from .adapters import CollectedPackage, MAX_UPLOAD, IntakeRejected

def main():
    payload=sys.stdin.buffer.read(MAX_UPLOAD+1)
    if len(payload)>MAX_UPLOAD: return 2
    module=importlib.import_module(os.environ["CVEVIDENCE_CORE_MODULE"])
    try:
        result=module.collect_for_runner(payload)
        collected=CollectedPackage.model_validate(result)
    except IntakeRejected:
        return 2
    sys.stdout.write(collected.model_dump_json())
    return 0

if __name__=="__main__":
    raise SystemExit(main())
