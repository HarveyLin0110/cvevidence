"""PYTHONPATH=src python -m cvevidence.cli --help"""
import argparse
from pathlib import Path
import sys
from .adapters import MAX_UPLOAD as MAX_ZIP
from .runner import Runner
from .storage import RunStore

def main(argv=None):
    parser=argparse.ArgumentParser(description="CVEvidence persisted OFFLINE intake; no Q1-Q5 or verdict engine yet.")
    parser.add_argument("--store", default="var")
    sub=parser.add_subparsers(dest="command", required=True)
    run=sub.add_parser("run")
    run.add_argument("package", type=Path)
    run.add_argument("--product", required=True)
    run.add_argument("--cve", required=True)
    run.add_argument("--mode", choices=["OFFLINE","LIVE"], default="OFFLINE")
    run.add_argument("--timeout", type=float, default=30)
    read=sub.add_parser("show")
    read.add_argument("run_id")
    sub.add_parser("list")
    args=parser.parse_args(argv)
    try:
        store=RunStore(args.store)
        if args.command=="run":
            with args.package.open("rb") as handle:
                payload=handle.read(MAX_ZIP+1)
            result=Runner(store).start(payload,args.product,args.cve,args.mode,args.timeout)
        elif args.command=="show":
            result=store.read(args.run_id)
        else:
            for item in store.list_runs():
                print(item.model_dump_json())
            return 0
        print(result.model_dump_json(indent=2))
        return 2 if result.error else 0
    except (ValueError,OSError) as exc:
        print(type(exc).__name__ + ": request or storage failed",file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
