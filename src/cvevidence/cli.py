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
    intake=sub.add_parser("import",help="Real Horace file-backed intake")
    intake.add_argument("package",type=Path)
    intake.add_argument("--cve",default="")
    intake.add_argument("--symptom",default="")
    delta=sub.add_parser("delta",help="Real same-build delta supplement")
    delta.add_argument("parent_run_id")
    delta.add_argument("--package",type=Path)
    delta.add_argument("--note",default="")
    run=sub.add_parser("run")
    run.add_argument("package", type=Path)
    run.add_argument("--product", required=True)
    run.add_argument("--cve", required=True)
    run.add_argument("--mode", choices=["OFFLINE","LIVE"], default="OFFLINE")
    run.add_argument("--timeout", type=float, default=30)
    read=sub.add_parser("show")
    read.add_argument("run_id")
    sub.add_parser("list")
    supplement=sub.add_parser("supplement")
    supplement.add_argument("parent_run_id")
    supplement.add_argument("--package", type=Path)
    supplement.add_argument("--note", default="")
    export=sub.add_parser("report")
    export.add_argument("run_id")
    args=parser.parse_args(argv)
    try:
        store=RunStore(args.store)
        if args.command=="import":
            result=Runner(store).start_file(args.package,cve=args.cve,symptom=args.symptom)
        elif args.command=="delta":
            result=Runner(store).supplement_file(args.parent_run_id,path=args.package,note=args.note)
        elif args.command=="run":
            with args.package.open("rb") as handle:
                payload=handle.read(MAX_ZIP+1)
            result=Runner(store).start(payload,args.product,args.cve,args.mode,args.timeout)
        elif args.command=="supplement":
            payload=None
            if args.package:
                with args.package.open("rb") as handle:
                    payload=handle.read(MAX_ZIP+1)
            result=Runner(store).supplement(args.parent_run_id,payload,args.note)
        elif args.command=="report":
            from .reports import report
            print(report(store.read(args.run_id)),end="")
            return 0
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
