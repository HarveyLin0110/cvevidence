"""Local operator CLI: recheck a downloaded dossier against its exact package."""
import argparse,json
from pathlib import Path
from cvevidence_core.integrity import ingest_package
from cvevidence_core.condition_review import verify_review


def main():
    p=argparse.ArgumentParser(description='覆核條件與證據；保存獨立收據，不改正式判定。')
    p.add_argument('--package',required=True);p.add_argument('--dossier',required=True)
    p.add_argument('--decision',required=True);p.add_argument('--output',required=True)
    a=p.parse_args()
    receipt=verify_review(ingest_package(a.package),json.loads(Path(a.dossier).read_text()),json.loads(Path(a.decision).read_text()))
    with Path(a.output).open('x') as f:json.dump(receipt,f,ensure_ascii=False,indent=2)

if __name__=='__main__':main()
