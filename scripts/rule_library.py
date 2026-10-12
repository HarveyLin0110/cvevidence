"""Operator-only review/release/rollback of public investigation templates."""
import argparse
import json
from pathlib import Path
from cvevidence_core.rule_library import draft,review,install,activate,select


def main():
    p=argparse.ArgumentParser(description='CVE 調查規則：草稿 → 逐條覆核 → 發布／啟用；不自動改漏洞判定')
    p.add_argument('--library',type=Path)
    commands=p.add_subparsers(dest='command',required=True)
    d=commands.add_parser('draft');d.add_argument('investigation',type=Path);d.add_argument('output',type=Path)
    r=commands.add_parser('review');r.add_argument('draft',type=Path)
    for name in ('reviewer','rationale','applicability','validation-reference'):r.add_argument('--'+name,required=True)
    a=commands.add_parser('activate');a.add_argument('cve');a.add_argument('revision')
    c=commands.add_parser('check');c.add_argument('cve');c.add_argument('public_sources',type=Path)
    args=p.parse_args()
    if args.command=='draft':
        data=json.loads(args.investigation.read_text())
        # Accept both core results and the actual UI AI-download envelope.
        if 'result' in data:data=data['result']
        if not isinstance(data,dict):raise ValueError('AI 調查尚無可用結果')
        if 'analyses' in data:
            if len(data['analyses'])!=1:raise ValueError('請選取單一 CVE 的 AI 調查紀錄')
            data=data['analyses'][0]['ai']
        rule=draft(data)
        with args.output.open('x',encoding='utf-8') as out:json.dump(rule,out,ensure_ascii=False,indent=2)
        print('已建立未核准草稿：'+str(args.output))
    elif args.command=='review':
        rule=review(json.loads(args.draft.read_text()),reviewer=args.reviewer,rationale=args.rationale,
                    applicability=args.applicability,validation_reference=args.validation_reference)
        print(install(rule,args.library));print('覆核版本已保存，尚未啟用：'+rule['rule_hash'])
    elif args.command=='activate':
        activate(args.cve,args.revision,args.library);print('已啟用指定版本；舊版本仍可回復。')
    else:print(json.dumps(select(args.cve,json.loads(args.public_sources.read_text())['sources'],args.library),ensure_ascii=False,indent=2))


if __name__=='__main__':main()
