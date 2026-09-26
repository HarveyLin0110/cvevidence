"""Offline backup/verify/restore; never uploads company evidence."""
import argparse
import json
from pathlib import Path
import sys
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from cvevidence.backup import create,verify,restore


def main():
    parser=argparse.ArgumentParser(description='本機案件備份／驗證／還原；請先停止工作區寫入，備份檔未加密。')
    sub=parser.add_subparsers(dest='command',required=True)
    p=sub.add_parser('create',help='備份單一帳號工作區，不包含金鑰與設定')
    p.add_argument('--store',required=True);p.add_argument('--output',required=True)
    p=sub.add_parser('verify',help='核對備份所有檔案的大小與 SHA256')
    p.add_argument('archive')
    p=sub.add_parser('restore',help='還原到不存在的新資料夾，不覆蓋既有工作區')
    p.add_argument('archive');p.add_argument('--destination',required=True)
    args=parser.parse_args()
    try:
        if args.command=='create':result=create(args.store,args.output)
        elif args.command=='verify':result=verify(args.archive)
        else:result=restore(args.archive,args.destination)
    except (ValueError,OSError,zipfile.BadZipFile,KeyError,RuntimeError) as exc:
        print('未完成：'+(str(exc) if type(exc) is ValueError else '檔案不可讀、格式錯誤或儲存失敗。'),file=sys.stderr)
        return 1
    print(json.dumps({'status':'完成',**result,'note':'未加密；請依公司資料政策保管。雜湊完整性不等於來源認證。'},ensure_ascii=False))
    return 0


if __name__=='__main__':raise SystemExit(main())
