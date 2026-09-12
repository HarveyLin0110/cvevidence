"""Explicit live acceptance. Four small, independently reviewed scenarios."""
import datetime,json,pathlib,sys,time
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from cvevidence_core.workflow import analyze_package

CASES=[
 ('rom_missing','fresh-rom-r2','03_rom','CVE-2014-0160','掃描只憑 OpenSSL 1.0.1f 就說有 Heartbleed。同事口述有關掉 heartbeat，但沒附命令。請核對现有資料並列出最小補件。'),
 ('cmake_symptom','fresh-cmake-r2','04_cmake','CVE-2022-37434','更新匯入失敗，gzip stream ended before trailer。請查現有正常與截短測試紀錄，確認這種錯誤能否直接歸因 CVE。'),
 ('curl_missing','fresh-curl-r2','09_curl','CVE-2023-38545','更新下載經 SOCKS5，偶爾握手慢。我不知道 DNS 在哪裡解析，請確認還缺什麼執行設定。'),
 ('curl_early_material','fresh-curl-r2','07_curl','CVE-2023-38545','launcher、download.conf 與正常 SOCKS5 觀測已經在提交資料中。請直接檢查現有檔案的 DNS、limit-rate 與握手觀測；分開說明程式有受影響條件和正常測試是否已重現漏洞。')]

def main(selected=None):
 stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%f');folder=ROOT/'var/validation'/('live-'+stamp);folder.mkdir()
 rows=[]
 for name,rev,package,cve,symptom in CASES:
  if selected and selected!=name:continue
  result=analyze_package(ROOT/'var/artifacts/datasets'/rev/'packages'/package,[cve],symptom,mode='LIVE',env_file=ROOT/'.env.local')
  (folder/(name+'.json')).write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');ai=result['analyses'][0]['ai']
  row={'case':name,'package_id':package,'model':ai['model'],'status':ai['status'],'seconds':ai['elapsed_seconds'],
       'actions':[t['action'] for t in ai['tasks']],'questions':[t['question'] for t in ai['tasks']],
       'citations_valid':all(t['citation_verification']['valid'] for t in ai['tasks'] if t['status']=='COMPLETED'),
       'rejected_proposals':sum(t['status']=='REJECTED' for t in ai['tasks']),
       'transport_gate':ai['mode']=='LIVE' and bool(ai['calls']) and ai['status'] in ['COMPLETED','NEEDS_USER_INPUT'],
       'semantic_review':'待人工閱讀原文與調查問題；不可把傳輸成功当語意正確'}
  rows.append(row);print(json.dumps(row,ensure_ascii=False),flush=True)
 (folder/'summary.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2)+'\n');print(folder,flush=True)
 return 0 if all(r['transport_gate'] and r['citations_valid'] for r in rows) else 1
if __name__=='__main__':sys.exit(main(sys.argv[1] if len(sys.argv)>1 else None))
