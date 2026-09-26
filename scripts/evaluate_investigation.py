import argparse,json
from pathlib import Path
from cvevidence_core.quality import evaluate


def main():
    p=argparse.ArgumentParser(description='量測未知 CVE 調查紀錄，不呼叫模型、不自動評斷語意正確。')
    p.add_argument('record');p.add_argument('--previous');p.add_argument('--expected-path',action='append',default=[])
    a=p.parse_args()
    def load(path):
        data=json.loads(Path(path).read_text())
        return data['result']['analyses'][0]['ai'] if 'result' in data else data
    print(json.dumps(evaluate(load(a.record),expected_paths=a.expected_path,previous=load(a.previous) if a.previous else None),ensure_ascii=False,indent=2))
if __name__=='__main__':main()
