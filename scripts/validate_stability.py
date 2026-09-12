"""Ten offline reruns of each live-demo input; no API and no preset core answers."""
import datetime,json,pathlib,sys,time
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from cvevidence_core.workflow import analyze_package

def main():
    cases=[('fresh-rom-r2','03_rom','CVE-2014-0160'),('fresh-cmake-r2','04_cmake','CVE-2022-37434'),('fresh-curl-r2','09_curl','CVE-2023-38545')]
    expected={};rows=[];started=time.monotonic()
    for round_no in range(1,11):
        for rev,name,cve in cases:
            start=time.monotonic();r=analyze_package(ROOT/'var/artifacts/datasets'/rev/'packages'/name,[cve],mode='OFFLINE');a=r['analyses'][0]
            observed={'verdict':a['assessment']['verdict'],'assessment_id':a['assessment']['assessment_id'],'evidence_ids':[e['evidence_id'] for e in a['evidence']]}
            expected.setdefault(name,observed)
            rows.append({'round':round_no,'package_id':name,'pass':observed==expected[name] and a['ai']['status']=='OFFLINE','seconds':round(time.monotonic()-start,3)})
        print(json.dumps({'round':round_no,'pass':all(x['pass'] for x in rows[-3:])}),flush=True)
    report={'scope':'三個主展示輸入各重跑 10 次，共 30 次 OFFLINE；不是九包各跑 10 次。','cases':rows,'pass':all(x['pass'] for x in rows),'seconds':round(time.monotonic()-started,3)}
    output=ROOT/'var/validation'/('stability-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'.json');output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');print(output)
    return 0 if report['pass'] else 1
if __name__=='__main__':sys.exit(main())
