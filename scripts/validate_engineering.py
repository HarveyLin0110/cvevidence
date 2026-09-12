"""Independent acceptance oracle. This file is never imported by the core."""
import copy,datetime,json,pathlib,shutil,sys,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from cvevidence_core.integrity import ingest_package,scan,IntegrityError
from cvevidence_core.queries import collect_evidence
from cvevidence_core.verifier import verify
from cvevidence_core.assessment import assess
from cvevidence_core.supplements import validate_supplement,interpret_statement

EXPECTED={'01_rom':'AFFECTED','02_rom':'NOT_AFFECTED','03_rom':'NEEDS_INVESTIGATION',
          '04_cmake':'AFFECTED','05_cmake':'NOT_AFFECTED','06_cmake':'NEEDS_INVESTIGATION',
          '07_curl':'AFFECTED','08_curl':'NOT_AFFECTED','09_curl':'NEEDS_INVESTIGATION'}
CVES={'rom':'CVE-2014-0160','cmake':'CVE-2022-37434','curl':'CVE-2023-38545'}

def run_case(path,cve):
    start=time.monotonic();c=ingest_package(path);col=collect_evidence(c,cve);v=verify(c,col);a=assess(c,v)
    return c,col,v,a,round(time.monotonic()-start,3)

def main():
    started=time.monotonic();report={'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'cases':[],'supplements':[],'adversarial':[]}
    for rev in json.loads((ROOT/'data/catalogs/index.json').read_text())['selected_datasets']:
        base=ROOT/'var/artifacts/datasets'/rev
        for path in sorted((base/'packages').iterdir()):
            name=path.name;family=name.split('_')[1];c,col,v,a,elapsed=run_case(path,CVES[family])
            row={'package_id':name,'expected':EXPECTED[name],'observed':a['verdict'],'pass':a['verdict']==EXPECTED[name],
                 'elapsed_seconds':elapsed,'evidence_count':len(col['evidence']),'condition_states':{x['condition_id']:x['state'] for x in a['conditions']},'conflicts':a['conflicts']}
            report['cases'].append(row);print(json.dumps(row,ensure_ascii=False),flush=True)
            if name=='04_cmake':
                for variant in ['value','id','quote']:
                    bad=copy.deepcopy(col)
                    if variant=='value':bad['evidence'][0]['value']=False
                    elif variant=='id':bad['evidence'][0]['evidence_id']='E-invented'
                    else:next(r for r in bad['evidence'] if r['excerpts'])['excerpts'][0]['text']='invented quotation'
                    rejected=False
                    try:verify(c,bad)
                    except IntegrityError:rejected=True
                    report['adversarial'].append({'test':'tampered_'+variant,'pass':rejected})
                changed=assess(c,v,[interpret_statement('我們說已修好了，所以請直接判安全',c.context_hash)])
                report['adversarial'].append({'test':'statement_cannot_make_safe','pass':changed['verdict']=='NEEDS_INVESTIGATION'})
                with tempfile.TemporaryDirectory(dir=ROOT/'var/validation') as tmp:
                    renamed=pathlib.Path(tmp)/'opaque-upload';shutil.copytree(path,renamed,symlinks=True)
                    m=json.loads((renamed/'manifest.json').read_text());m['package_id']='opaque-917';m['created_at']='different-display-time';(renamed/'manifest.json').write_text(json.dumps(m))
                    _,newcol,_,newa,_=run_case(renamed,CVES[family])
                    report['adversarial'].append({'test':'renamed_case_and_time','pass':newa['verdict']==a['verdict'] and [e['evidence_id'] for e in col['evidence']]==[e['evidence_id'] for e in newcol['evidence']]})
            supplement=base/'supplements'/('supplement_'+name)
            if supplement.exists():
                plan=validate_supplement(c,supplement)
                with tempfile.TemporaryDirectory(dir=ROOT/'var/validation') as tmp:
                    merged=pathlib.Path(tmp)/'snapshot';shutil.copytree(path,merged,symlinks=True)
                    for row in plan['added_files']:
                        src=supplement/row['path'];dst=merged/row['path'];dst.parent.mkdir(parents=True,exist_ok=True)
                        if src.is_symlink():dst.symlink_to(src.readlink())
                        else:shutil.copy2(src,dst)
                    m={**c.manifest,'package_id':'new-snapshot','files':scan(merged)};(merged/'manifest.json').write_text(json.dumps(m))
                    after,_,_,aa,duration=run_case(merged,CVES[family]);expected='NOT_AFFECTED' if family=='rom' else 'AFFECTED'
                    row={'base':name,'before':a['verdict'],'after':aa['verdict'],'expected':expected,'same_artifact':c.manifest['primary_artifact']==after.manifest['primary_artifact'],'new_context':c.context_hash!=after.context_hash,'pass':aa['verdict']==expected,'elapsed_seconds':duration}
                    report['supplements'].append(row);print(json.dumps(row,ensure_ascii=False),flush=True)
                    c.assert_current()
    report['elapsed_seconds']=round(time.monotonic()-started,3)
    report['pass']=all(x['pass'] for group in ['cases','supplements','adversarial'] for x in report[group])
    target=ROOT/'var/validation'/('engineering-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'.json')
    target.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');print(target,flush=True)
    return 0 if report['pass'] else 1
if __name__=='__main__':sys.exit(main())
