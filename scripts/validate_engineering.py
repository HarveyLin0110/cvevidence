"""Independent acceptance oracle. This file is never imported by the core."""
import copy,datetime,json,pathlib,shutil,sys,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from cvevidence_core.integrity import ingest_package,scan,IntegrityError,safe_extract,file_hash
from cvevidence_core.queries import collect_evidence
from cvevidence_core.verifier import verify
from cvevidence_core.assessment import assess
from cvevidence_core.supplements import validate_supplement,interpret_statement

EXPECTED={'01_rom':'NEEDS_INVESTIGATION','02_rom':'NOT_AFFECTED','03_rom':'NEEDS_INVESTIGATION',
          '04_cmake':'NEEDS_INVESTIGATION','05_cmake':'NOT_AFFECTED','06_cmake':'NEEDS_INVESTIGATION',
          '07_curl':'NEEDS_INVESTIGATION','08_curl':'NOT_AFFECTED','09_curl':'NEEDS_INVESTIGATION'}
EXPECTED.update({f'pc3_{family}_static':'NEEDS_INVESTIGATION' for family in ('rom','cmake','curl')})
STATIC_COMPLETE={'01_rom','04_cmake','07_curl','pc3_rom_static','pc3_cmake_static','pc3_curl_static'}
CVES={'rom':'CVE-2014-0160','cmake':'CVE-2022-37434','curl':'CVE-2023-38545'}

def run_case(path,cve):
    start=time.monotonic();c=ingest_package(path);col=collect_evidence(c,cve);v=verify(c,col);a=assess(c,v)
    return c,col,v,a,round(time.monotonic()-start,3)

def unpack_entry(entry,destination):
    archive=entry['archive'];path=(ROOT/archive['repo_path']).resolve()
    if not path.is_relative_to((ROOT/'demo-inputs').resolve()):
        raise IntegrityError('Acceptance archive is outside demo-inputs')
    if path.stat().st_size!=archive['size_bytes'] or file_hash(path)!=archive['sha256']:
        raise IntegrityError('Acceptance archive differs from catalog')
    safe_extract(path,destination)
    if file_hash(destination/'manifest.json')!=entry['manifest_sha256']:
        raise IntegrityError('Acceptance manifest differs from catalog')
    return destination


def assessment_matches(assessment,verdict,static_complete=False):
    if assessment['verdict']!=verdict:return False
    states={c['condition_id']:c['state'] for c in assessment['conditions']}
    if verdict=='AFFECTED':return bool(states) and all(v=='SUPPORTED' for v in states.values())
    if static_complete:
        return states.get('runtime_observation')=='UNKNOWN' and len(states)>1 and all(
            value=='SUPPORTED' for key,value in states.items() if key!='runtime_observation')
    return True


def main():
    started=time.monotonic();report={'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'cases':[],'supplements':[],'adversarial':[]}
    validation=ROOT/'var/validation';validation.mkdir(parents=True,exist_ok=True)
    entries=[]
    for catalog in ('demo-inputs/catalog.json','demo-inputs/runtime-v2/catalog.json'):
        entries.extend(json.loads((ROOT/catalog).read_text())['packages'])
    initial={r['package_id']:r for r in entries if r['kind']=='initial'}
    supplements={r['base_package_id']:r for r in entries if r['kind']=='supplement'}
    if len(initial)!=len(EXPECTED) or set(initial)!=set(EXPECTED):
        raise IntegrityError('Acceptance catalog is incomplete or unexpected')
    if len(supplements)!=6:raise IntegrityError('Expected six supplement cases')
    for name,entry in initial.items():
        with tempfile.TemporaryDirectory(dir=validation) as unpacked:
            base=pathlib.Path(unpacked);path=unpack_entry(entry,base/'initial')
            family=entry['format'];c,col,v,a,elapsed=run_case(path,CVES[family])
            row={'package_id':name,'expected':EXPECTED[name],'observed':a['verdict'],'pass':assessment_matches(a,EXPECTED[name],name in STATIC_COMPLETE),
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
            if name in supplements:
                supplement=unpack_entry(supplements[name],base/'supplement')
                plan=validate_supplement(c,supplement)
                if not plan['can_merge']:raise IntegrityError('Acceptance supplement cannot merge')
                with tempfile.TemporaryDirectory(dir=ROOT/'var/validation') as tmp:
                    merged=pathlib.Path(tmp)/'snapshot';shutil.copytree(path,merged,symlinks=True)
                    for row in plan['added_files']:
                        src=supplement/row['path'];dst=merged/row['path'];dst.parent.mkdir(parents=True,exist_ok=True)
                        if src.is_symlink():dst.symlink_to(src.readlink())
                        else:shutil.copy2(src,dst)
                    m={**c.manifest,'package_id':'new-snapshot','files':scan(merged)};(merged/'manifest.json').write_text(json.dumps(m))
                    after,_,_,aa,duration=run_case(merged,CVES[family]);expected='AFFECTED' if name.startswith('pc3_') else ('NOT_AFFECTED' if family=='rom' else 'NEEDS_INVESTIGATION')
                    row={'base':name,'before':a['verdict'],'after':aa['verdict'],'expected':expected,'same_artifact':c.manifest['primary_artifact']==after.manifest['primary_artifact'],'new_context':c.context_hash!=after.context_hash,'pass':assessment_matches(aa,expected,not name.startswith('pc3_') and family!='rom') and c.manifest['primary_artifact']==after.manifest['primary_artifact'] and c.context_hash!=after.context_hash,'elapsed_seconds':duration}
                    report['supplements'].append(row);print(json.dumps(row,ensure_ascii=False),flush=True)
                    c.assert_current()
    report['elapsed_seconds']=round(time.monotonic()-started,3)
    report['pass']=len(report['cases'])==12 and len(report['supplements'])==6 and len(report['adversarial'])==5 and all(x['pass'] for group in ['cases','supplements','adversarial'] for x in report[group])
    target=ROOT/'var/validation'/('engineering-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'.json')
    target.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');print(target,flush=True)
    return 0 if report['pass'] else 1
if __name__=='__main__':sys.exit(main())
