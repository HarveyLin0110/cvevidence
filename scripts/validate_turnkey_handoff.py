"""Offline acceptance against an operator-supplied private handoff directory.

Only aggregate assertions are printed; private samples never enter the repo.
No source command, firmware, company URL or cloud API is executed.
"""
import argparse
import io
import json
from pathlib import Path
import tarfile
import tempfile
from cvevidence_core.integrity import safe_extract,ingest_package,file_hash
from cvevidence_core.partial_intake import create
from cvevidence_core.turnkey import inventory


def main():
    p=argparse.ArgumentParser();p.add_argument('bundle',type=Path);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--only',action='append',default=[])
    args=p.parse_args();bundle=args.bundle.resolve()
    cases=json.loads((bundle/'acceptance/cases.json').read_text())['cases'];results=[];contexts={}
    all_cases={c['case_id']:c for c in cases}
    if args.only:
        wanted=set(args.only)
        for _ in range(len(cases)):
            wanted.update(c['previous_case_id'] for c in cases if c['case_id'] in wanted and c.get('previous_case_id'))
        cases=[c for c in cases if c['case_id'] in wanted]
    with tempfile.TemporaryDirectory() as temporary:
        root=Path(temporary)
        for case in cases:
            cid=case['case_id'];folder=root/cid;folder.mkdir();checks=[]
            try:
                if cid=='CASE-UNSAFE-ARCHIVE-DESCRIPTORS':
                    descriptor=json.loads((bundle/case['inputs'][0]['packaged_path']).read_text())
                    for i,entry in enumerate(descriptor['entries']):
                        archive=folder/(str(i)+'.tar')
                        with tarfile.open(archive,'w') as tf:
                            m=tarfile.TarInfo(entry['name'])
                            if entry['type']=='symlink':m.type=tarfile.SYMTYPE;m.linkname=entry['target']
                            elif entry['type']=='character_device':m.type=tarfile.CHRTYPE
                            else:m.size=1
                            tf.addfile(m,io.BytesIO(b'x') if m.isfile() else None)
                        rejected=False
                        try:safe_extract(archive,folder/('out'+str(i)))
                        except ValueError:rejected=True
                        assert rejected
                    checks.append('five_real_unsafe_archives_rejected')
                else:
                    base=contexts.get(case.get('previous_case_id'))
                    conditions=case.get('test_conditions',{})
                    if conditions.get('initial_material_inputs_from_case'):
                        original=all_cases[conditions['initial_material_inputs_from_case']]
                        initial=[r for r in original['inputs'] if r['material_id'] in conditions['initial_material_ids']]
                        create([(r.get('upload_relative_path',r['packaged_path']),(bundle/r['packaged_path']).read_bytes()) for r in initial],
                            folder/'initial.tgz',build='TEST_BUILD_ALPHA_001')
                        safe_extract(folder/'initial.tgz',folder/'initial');base=ingest_package(folder/'initial')
                    parent=base;old=base.context_hash if base else None
                    target_build=case.get('test_conditions',{}).get('target_case_build_id','未確認')
                    # Wrong-build test preserves original target; inspect the conflicting receipt as unbound data.
                    if cid=='CASE-SYNTHETIC-ASSOCIATION-POSITIVE':target_build='TEST_BUILD_ALPHA_001'
                    for i,item in enumerate(case['inputs']):
                        path=(bundle/item['packaged_path']).resolve()
                        assert path.is_relative_to(bundle) and file_hash(path)==item['sha256']
                        archive=folder/(str(i)+'.tgz');destination=folder/('snapshot'+str(i))
                        with path.open('rb') as stream:
                            create([(item.get('upload_relative_path',item['packaged_path']),stream)],archive,
                                base=base,large=path.stat().st_size>20*1024*1024,build=target_build)
                        safe_extract(archive,destination);base=ingest_package(destination)
                    contexts[cid]=base
                    enabled=case.get('test_conditions',{}).get('embedded_metadata_reader_capability_for_this_test')!='UNAVAILABLE'
                    report=inventory(base,container_reader=enabled)
                    expected=case['expected'];rec={r['recommendation_id'] for r in report['recommendations']}
                    assert set(expected.get('recommendations_required',[]))<=rec, 'missing recommendations: '+str(set(expected.get('recommendations_required',[]))-rec)
                    assert not set(expected.get('recommendations_absent',[]))&rec, 'unwanted recommendations'
                    assert report['assessment']=='NOT_ASSESSED' and report['build_binding']=='UNKNOWN'
                    assert all(r['build_binding']=='UNKNOWN' for r in report['materials'])
                    assert sum(r['priority']=='NOW' for r in report['recommendations'])<=1
                    checks.extend(['required_and_forbidden_recommendations','no_shipping_or_cve_claim','one_next_action'])
                    if old:
                        parent.assert_current()
                        assert parent.context_hash==old and base.context_hash!=old, 'immutable identities: '+str((parent.context_hash==old,base.context_hash!=old))
                        checks.append('immutable_supplement')
                    if cid=='CASE-APPLICATION-LINK-MAP-REAL':
                        assert sum(r['material_role']=='application_link_map' for r in report['materials'])==2
                        checks.append('txt_link_maps_content_identified')
                    if cid=='CASE-DELIVERY-CHECKSUM-SIX-REAL':
                        obs=[o for r in report['materials'] for o in r['observations'] if o['kind']=='CONTENT_CHECKSUM']
                        assert len(obs)==6 and all(o['matched_source_ids'] for o in obs)
                        checks.append('six_actual_checksums_match')
                    if cid=='CASE-CONTAINED-BYTES-NOT-BUILD':
                        assert len(report['relations'])>=6
                        checks.append('six_actual_contained_spans_match')
                    if cid=='CASE-2506-MFI-PARTIAL-BSP-METADATA':
                        versions=[x for r in report['materials'] for x in r.get('container',{}).get('rootfs',[]) if x['name']=='rootfs']
                        assert len(versions)==2 and all(x['version_state']=='PRESENT_BUT_UNUSABLE' for x in versions)
                        checks.append('two_unusable_bsp_fields_preserved')
                    if cid=='CASE-E5-EMBEDDED-METADATA-READABLE':
                        versions=[x for r in report['materials'] for x in r.get('container',{}).get('rootfs',[]) if x['name']=='rootfs']
                        assert versions[0]['version_state']=='PRESENT' and versions[0]['version']==expected['rootfs_VERSION_declared']
                        checks.append('valid_legacy_bsp_retained')
                    if cid=='CASE-2506-BRINGUP-EMBEDDED-VS-FILENAME':
                        embedded=next(r['container']['metadata'] for r in report['materials'] if r.get('container'))
                        assert embedded==expected['embedded_declared_identity']
                        checks.append('embedded_identity_not_filename')
                    if cid in ('CASE-SYNTHETIC-ASSOCIATION-POSITIVE','CASE-SYNTHETIC-IMMUTABLE-SUPPLEMENT'):
                        associations=[r['test_association'] for r in report['materials'] if r.get('test_association')]
                        assert any(r['state']=='MATCHED_TEST_RECORD' and not r['production_evidence_eligible'] for r in associations)
                        checks.append('test_namespace_only_match')
                results.append({'case_id':cid,'status':'PASS','checks':checks})
            except (OSError,ValueError,KeyError,AssertionError) as exc:
                results.append({'case_id':cid,'status':'FAIL','checks':checks,'error':str(exc)[:300]})
            print(cid,results[-1]['status'],flush=True)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps({'cases':results,'scope':'本地收件／盤點／補件驗收；未外送公司資料，未驗證漏洞影響。'},ensure_ascii=False,indent=2))
        if any(r['status']!='PASS' for r in results):raise SystemExit(1)


if __name__=='__main__':main()
