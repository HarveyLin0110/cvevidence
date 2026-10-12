import json
from cvevidence_core.partial_intake import create
from cvevidence_core.integrity import safe_extract,ingest_package
from cvevidence_core.component_discovery import discover

def test_osv_consent_scope_and_symptom_not_transmitted(tmp_path):
    archive=tmp_path/'p.tgz'
    create([('custom-sbom.json',json.dumps({'components':[{'name':'django','version':'4.2.0','purl':'pkg:pypi/django@4.2.0'}]}).encode())],archive)
    safe_extract(archive,tmp_path/'p');c=ingest_package(tmp_path/'p');calls=[]
    def query(value,timeout):
        calls.append(value)
        return {'vulns':[{'id':'GHSA-TEST','aliases':['CVE-2024-42005'],'summary':'query crash'}]},'0'*64
    assert discover(c,transport=query)['status']=='CONSENT_REQUIRED' and not calls
    r=discover(c,'private symptom crash',consent=True,transport=query)
    assert r['candidates'][0]['cve_id']=='CVE-2024-42005'
    assert r['symptom_causation']=='NOT_ESTABLISHED'
    assert calls==[{'package':{'name':'django','ecosystem':'PyPI'},'version':'4.2.0'}]

def test_unrelated_json_shapes_do_not_break_intake(tmp_path):
    from cvevidence_core.component_discovery import components
    create([('data.json',b'{"components":42,"packages":{"name":"not-sbom"}}')],tmp_path/'p.tgz')
    safe_extract(tmp_path/'p.tgz',tmp_path/'p')
    assert components(ingest_package(tmp_path/'p'))==[]
