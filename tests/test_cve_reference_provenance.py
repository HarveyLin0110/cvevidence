import hashlib
import json
from cvevidence_core.public_cve import brief, record_url, _references


def test_saved_cve_collects_adp_links_without_promoting_adp_to_cna():
    cve='CVE-2022-48174'
    data={'cveMetadata':{'cveId':cve,'state':'PUBLISHED'},'containers':{
        'cna':{'providerMetadata':{'shortName':'CNA_TEST'},
               'descriptions':[{'lang':'en','value':'TEST_ONLY primary description'}],
               'references':[{'url':'https://example.com/a'}]},
        'adp':[{'providerMetadata':{'shortName':'ADP_TEST','orgId':'test-org'},
                'descriptions':[{'lang':'en','value':'must not replace primary description'}],
                'references':[{'url':'https://example.com/a'},{'url':'https://example.com/b'}]}]}}
    body=json.dumps(data)
    result=brief({'cve_id':cve,'status':'PUBLISHED','source_url':record_url(cve),
                  'body':body,'sha256':hashlib.sha256(body.encode()).hexdigest()})
    assert result['description']=='TEST_ONLY primary description'
    assert result['references']==['https://example.com/a','https://example.com/b']
    first,second=result['reference_details']
    assert [r['container'] for r in first['origins']]==['CNA','ADP']
    assert second['origins']==[{'container':'ADP','provider':'ADP_TEST','org_id':'test-org'}]
    assert not result['references_truncated']


def test_reference_budgets_and_duplicate_entries_preserve_new_links():
    same={'url':'https://example.com/same'}
    urls,details,truncated=_references({'cna':{'references':[same]*15},'adp':[
        {'references':[{'url':f'https://example.com/{i}'} for i in range(30)]}]})
    assert len(urls)==len(details)==20 and len(set(urls))==20
    assert urls[0].endswith('/same') and truncated
    assert len(details[0]['origins'])==1


def test_invalid_optional_adp_entries_do_not_discard_primary_reference():
    urls,_,_=_references({'cna':{'references':[None,{'url':5},{'url':'http://example.com'},
                          {'url':'https://example.com/ok'}]},
                         'adp':[None,{'references':None},{'references':[]} ]})
    assert urls==['https://example.com/ok']


def test_container_and_per_container_limits_are_disclosed():
    assert _references({'adp':[{}]*9})[2]
    assert _references({'cna':{'references':[{}]*33}})[2]
