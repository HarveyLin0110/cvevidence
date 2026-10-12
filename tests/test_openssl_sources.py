"""Legacy official references resolve to fixed current origins, not redirects."""
from unittest.mock import patch
import pytest
from cvevidence_core import public_sources as sources

SHA='3118eb64934499d93db3230748a452351d1d9a65'
PATCH='https://github.com/openssl/openssl/commit/'+SHA+'.patch'
OLD='https://www.openssl.org/news/secadv/20220315.txt'
CURRENT='https://openssl-library.org/news/secadv/20220315.txt'
GIT='https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h='+SHA


@pytest.mark.parametrize('url',[GIT,GIT.replace(';','%3B'),GIT.replace(';','%3b'),
    GIT.replace(';','%3B').replace('a=','a%3D').replace('h=','h%3D')])
def test_exact_legacy_commit_mapping(url):
    assert sources.approved(url)
    assert sources.snapshot_url(url)==PATCH


def test_official_advisory_migration_keeps_reference_and_fetches_current_bytes():
    assert sources.snapshot_url(OLD)==CURRENT
    origin={'container':'CNA','provider':'TEST_ONLY'}
    with patch.object(sources,'_download',return_value=(b'TEST_ONLY official advisory','text/plain')) as get:
        result=sources.collect({'source_url':'CNA','references':[OLD,CURRENT],
            'reference_details':[{'url':OLD,'origins':[origin]}]})
    assert get.call_count==1 and get.call_args.args[0]==CURRENT
    assert result['sources'][0]['reference_url']==OLD
    assert result['sources'][0]['reference_origins']==[origin]
    assert result['sources'][0]['url']==CURRENT
    assert not result['unsupported_references'] and not result['unvisited_references']


@pytest.mark.parametrize('url',[
    GIT.replace('https:','http:'),GIT.replace('git.openssl.org','git.openssl.org.evil.test'),
    GIT.replace('git.openssl.org','git.openssl.org@localhost'),GIT+'&redirect=http://localhost',
    GIT+'#secret',GIT.replace('openssl.git','other.git'),GIT.replace('commitdiff','blob'),
    GIT.replace(SHA,SHA[:7]),GIT.replace('/gitweb/','/other/'),GIT.replace(';','%253B'),
    GIT.replace('git.openssl.org','git.openssl.org:444'),GIT.replace(SHA,'../private'),
])
def test_no_general_gitweb_or_redirect_permission(url):
    assert not sources.approved(url)
    assert sources.snapshot_url(url)==url


def test_commit_aliases_deduplicate_without_losing_source_parent():
    with patch.object(sources,'_download',return_value=(b'TEST_ONLY patch','text/plain')) as get:
        result=sources.collect({'source_url':'CNA','references':[GIT,PATCH,GIT.replace(';','%3B')]})
    assert [c.args[0] for c in get.call_args_list]==[PATCH]
    assert result['sources'][0]['reference_url']==GIT
    assert result['sources'][0]['discovered_from']=='CNA'
    assert not result['unvisited_references']


def test_html_commit_link_uses_same_fixed_mapping_and_budget():
    calls=[]
    def get(url,deadline):
        calls.append((url,deadline))
        return ((f'<p>TEST_ONLY advisory</p><a href="{GIT}">fix</a>'.encode(),'text/html')
                if url==CURRENT else (b'TEST_ONLY patch','text/plain'))
    with patch.object(sources,'_download',side_effect=get):
        result=sources.collect({'references':[OLD]})
    assert [x[0] for x in calls]==[CURRENT,PATCH]
    assert calls[0][1]==calls[1][1]
    assert result['sources'][1]['discovered_from']==CURRENT


def test_normalized_download_still_rejects_private_address():
    with patch.object(sources.socket,'getaddrinfo',return_value=[(0,0,0,'',('127.0.0.1',443))]) as dns:
        with pytest.raises(ValueError,match='NON_PUBLIC'):sources._download(GIT,1e20)
    assert dns.call_args.args[0]=='github.com'


def test_primary_advisory_and_patch_not_starved_by_downstream_failures():
    debian='https://lists.debian.org/debian-lts-announce/2022/03/msg00023.html'
    with patch.object(sources,'_download',return_value=(b'TEST_ONLY source','text/plain')) as get:
        sources.collect({'references':[debian,GIT,OLD]},limit=2)
    assert [c.args[0] for c in get.call_args_list]==[CURRENT,PATCH]
