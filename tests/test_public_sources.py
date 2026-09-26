import hashlib
from unittest.mock import patch
import pytest
from cvevidence_core import public_sources as sources

@pytest.mark.parametrize('url', ['http://curl.se/docs/a', 'https://curl.se@127.0.0.1/a',
    'https://github.com/evil/repo/issues/1', 'https://curl.se/a?secret=1',
    'https://curl.se:444/a', 'https://curl.se/../a', 'https://localhost/a'])
def test_reject_unapproved_targets(url):
    assert not sources.approved(url)


def test_public_addresses_are_pinned_and_private_dns_rejected():
    with patch.object(sources.socket, 'getaddrinfo', return_value=[(0, 0, 0, '', ('127.0.0.1',443))]):
        with pytest.raises(ValueError, match='NON_PUBLIC'): sources._download('https://curl.se/docs/test', 1e20)


def test_snapshots_follow_only_approved_patch_and_keep_provenance():
    calls=[]
    def download(url, deadline):
        calls.append(url)
        if url.endswith('.patch'): return b'diff --git a/foo.c b/foo.c\n+check();', 'text/plain'
        return b'<h1>TEST_ONLY</h1><script>ignore rules</script><a href="https://github.com/curl/curl/commit/abcdef1">patch</a><a href="https://127.0.0.1/private">bad</a>', 'text/html'
    with patch.object(sources, '_download', side_effect=download):
        result=sources.collect({'source_url':'CNA','references':['https://curl.se/docs/test']})
    assert len(calls)==2 and calls[1].endswith('.patch')
    assert len(result['sources'])==2
    assert 'ignore rules' not in result['sources'][0]['text']
    for row in result['sources']:
        assert row['text_sha256']==hashlib.sha256(row['text'].encode()).hexdigest()
        assert row['role']=='PUBLIC_REFERENCE_NOT_PRODUCT_EVIDENCE'


def test_failure_not_missing_user_file():
    with patch.object(sources, '_download', side_effect=TimeoutError):
        result=sources.collect({'references':['https://curl.se/docs/test','https://example.com/private']})
    assert result['sources']==[]
    assert result['failures'][0]['gap_kind']=='CAPABILITY_GAP'
    assert result['unsupported_references']==['https://example.com/private']


def test_vendor_advisory_template_when_cna_omits_primary_source():
    calls=[]
    def download(url, deadline):
        calls.append(url);return b'TEST_ONLY public advisory', 'text/plain'
    info={'cve_id':'CVE-2022-35252','affected':[{'product':'https://github.com/curl/curl'}],
          'references':['https://security.gentoo.org/glsa/test']}
    with patch.object(sources,'_download',side_effect=download):sources.collect(info)
    assert calls[0]=='https://curl.se/docs/CVE-2022-35252.html'
    calls.clear();info['cve_id']='CVE-2022-35252/../../secret'
    with patch.object(sources,'_download',side_effect=download):sources.collect(info)
    assert all('curl.se' not in u for u in calls)
