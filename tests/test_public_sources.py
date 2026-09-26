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


def test_debian_policy_only_accepts_security_announcement_paths():
    base='https://lists.debian.org/'
    assert sources.approved(base+'debian-lts-announce/2025/01/msg00012.html')
    assert sources.approved(base+'debian-security-announce/2025/01/msg00012.html')
    for path in ['debian-user/2025/01/msg00012.html','debian-lts-announce/2025/01/msg00012.html?a=1',
                 'debian-lts-announce/../../private','debian-lts-announce/2025/01/msg1.html']:
        assert not sources.approved(base+path)


def test_failures_do_not_exhaust_success_budget_and_downstream_provenance_retained():
    debian='https://lists.debian.org/debian-lts-announce/2025/01/msg00012.html'
    refs=[f'https://curl.se/docs/test-{i}' for i in range(3)]+[debian]
    origin={'container':'ADP','provider':'TEST_ONLY','org_id':'test'}
    calls=[]
    def download(url, deadline):
        calls.append(url)
        if url!=debian:raise TimeoutError()
        return b'TEST_ONLY distribution-specific fix; not a product verdict', 'text/plain'
    with patch.object(sources,'_download',side_effect=download):
        result=sources.collect({'references':refs,'reference_details':[{'url':debian,'origins':[origin]}]})
    assert len(calls)==4 and len(result['failures'])==3
    assert result['sources'][0]['reference_origins']==[origin]
    assert result['sources'][0]['publisher_scope']=='DOWNSTREAM_DISTRIBUTION'
    assert not result['unvisited_references']


def test_attempt_budget_discloses_unvisited_sources_without_requesting_user_material():
    refs=[f'https://curl.se/docs/test-{i}' for i in range(9)]
    with patch.object(sources,'_download',side_effect=TimeoutError) as download:
        result=sources.collect({'references':refs})
    assert download.call_count==6
    assert result['unvisited_references']==refs[6:]
    assert all(row['gap_kind']=='CAPABILITY_GAP' for row in result['failures'])


def test_duplicate_commit_is_not_falsely_reported_unvisited():
    url='https://github.com/test/project/commit/abcdef1'
    with patch.object(sources,'_download',return_value=(b'TEST_ONLY patch','text/plain')) as download:
        result=sources.collect({'references':[url,url,url]},limit=1)
    assert download.call_count==1 and not result['unvisited_references']


def test_saved_patch_beyond_old_prefix_is_available_for_later_read():
    body=('TEST_ONLY patch context\n'*800+'late condition\n').encode()
    with patch.object(sources,'_download',return_value=(body,'text/plain')):
        result=sources.collect({'references':['https://curl.se/docs/test']})
    assert result['sources'][0]['text'].endswith('late condition\n')
    assert len(result['sources'][0]['text'])>14000
    assert not result['sources'][0]['truncated']


def test_saved_public_text_still_has_a_hard_limit():
    with patch.object(sources,'_download',return_value=(b'a'*(sources.MAX_TEXT+1),'text/plain')):
        result=sources.collect({'references':['https://curl.se/docs/test']})
    assert len(result['sources'][0]['text'])==sources.MAX_TEXT
    assert result['sources'][0]['truncated']


def test_pr_reference_is_mapped_to_fixed_patch_host_with_origin_preserved():
    url='https://github.com/madler/zlib/pull/843'
    patch_url='https://patch-diff.githubusercontent.com/raw/madler/zlib/pull/843.patch'
    assert sources.approved(url) and sources.approved(patch_url)
    origin={'container':'CNA','provider':'TEST_ONLY'}
    with patch.object(sources,'_download',return_value=(b'TEST_ONLY patch','text/plain')) as download:
        result=sources.collect({'source_url':'CNA','references':[url,patch_url],
            'reference_details':[{'url':url,'origins':[origin]}]},limit=1)
    assert download.call_args[0][0]==patch_url
    assert result['sources'][0]['reference_url']==url
    assert result['sources'][0]['url']==patch_url
    assert result['sources'][0]['discovered_from']=='CNA'
    assert result['sources'][0]['reference_origins']==[origin]
    assert not result['unvisited_references']


@pytest.mark.parametrize('url',[
    'https://github.com/org/repo/pull/843/files',
    'https://github.com/org/repo/pull/843?redirect=http://localhost',
    'https://github.com/org/repo/pull/0',
    'https://github.com/org/repo/pull/1234567890',
    'https://patch-diff.githubusercontent.com/raw/org/repo/pull/843.patch?x=1',
    'https://patch-diff.githubusercontent.com/raw/org/repo/pull/843',
    'https://patch-diff.githubusercontent.com@localhost/raw/org/repo/pull/843.patch',
    'http://patch-diff.githubusercontent.com/raw/org/repo/pull/843.patch'])
def test_pr_policy_does_not_open_arbitrary_github_targets(url):
    assert not sources.approved(url)


def test_pr_dedup_preserves_first_reference_order():
    first='https://github.com/test/first/pull/1'
    second='https://github.com/test/second/pull/2'
    with patch.object(sources,'_download',return_value=(b'TEST_ONLY patch','text/plain')) as download:
        sources.collect({'references':[first,sources.snapshot_url(first),second]})
    assert [c.args[0] for c in download.call_args_list]==[sources.snapshot_url(first),sources.snapshot_url(second)]
