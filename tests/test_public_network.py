"""Address failover keeps public-DNS, TLS, content and deadline checks."""
import errno
import ssl
from unittest.mock import patch
import pytest
from cvevidence_core import public_sources as sources

URL='https://openssl-library.org/news/secadv/20220315.txt'
IPS=['2600:1901:0:d50b::','34.49.79.89']


def dns(ips):return [(0,0,0,'',(ip,443)) for ip in ips]


class Response:
    status=200
    def __init__(self):self.blocks=[b'TEST_ONLY advisory',b'']
    def getheader(self,name,default=''):return 'text/plain'
    def read1(self,size):return self.blocks.pop(0)


class Connection:
    sock=None
    def __init__(self,error=None,response=None):self.error=error;self.response=response or Response();self.closed=False
    def request(self,*args,**kwargs):
        if self.error:raise self.error
    def getresponse(self):return self.response
    def close(self):self.closed=True


@pytest.mark.parametrize('error',[ConnectionRefusedError(),OSError(errno.ENETUNREACH,'unreachable'),TimeoutError()])
def test_second_public_address_is_used_with_same_tls_hostname_and_shared_budget(error):
    first=Connection(error);second=Connection()
    with patch.object(sources.socket,'getaddrinfo',return_value=dns(IPS)) as resolver, \
         patch.object(sources,'_PinnedHTTPS',side_effect=[first,second]) as connection, \
         patch.object(sources.time,'monotonic',side_effect=[100,100,104,104,104,104]):
        raw,kind=sources._download(URL,108)
    assert raw==b'TEST_ONLY advisory' and kind=='text/plain'
    assert [(c.args[0],c.args[1],c.args[2]) for c in connection.call_args_list]==[
        ('openssl-library.org',IPS[0],5),('openssl-library.org',IPS[1],4)]
    assert resolver.call_count==1 and first.closed and second.closed


def test_deadline_prevents_starting_next_address():
    first=Connection(TimeoutError())
    with patch.object(sources.socket,'getaddrinfo',return_value=dns(IPS)), \
         patch.object(sources,'_PinnedHTTPS',return_value=first) as connection, \
         patch.object(sources.time,'monotonic',side_effect=[100,100,109]):
        with pytest.raises(TimeoutError):sources._download(URL,108)
    assert connection.call_count==1 and first.closed


def test_any_private_dns_answer_rejects_entire_candidate_set():
    with patch.object(sources.socket,'getaddrinfo',return_value=dns(IPS+['127.0.0.1'])), \
         patch.object(sources,'_PinnedHTTPS') as connection:
        with pytest.raises(ValueError,match='NON_PUBLIC'):sources._download(URL,1e20)
    connection.assert_not_called()


@pytest.mark.parametrize('failure',['certificate','redirect','content_type','unexpected_io'])
def test_non_connection_failures_are_not_hidden_by_next_address(failure):
    first=Connection()
    if failure=='certificate':first.error=ssl.SSLCertVerificationError('TEST_ONLY invalid certificate')
    if failure=='redirect':first.response.status=302
    if failure=='content_type':first.response.getheader=lambda *args:'application/zip'
    if failure=='unexpected_io':first.error=OSError(errno.EACCES,'TEST_ONLY denied')
    with patch.object(sources.socket,'getaddrinfo',return_value=dns(IPS)), \
         patch.object(sources,'_PinnedHTTPS',return_value=first) as connection:
        with pytest.raises((OSError,ValueError)):sources._download(URL,1e20)
    assert connection.call_count==1 and first.closed


def test_address_attempt_count_is_bounded():
    with patch.object(sources.socket,'getaddrinfo',return_value=dns(['8.8.8.'+str(i) for i in range(1,9)])), \
         patch.object(sources,'_PinnedHTTPS',side_effect=lambda *args:Connection(ConnectionRefusedError())) as connection:
        with pytest.raises(ConnectionRefusedError):sources._download(URL,1e20)
    assert connection.call_count==4
