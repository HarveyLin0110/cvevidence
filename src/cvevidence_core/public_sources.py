"""Bounded official advisory/patch snapshots. No model-supplied network URLs."""
from datetime import datetime, timezone
from html.parser import HTMLParser
import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
import time
from urllib.parse import urlsplit, urljoin

# Operator-reviewed origins, not a claim that all content on them is trustworthy.
HOSTS = frozenset({'curl.se', 'openssl-library.org', 'www.openssl.org', 'zlib.net',
    'www.zlib.net', 'github.com', 'raw.githubusercontent.com', 'www.openwall.com',
    'security.gentoo.org', 'www.djangoproject.com', 'httpd.apache.org',
    'www.apache.org', 'security.apache.org', 'www.kernel.org', 'git.kernel.org'})
MAX_BYTES = 1_000_000
MAX_TEXT = 14000


def approved(url):
    try:
        p = urlsplit(url)
        if (p.scheme != 'https' or p.hostname not in HOSTS or p.port not in (None, 443)
                or p.username or p.password or p.query or p.fragment or '\\' in url):
            return False
        if p.hostname == 'github.com':
            return bool(re.fullmatch(r'/[\w.-]+/[\w.-]+/(?:commit/[0-9a-f]{7,40}(?:\.patch)?|security/advisories/GHSA-[\w-]+|releases/tag/[\w.-]+)', p.path))
        if p.hostname == 'raw.githubusercontent.com':
            return bool(re.fullmatch(r'/[\w.-]+/[\w.-]+/[0-9a-f]{40}/[\w./-]+', p.path))
        return bool(p.path and '..' not in p.path)
    except (ValueError, TypeError):
        return False


class _Text(HTMLParser):
    def __init__(self):
        super().__init__(); self.parts = []; self.links = []; self.hidden = 0
    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'): self.hidden += 1
        if tag == 'a':
            self.links.extend(v for k, v in attrs if k == 'href' and v)
        if tag in ('p', 'div', 'br', 'li', 'pre', 'h1', 'h2', 'h3'): self.parts.append('\n')
    def handle_endtag(self, tag):
        if tag in ('script', 'style'): self.hidden = max(0, self.hidden - 1)
    def handle_data(self, data):
        if not self.hidden: self.parts.append(data)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, ip, timeout):
        super().__init__(host, timeout=timeout, context=ssl.create_default_context()); self.ip = ip
    def connect(self):
        raw = socket.create_connection((self.ip, 443), self.timeout)
        try: self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close(); raise


def _download(url, deadline):
    if not approved(url): raise ValueError('SOURCE_POLICY')
    p = urlsplit(url)
    addresses = sorted({row[4][0] for row in socket.getaddrinfo(p.hostname, 443, type=socket.SOCK_STREAM)})
    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise ValueError('NON_PUBLIC_ADDRESS')
    remaining = deadline - time.monotonic()
    if remaining <= 0: raise TimeoutError()
    conn = _PinnedHTTPS(p.hostname, addresses[0], min(remaining, 5))
    try:
        conn.request('GET', p.path, headers={'User-Agent': 'CVEvidence/0.1', 'Accept': 'text/plain,text/html,application/json', 'Accept-Encoding': 'identity'})
        response = conn.getresponse()
        if response.status != 200: raise ValueError('HTTP_' + str(response.status))
        kind = response.getheader('Content-Type', '').split(';')[0]
        if kind not in ('text/html', 'text/plain', 'text/x-patch', 'text/x-diff', 'application/json', 'application/octet-stream'):
            raise ValueError('CONTENT_TYPE')
        chunks = []; size = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise TimeoutError()
            if conn.sock: conn.sock.settimeout(min(remaining, 5))
            block = response.read1(min(65536, MAX_BYTES + 1 - size))
            if not block: break
            size += len(block)
            if size > MAX_BYTES: raise ValueError('SOURCE_TOO_LARGE')
            chunks.append(block)
        return b''.join(chunks), kind
    finally: conn.close()


def collect(info, *, timeout=15, limit=3):
    """Only CNA references and approved patch links from their saved HTML."""
    deadline = time.monotonic() + max(0, min(timeout, 15))
    sources = []; failures = []; seen = set()
    references = list(info.get('references', []))
    # A reviewed vendor URL template handles CNA records that omit the vendor
    # advisory. Only the validated CVE ID is interpolated, never model text.
    cve = info.get('cve_id','')
    if re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,20}',cve) and any(
            a.get('product','').lower().rstrip('/') in {'curl','libcurl','https://github.com/curl/curl'}
            for a in info.get('affected', [])):
        references.insert(0,'https://curl.se/docs/'+cve+'.html')
    queue = [(url, info.get('source_url')) for url in references if approved(url)]
    # Prefer the vendor advisory over mirrors and commit patch bytes over HTML.
    queue.sort(key=lambda row: (urlsplit(row[0]).hostname != 'curl.se', 'github.com' in row[0], '/docs/' not in row[0]))
    while queue and len(sources) + len(failures) < limit and time.monotonic() < deadline:
        original, parent = queue.pop(0)
        url = original + '.patch' if re.fullmatch(r'https://github.com/[\w.-]+/[\w.-]+/commit/[0-9a-f]{7,40}', original) else original
        if url in seen: continue
        seen.add(url)
        try:
            raw, kind = _download(url, deadline)
            body = raw.decode('utf-8')
            if '\0' in body: raise ValueError('BINARY_CONTENT')
            links = []
            if kind == 'text/html':
                parser = _Text(); parser.feed(body)
                body = '\n'.join(line.strip() for line in ''.join(parser.parts).splitlines() if line.strip())
                links = [urljoin(url, link) for link in parser.links]
            text = body[:MAX_TEXT]
            row = {'source_id': 'P-' + hashlib.sha256(url.encode() + raw).hexdigest()[:24],
                'url': url, 'discovered_from': parent, 'retrieved_at': datetime.now(timezone.utc).isoformat(),
                'raw_sha256': hashlib.sha256(raw).hexdigest(), 'text_sha256': hashlib.sha256(text.encode()).hexdigest(),
                'text': text, 'truncated': len(body) > MAX_TEXT, 'status': 'RETRIEVED',
                'role': 'PUBLIC_REFERENCE_NOT_PRODUCT_EVIDENCE'}
            sources.append(row)
            patches = [(link, url) for link in links if approved(link) and re.search(r'/commit/[0-9a-f]{7,40}(?:\.patch)?$', link)]
            queue = patches + queue
        except (OSError, ValueError, UnicodeError, http.client.HTTPException):
            failures.append({'url': url, 'status': 'UNAVAILABLE', 'gap_kind': 'CAPABILITY_GAP'})
    return {'sources': sources, 'failures': failures,
            'unsupported_references': [u for u in info.get('references', []) if not approved(u)],
            'note': '只取得經來源政策允許的公告與修補；內容仍是待覆核資料，不是產品證據。未取得不等於不存在，不向使用者自動索取。'}


def cna_source(info):
    if not info or info.get('status') != 'PUBLISHED': return []
    text = info.get('description', '')
    return [{'source_id': 'P-CNA-' + info['record_sha256'][:20], 'url': info['source_url'],
        'text': text, 'text_sha256': hashlib.sha256(text.encode()).hexdigest(),
        'raw_sha256': info['record_sha256'], 'truncated': info.get('description_truncated', False),
        'status': 'RETRIEVED', 'role': 'PUBLIC_REFERENCE_NOT_PRODUCT_EVIDENCE'}]
