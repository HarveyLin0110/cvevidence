"""Bounded public CVE lookup. Only the validated CVE ID leaves this process.

The saved public record supplies investigation leads, never product evidence.
References in the record are displayed as data and are not followed.
"""
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone

MAX_BYTES = 1_000_000
ORIGIN = 'https://cveawg.mitre.org/api/cve/'


def record_url(cve_id):
    if not isinstance(cve_id, str) or not re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,20}', cve_id):
        raise ValueError('Invalid CVE ID')
    return ORIGIN + cve_id


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def lookup(cve_id):
    result = {'cve_id': cve_id, 'source_url': record_url(cve_id),
              'status': 'UNAVAILABLE', 'retrieved_at': datetime.now(timezone.utc).isoformat(),
              'note': '公開公告不是本產品的適用性證據；無法取得資料不代表 CVE 不存在或產品安全。'}
    if os.environ.get('CVEVIDENCE_PUBLIC_CVE_LOOKUP') == '0':
        return {**result, 'reason_code': 'LOOKUP_DISABLED'}
    try:
        request = urllib.request.Request(result['source_url'], headers={'Accept': 'application/json'})
        with urllib.request.build_opener(_NoRedirect()).open(request, timeout=8) as response:
            raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError('Record too large')
        body = raw.decode('utf-8')
        data = json.loads(body)
        if not isinstance(data, dict) or data.get('cveMetadata', {}).get('cveId') != cve_id:
            raise ValueError('Record identity mismatch')
        state = data['cveMetadata'].get('state')
        if state not in {'PUBLISHED', 'REJECTED', 'RESERVED'}:
            raise ValueError('Unknown record state')
        result.update(status=state, body=body, sha256=hashlib.sha256(raw).hexdigest())
        brief(result)  # Validate nested structures before publishing a usable record.
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        result = {k: v for k, v in result.items() if k not in {'body', 'sha256'}}
        result['status'] = 'UNAVAILABLE'
    return result


def brief(record):
    """Recheck saved bytes/identity; this does not certify advisory semantics."""
    if not isinstance(record, dict) or record.get('source_url') != record_url(record.get('cve_id')):
        raise ValueError('Public source identity mismatch')
    status = record.get('status')
    if status == 'UNAVAILABLE':
        return {'status': status, 'cve_id': record['cve_id'], 'source_url': record['source_url'],
                'note': '尚未取得可用公開公告；請提供公告或核對 CVE 編號，所有 PC 保持待確認。'}
    body = record.get('body')
    if not isinstance(body, str) or len(body.encode()) > MAX_BYTES or hashlib.sha256(body.encode()).hexdigest() != record.get('sha256'):
        raise ValueError('Public record bytes changed')
    data = json.loads(body)
    metadata = data['cveMetadata']
    if metadata.get('cveId') != record['cve_id'] or metadata.get('state') != status or status not in {'PUBLISHED', 'REJECTED', 'RESERVED'}:
        raise ValueError('Public record scope changed')
    cna = data.get('containers', {}).get('cna', {})
    descriptions = cna.get('descriptions', [])
    description = next((d['value'] for d in descriptions if d.get('lang') == 'en'), '')
    if not isinstance(description, str):
        raise ValueError('Invalid description')
    affected = [{'vendor': str(a.get('vendor', ''))[:200], 'product': str(a.get('product', ''))[:200],
                 'versions': [{k: str(v[k])[:200] for k in ('version', 'status', 'lessThan', 'lessThanOrEqual', 'versionType') if k in v}
                              for v in a.get('versions', [])[:20]]} for a in cna.get('affected', [])[:20]]
    references = [r['url'] for r in cna.get('references', []) if isinstance(r.get('url'), str)
                  and r['url'].startswith('https://')][:10]
    return {'status': status, 'cve_id': record['cve_id'], 'source_url': record['source_url'],
            'record_sha256': record['sha256'], 'title': str(cna.get('title', ''))[:600],
            'description': description[:6000], 'description_truncated': len(description) > 6000,
            'affected': affected, 'references': references,
            'note': 'CNA 公告內容，僅作待覆核的查核線索；不是本次產品的已驗證條件。'}
