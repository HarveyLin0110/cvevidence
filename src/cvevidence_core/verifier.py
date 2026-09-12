"""Recompute facts and mint an in-process, tamper-evident verification receipt."""
import dataclasses,hmac,secrets
from .evidence import VerifiedEvidence
from .integrity import IntegrityError,canonical,digest
from .queries import collect_evidence
from .sources import verify_excerpt

_SECRET=secrets.token_bytes(32)

def _sign(value):return hmac.new(_SECRET,canonical(value),'sha256').hexdigest()

def verify(context,collection):
    if not isinstance(collection,dict) or collection.get('context_hash')!=context.context_hash:raise IntegrityError('證據不屬於目前快照')
    actual=collect_evidence(context,collection.get('cve_id'))
    if canonical(actual)!=canonical(collection):raise IntegrityError('證據 ID、原值、來源或 query 結果與重新取證不一致')
    for record in actual['evidence']:
        if not all(verify_excerpt(context,e) for e in record['excerpts']):raise IntegrityError('原文引用驗證失敗')
    payload={'context_hash':context.context_hash,'cve_id':actual['cve_id'],'profile_version':actual['profile_version'],
             'collection_hash':digest(actual),'records':tuple(actual['evidence']),'queries':tuple(actual['queries'])}
    return VerifiedEvidence(**payload,certificate=_sign(payload))

def require_verified(context,verified):
    if not isinstance(verified,VerifiedEvidence):raise IntegrityError('正式判定只接受 Verifier 核對結果')
    payload=dataclasses.asdict(verified);signature=payload.pop('certificate')
    if verified.context_hash!=context.context_hash or not hmac.compare_digest(signature,_sign(payload)):raise IntegrityError('Verifier 核對結果已變更或來自另一程序；請重新驗證')
    context.assert_current()

def verify_citations(context,verified,citations,excerpts=()):
    require_verified(context,verified)
    known={r['evidence_id'] for r in verified.records}
    xids={x['excerpt_id']:x for x in excerpts}
    return {'valid':all(cid in known or (cid in xids and verify_excerpt(context,xids[cid])) for cid in citations),
            'invalid_ids':[cid for cid in citations if cid not in known and not(cid in xids and verify_excerpt(context,xids[cid]))],
            'meaning_verified':False,'note':'已驗證引用存在與原文一致；AI 語意推論仍待工程師覆核。'}
