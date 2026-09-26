"""Verifiable condition/evidence dossiers and explicit operator review receipts."""
from .integrity import digest, IntegrityError
from .sources import verify_excerpt


def dossier(context, investigation):
    if investigation.get('context_hash')!=context.context_hash:raise IntegrityError('Review scope mismatch')
    plan=investigation.get('condition_plan') or {}
    if not plan:return None
    if plan.get('context_hash')!=context.context_hash or plan.get('cve_id')!=investigation.get('cve_id'):
        raise IntegrityError('Condition scope mismatch')
    if plan.get('plan_hash')!=digest(plan['conditions']):raise IntegrityError('Condition plan changed')
    excerpts={x['excerpt_id']:x for x in investigation.get('excerpts',[])}
    rows=[]
    for condition in plan['conditions']:
        evidence=[]
        for citation in condition['citations']:
            if not citation.startswith('X-'):continue
            x=excerpts.get(citation)
            if not x or not verify_excerpt(context,x):raise IntegrityError('Condition excerpt changed')
            evidence.append({**x,'path':context.sources[x['source_id']]['path'],'verification':'EXACT_BYTES_AND_LOCATOR'})
        rows.append({**condition,'evidence':evidence,'support_relation':'PENDING_HUMAN_SEMANTIC_REVIEW',
            'unconfirmed':condition['explanation'] if condition['state'] in ('NOT_REVIEWED','USER_MATERIAL_MISSING','CAPABILITY_GAP','CONFLICT') else
                '需覆核引用是否充分支持條件、建置綁定與完整適用範圍；逐字一致不代表語意成立。'})
    payload={'context_hash':context.context_hash,'cve_id':investigation['cve_id'],
        'plan_hash':plan['plan_hash'],'conditions':rows,'formal_verdict_unchanged':True}
    return {**payload,'dossier_hash':digest(payload)}


def verify_review(context, saved_dossier, decision):
    """Called by an operator, never an AI tool. Reviews do not replace assessment.

    A reviewer signs off each relation; the verifier independently checks bytes,
    scope and coverage. A later dedicated rule still owns product verdicts.
    """
    if saved_dossier.get('dossier_hash')!=digest({k:v for k,v in saved_dossier.items() if k!='dossier_hash'}):
        raise IntegrityError('Dossier changed')
    if saved_dossier['context_hash']!=context.context_hash:raise IntegrityError('Review context mismatch')
    if set(decision)!={'dossier_hash','reviewer','conditions'} or decision['dossier_hash']!=saved_dossier['dossier_hash']:
        raise ValueError('Review must bind exact dossier')
    if not isinstance(decision['reviewer'],str) or not 1<=len(decision['reviewer'].strip())<=100:raise ValueError('Reviewer required')
    rows=decision['conditions'];original={r['condition_id']:r for r in saved_dossier['conditions']}
    if not isinstance(rows,list) or len(rows)!=len(original) or {r.get('condition_id') for r in rows}!=set(original):
        raise ValueError('Review all conditions exactly once')
    receipts=[]
    for row in rows:
        if set(row)!={'condition_id','relation','rationale'} or row['relation'] not in ('SUPPORTED','EXCLUDED','UNRESOLVED','CONFLICT'):
            raise ValueError('Invalid review relation')
        if not isinstance(row['rationale'],str) or not 1<=len(row['rationale'].strip())<=2000:raise ValueError('Review rationale required')
        evidence=original[row['condition_id']]['evidence']
        if row['relation'] in ('SUPPORTED','EXCLUDED','CONFLICT') and not evidence:raise ValueError('Reviewed relation needs product excerpts')
        for x in evidence:
            raw={k:v for k,v in x.items() if k not in ('path','verification')}
            if not verify_excerpt(context,raw):raise IntegrityError('Reviewed bytes changed')
        receipts.append({**row,'excerpt_ids':[x['excerpt_id'] for x in evidence],
            'verification':'BYTES_RECHECKED_HUMAN_RELATION_RECORDED','automated_semantic_proof':False})
    context.assert_current()
    result={'context_hash':context.context_hash,'cve_id':saved_dossier['cve_id'],
        'dossier_hash':saved_dossier['dossier_hash'],'reviewer':decision['reviewer'],'conditions':receipts,
        'status':'REVIEW_RECORDED','formal_verdict_unchanged':True,'reviewer_authenticated':False}
    return {**result,'receipt_hash':digest(result)}
