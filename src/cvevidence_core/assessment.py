"""Deterministic engineering conditions; AI prose cannot change the verdict."""
from .catalog import CATALOG
from .verifier import require_verified
from .integrity import digest

LABELS={'build_identity':'同一成品與 build 身分','component':'元件與已審查版本',
        'library_binding':'元件 source／object／library 綁定','product_binding':'產品實際連結綁定',
        'scope_complete':'交付成品的分析範圍完整','vulnerable_implementation':'受影響實作存在且未有效排除',
        'entry_reachable':'外部輸入可進入相關程式路徑','trigger_prerequisites':'漏洞特有的必要使用條件'}
GUARDS=('build_identity','component','library_binding','product_binding','scope_complete')
NECESSARY=('vulnerable_implementation','entry_reachable','trigger_prerequisites')

def assess(context,verified,statements=()):
    require_verified(context,verified)
    facts={r['fact_key']:r for r in verified.records};conditions=[]
    for key,title in LABELS.items():
        r=facts.get(key);value=r['value'] if r else None
        if key=='component':value=True if isinstance(value,dict) and value.get('confirmed') else None
        state='SUPPORTED' if value is True else 'BLOCKED' if value is False else 'UNKNOWN'
        conditions.append({'condition_id':key,'title':title,'state':state,'evidence_ids':[r['evidence_id']] if r else [],'explanation':r['reason'] if r else '缺少本格式可驗證的取證規則。'})
    states={x['condition_id']:x['state'] for x in conditions}
    conflicts=[{'query_id':q['query_id'],'message':m} for q in verified.queries for m in q['conflicts']]
    # Free text is never verified. A correction is conservatively held for review.
    reviews=[{'statement_id':s.get('material_id'),'text':s.get('text',''),'reason':'文字聲明未核對原始工程資料；請補同 build 證據。'} for s in statements]
    guards=all(states[k]=='SUPPORTED' for k in GUARDS)
    blocked=[k for k in NECESSARY if states[k]=='BLOCKED']
    if conflicts or reviews:verdict='NEEDS_INVESTIGATION';reason='證據有矛盾或收到尚未驗證的新聲明，需覆核。'
    elif guards and blocked:verdict='NOT_AFFECTED';reason='已核對成品範圍與綁定，且有必要條件被有效阻斷。'
    elif guards and all(states[k]=='SUPPORTED' for k in NECESSARY):verdict='AFFECTED';reason='目前交付成品的所有必要工程條件均有可核對證據支持。'
    else:verdict='NEEDS_INVESTIGATION';reason='尚有必要證據、綁定或分析範圍缺口，不能判為安全。'
    gaps=[{'query_id':q['query_id'],'needed':m,'same_build_required':True} for q in verified.queries for m in q['missing']]
    playbook={
        'rom':'提供同一 ROM hash 的 SDK/source、libssl 每個 object 的編譯紀錄、heartbeat 旗標與預處理輸出、實際 linker map。',
        'cmake':'提供同次產品 source、CMake compile/link 紀錄、libz.a 與 linker map，核對 inflateGetHeader 及 extra/chunk 容量。',
        'curl':'提供同成品 hash 的 launcher/config、libcurl 與 compiler/link 紀錄，以及 SOCKS5 DNS/握手與 buffer 設定觀測。'}
    result={'schema_version':'1.0','cve_id':verified.cve_id,'profile_version':verified.profile_version,'context_hash':context.context_hash,
            'verdict':verdict,'reason':reason,'conditions':conditions,'conflicts':conflicts,'statement_reviews':reviews,'gaps':gaps,
            'next_steps':[playbook[context.manifest['format']]] if verdict=='NEEDS_INVESTIGATION' else ['由工程師覆核成品範圍、交付紀錄可信度與實際部署環境。'],
            'blocked_conditions':blocked if guards else [],'evidence_ids':[r['evidence_id'] for r in verified.records],
            'source_advisories':CATALOG[verified.cve_id]['sources'],'human_review_required':True,'provenance_verified':False,
            'scope':'只涵蓋目前提交的成品與已審查程式路徑；未證明實際部署暴露、漏洞已被利用或異常由此 CVE 造成。',
            'symptom_causation':'NOT_ESTABLISHED','verification_hash':verified.collection_hash}
    result['assessment_id']='A-'+digest(result)
    return result

def check_claim(context,assessment,claim):
    identity=claim.get('build_id')==context.manifest['build_id'] and claim.get('artifact_sha256')==context.manifest['primary_artifact']['sha256']
    if not identity:state='DIFFERENT_OR_UNSPECIFIED_BUILD';why='舊聲明未綁定目前成品 hash/build，不得沿用。'
    elif claim.get('verdict')!=assessment['verdict']:state='NOT_SUPPORTED';why='目前可核對的工程結果未支持舊判定。'
    elif assessment['verdict']=='NEEDS_INVESTIGATION':state='UNRESOLVED';why='現有證據不足以確認舊聲明。'
    else:state='CONSISTENT_WITH_CURRENT_EVIDENCE';why='目前工程證據與聲明一致；聲明本身仍非取證來源。'
    return {'claim_id':'M-'+digest(claim),'status':state,'explanation':why,'verified_claim':False,'assessment_id':assessment['assessment_id']}

def summarize(assessment,ai=None):
    names={'AFFECTED':'受影響（工程初判）','NOT_AFFECTED':'不受影響（限目前成品與 CVE）','NEEDS_INVESTIGATION':'需要進一步調查'}
    return {'title':assessment['cve_id']+'：'+names[assessment['verdict']],
            'conclusion':assessment['reason'],'evidence_ids':assessment['evidence_ids'],
            'missing':assessment['gaps'],'next_steps':assessment['next_steps'],'scope':assessment['scope'],
            'ai_status':ai.get('status') if ai else 'NOT_RUN','human_review_required':True}
