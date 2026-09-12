"""Deterministic engineering conditions; AI prose cannot change the verdict."""
from .catalog import CATALOG
from .verifier import require_verified
from .integrity import digest
from .supplements import interpret_statement,statement_parts

LABELS={'build_identity':'同一成品與 build 身分','component':'元件與已審查版本',
        'library_binding':'元件 source／object／library 綁定','product_binding':'產品實際連結綁定',
        'scope_complete':'交付成品的分析範圍完整','vulnerable_implementation':'受影響實作存在且未有效排除',
        'entry_reachable':'成品的靜態輸入路徑','trigger_prerequisites':'實作中的漏洞必要條件',
        'runtime_observation':'同成品的部署／運作條件觀測'}
GUARDS=('build_identity','component','library_binding','product_binding','scope_complete')
NECESSARY=('vulnerable_implementation','entry_reachable','trigger_prerequisites','runtime_observation')

def describe_condition_groups(cve_id):
    """Presentation semantics only; groups never replace profile conditions or rules."""
    if cve_id not in CATALOG:raise ValueError('No reviewed condition grouping for this CVE')
    return {'schema_version':'2.0','cve_id':cve_id,'grouping_only':True,
            'shared_prerequisite_ids':['build_identity','library_binding','product_binding','scope_complete'],
            'groups':[
                {'group_id':'PC1','title':'元件適用性','condition_ids':['component'],
                 'meaning':'核對元件與已審查版本，並由共用綁定證據確認它屬於目前成品。'},
                {'group_id':'PC2','title':'成品實作與靜態路徑','condition_ids':['vulnerable_implementation','entry_reachable','trigger_prerequisites'],
                 'meaning':'這份成品編入什麼：核對原碼、修補、功能設定、成品綁定及靜態輸入路徑；不代表設備已如此運作。'},
                {'group_id':'PC3','title':'部署與實際運作','condition_ids':['runtime_observation'],
                 'meaning':'這個成品如何運作：核對同成品的命令、正常交互原始紀錄及配置；缺件保持未知，受控觀測不冒充客戶實機。'}],
            'note':'PC 分組僅供呈現，沒有另算三個布林值；正式判定仍看所有條件、共用前提、範圍與衝突。'}

def _review_statements(context,facts,states,statements,conflicts):
    """Recheck original text against this receipt, never trust supplied review flags."""
    history=[];pending=[]
    guards=all(states[k]=='SUPPORTED' for k in GUARDS) and not conflicts
    for statement in statements:
        if isinstance(statement,str):statement=interpret_statement(statement,context.context_hash)
        # Validate text even when workflow receives a persisted material dictionary.
        material=interpret_statement(statement.get('text',''),statement.get('source_context_hash',context.context_hash))
        checks=[]
        for part in statement_parts(material['text'],context.manifest['format']):
            kind=part['kind'];ids=[];blocking=True;status=kind
            if kind=='OPERATIONAL_CONTEXT':
                blocking=False;reason='操作說明未新增工程主張，不改變已驗條件。'
            elif kind=='CONDITION_CLAIM':
                key=part['condition_id'];record=facts.get(key)
                ids=[record['evidence_id']] if record else []
                expected='SUPPORTED' if part['claimed_value'] else 'BLOCKED'
                if states[key]==expected and guards:
                    blocking=False;status='CONSISTENT_WITH_VERIFIED_EVIDENCE'
                    reason='目前同 build 證據與此工程主張一致；文字本身仍非工程證據。'
                    ids += [facts[k]['evidence_id'] for k in GUARDS]
                elif states[key] not in ('UNKNOWN',expected):
                    status='CONFLICTS_WITH_VERIFIED_EVIDENCE'
                    reason='文字與已驗條件「'+LABELS[key]+'」相反；請核對同 build 原始工程資料及聲明範圍。'
                else:
                    status='UNVERIFIED_ENGINEERING_CLAIM'
                    reason='請補同 build 的「'+LABELS[key]+'」及成品綁定／範圍證據；口述不能補足工程條件。'
            elif kind=='ARTIFACT_SCOPE':
                path=part['path']
                # Merely uploading a named file is insufficient: both the verified
                # delivery inventory and product binding must cover its exact path.
                covered=guards and all(any(w['path']==path for w in facts[k]['witnesses']) for k in ('scope_complete','product_binding'))
                if covered:
                    blocking=False;status='CONSISTENT_WITH_VERIFIED_EVIDENCE'
                    ids=[facts[k]['evidence_id'] for k in GUARDS]
                    reason='所指成品已包含於目前已驗交付清單與產品綁定；文字本身仍非工程證據。'
                else:
                    status='UNRESOLVED_SCOPE'
                    reason='請補 '+path+' 的同 build 成品、source／link 綁定與入口證據，確認它納入已審查範圍。'
            elif kind=='UNRESOLVED_SCOPE':
                reason='此段指出額外或未涵蓋的入口／成品；請提供具體路徑及同 build 的交付、編譯連結與入口證據：'+part['text']
            else:
                reason='此段尚無可完整核對的語意規則；請釐清它涉及的工程條件、入口或成品，並提供同 build 證據：'+part['text']
            checks.append({**part,'status':status,'blocks_verdict':blocking,'reason':reason,'evidence_ids':list(dict.fromkeys(ids))})
        blocking=any(c['blocks_verdict'] for c in checks)
        entry={'statement_id':statement.get('material_id') or material['material_id'],'text':material['text'],
               'source_context_hash':material['source_context_hash'],'assessed_context_hash':context.context_hash,
               'verified_engineering_fact':False,'review_required':True,'blocks_verdict':blocking,
               'reason':'；'.join(dict.fromkeys(c['reason'] for c in checks if c['blocks_verdict']==blocking)),
               'checks':checks}
        history.append(entry)
        if blocking:pending.append(entry)
    return history,pending

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
    statement_context,reviews=_review_statements(context,facts,states,statements,conflicts)
    guards=all(states[k]=='SUPPORTED' for k in GUARDS)
    blocked=[k for k in NECESSARY if states[k]=='BLOCKED']
    if conflicts or reviews:verdict='NEEDS_INVESTIGATION';reason='證據有矛盾或文字補充仍有具體工程／範圍事項待覆核。'
    elif guards and blocked:verdict='NOT_AFFECTED';reason='已核對成品範圍與綁定，且有必要條件被有效阻斷。'
    elif guards and all(states[k]=='SUPPORTED' for k in NECESSARY):verdict='AFFECTED';reason='目前交付成品的所有必要工程條件均有可核對證據支持。'
    else:verdict='NEEDS_INVESTIGATION';reason='尚有必要證據、綁定或分析範圍缺口，不能判為安全。'
    gaps=[{'query_id':q['query_id'],'needed':m,'same_build_required':True} for q in verified.queries for m in q['missing']]
    playbook={
        'rom':'提供同一 ROM hash 的 SDK/source、libssl 每個 object 的編譯紀錄、heartbeat 旗標與預處理輸出、實際 linker map。',
        'cmake':'提供同次產品 source、CMake compile/link 紀錄、libz.a 與 linker map，核對 inflateGetHeader 及 extra/chunk 容量。',
        'curl':'提供同成品 hash 的 launcher/config、libcurl 與 compiler/link 紀錄，以及 SOCKS5 DNS/握手與 buffer 設定觀測。'}
    next_steps = [playbook[context.manifest['format']]]
    if guards and not reviews and not conflicts and all(states[k]=='SUPPORTED' for k in NECESSARY if k!='runtime_observation') and states['runtime_observation']=='UNKNOWN':
        next_steps = ['PC2 工程證據已齊全；請補同成品 runtime/observation.json 及其引用的正常運作原始輸出／配置，或覆核不一致的材料。']
    result={'schema_version':'1.0','cve_id':verified.cve_id,'profile_version':verified.profile_version,'context_hash':context.context_hash,
            'verdict':verdict,'reason':reason,'conditions':conditions,'conflicts':conflicts,'statement_reviews':reviews,'gaps':gaps,
            'next_steps':next_steps if verdict=='NEEDS_INVESTIGATION' else ['由工程師覆核成品範圍、交付紀錄可信度與實際部署環境。'],
            'blocked_conditions':blocked if guards else [],'evidence_ids':[r['evidence_id'] for r in verified.records],
            'source_advisories':CATALOG[verified.cve_id]['sources'],'human_review_required':True,'provenance_verified':False,
            'scope':'只涵蓋目前提交的成品與已審查程式路徑；未證明實際部署暴露、漏洞已被利用或異常由此 CVE 造成。',
            'symptom_causation':'NOT_ESTABLISHED','verification_hash':verified.collection_hash}
    if statement_context:result['statement_context']=statement_context
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
