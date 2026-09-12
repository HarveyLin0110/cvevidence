"""Pure core stages. Runner owns run IDs, persistence, snapshots and deadlines."""
from .integrity import ingest_package,IntegrityError,UnsupportedError,InputPackage
from .catalog import discover_candidates,CATALOG
from .queries import collect_evidence
from .verifier import verify
from .assessment import assess,check_claim,summarize
from .ai import investigate
from .supplements import interpret_statement

def analyze_package(package,requested_cves=None,symptom='',statements=(),claims=(),mode='OFFLINE',env_file=None,event_callback=None):
    def event(stage,status,cve_id=None):
        if event_callback:event_callback({'stage':stage,'status':status,'cve_id':cve_id})
    if package is None:
        return {'status':'AWAITING_INPUT','discovery':discover_candidates(None,symptom,requested_cves),'analyses':[],'engineering_status':'NOT_RUN','ai_status':'NOT_RUN'}
    event('INGEST','STARTED');context=package if isinstance(package,InputPackage) else ingest_package(package);context.assert_current();event('INGEST','COMPLETED')
    discovery=discover_candidates(context,symptom,requested_cves)
    selected=requested_cves or [x['cve_id'] for x in discovery['candidates']]
    selected=list(dict.fromkeys(x.upper().strip() for x in selected))
    results=[]
    for cve_id in selected:
        if cve_id not in CATALOG:
            results.append({'cve_id':cve_id,'status':'UNSUPPORTED_CVE','assessment':None,'ai':None});continue
        event('QUERIES','STARTED',cve_id);collection=collect_evidence(context,cve_id);event('QUERIES','COMPLETED',cve_id)
        event('VERIFY','STARTED',cve_id);verified=verify(context,collection);event('VERIFY','COMPLETED',cve_id)
        notes=[interpret_statement(x,context.context_hash) if isinstance(x,str) else x for x in statements]
        assessment=assess(context,verified,notes);event('ASSESS','COMPLETED',cve_id)
        event('AI','STARTED',cve_id)
        ai=investigate(context,verified,assessment,symptom+'\n'+'\n'.join(x.get('text','') for x in notes),mode=mode,env_file=env_file)
        event('AI',ai['status'],cve_id)
        results.append({'cve_id':cve_id,'status':'COMPLETED','queries':collection['queries'],'evidence':collection['evidence'],
                        'assessment':assessment,'claim_checks':[check_claim(context,assessment,c) for c in claims if c.get('cve_id')==cve_id],
                        'ai':ai,'summary':summarize(assessment,ai)})
    context.assert_current()
    executed=[r for r in results if r.get('assessment')]
    return {'schema_version':'1.0','status':'COMPLETED','context_hash':context.context_hash,'input':context.public(),
            'discovery':discovery,'analyses':results,'engineering_status':'COMPLETED' if any(r.get('assessment') for r in results) else 'NOT_RUN',
            'ai_status':'NOT_RUN' if not executed else 'OFFLINE' if mode=='OFFLINE' else 'COMPLETED' if all(r['ai']['status'] in {'COMPLETED','NEEDS_USER_INPUT'} for r in executed) else 'INCOMPLETE'}

def investigate_after_engineering(package,engineering_result,user_context='',*,env_file=None,event_callback=None):
    """Attach a later AI stage to saved engineering data, without replacing it."""
    context=package if isinstance(package,InputPackage) else ingest_package(package)
    context.assert_current()
    if engineering_result.get('status')!='COMPLETED' or engineering_result.get('context_hash')!=context.context_hash:
        raise IntegrityError('AI 階段不屬於已保存的工程快照')
    results=[]
    for entry in engineering_result.get('analyses',[]):
        assessment=entry.get('assessment')
        if not assessment:continue
        collection={'schema_version':'1.0','cve_id':entry['cve_id'],'profile_version':assessment['profile_version'],
                    'context_hash':context.context_hash,'queries':entry['queries'],'evidence':entry['evidence']}
        verified=verify(context,collection)
        if event_callback:event_callback({'stage':'AI','status':'STARTED','cve_id':entry['cve_id']})
        ai=investigate(context,verified,assessment,user_context,mode='LIVE',env_file=env_file)
        if event_callback:event_callback({'stage':'AI','status':ai['status'],'cve_id':entry['cve_id']})
        results.append({'cve_id':entry['cve_id'],'engineering_assessment_id':assessment['assessment_id'],'ai':ai})
    return {'schema_version':'1.0','context_hash':context.context_hash,'mode':'LIVE','analyses':results,
            'status':'NOT_RUN' if not results else 'COMPLETED' if all(x['ai']['status'] in {'COMPLETED','NEEDS_USER_INPUT'} for x in results) else 'INCOMPLETE'}
