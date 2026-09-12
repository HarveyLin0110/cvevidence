"""Pure core stages. Runner owns run IDs, persistence, snapshots and deadlines."""
from .integrity import ingest_package,IntegrityError,UnsupportedError,InputPackage
from .catalog import discover_candidates,CATALOG
from .queries import collect_evidence
from .verifier import verify
from .assessment import assess,check_claim,summarize,describe_condition_groups
from .ai import investigate
from .supplements import interpret_statement
from .investigation_evidence import reassess_after_investigation

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
        event('QUERIES','STARTED',cve_id);collection=collect_evidence(context,cve_id);event('QUERIES','COMPLETED',cve_id)
        event('VERIFY','STARTED',cve_id);verified=verify(context,collection);event('VERIFY','COMPLETED',cve_id)
        notes=[interpret_statement(x,context.context_hash) if isinstance(x,str) else x for x in statements]
        assessment=assess(context,verified,notes);event('ASSESS','COMPLETED',cve_id)
        public_record=None;query_plan=None
        if cve_id not in CATALOG:
            from .public_cve import lookup
            from .general_triage import plan
            event('PUBLIC_CVE','STARTED',cve_id)
            public_record=lookup(cve_id)
            query_plan=plan(cve_id,context,public_record)
            event('PUBLIC_CVE',public_record['status'],cve_id)
        event('AI','STARTED',cve_id)
        ai=investigate(context,verified,assessment,symptom+'\n'+'\n'.join(x.get('text','') for x in notes),mode=mode,env_file=env_file,
                       **({'public_record':public_record} if public_record is not None else {}))
        event('AI',ai['status'],cve_id)
        followup=reassess_after_investigation(context,assessment,ai,notes) if ai['status'] in {'COMPLETED','NEEDS_USER_INPUT'} else None
        results.append({'cve_id':cve_id,'status':'COMPLETED','queries':collection['queries'],'evidence':collection['evidence'],
                        'condition_groups':describe_condition_groups(cve_id),
                        'followup_queries':collection['followup_queries'],'runtime_observation':collection['runtime_observation'],
                        'assessment':assessment,'claim_checks':[check_claim(context,assessment,c) for c in claims if c.get('cve_id')==cve_id],
                         'ai':ai,'investigation_verification':followup,'summary':summarize(assessment,ai)})
        if public_record is not None:
            results[-1].update(public_cve_record=public_record,query_plan=query_plan)
    context.assert_current()
    executed=[r for r in results if r.get('assessment')]
    return {'schema_version':'1.0','status':'COMPLETED','context_hash':context.context_hash,'input':context.public(),
            'discovery':discovery,'analyses':results,'engineering_status':'COMPLETED' if any(r.get('assessment') for r in results) else 'NOT_RUN',
            'ai_status':'NOT_RUN' if not executed else 'OFFLINE' if mode=='OFFLINE' else 'COMPLETED' if all(r['ai']['status'] in {'COMPLETED','NEEDS_USER_INPUT'} for r in executed) else 'INCOMPLETE'}

def investigate_after_engineering(package,engineering_result,user_context='',*,env_file=None,event_callback=None,analysis_depth='focused'):
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
        for field in ('followup_queries','runtime_observation'):
            if field in entry:collection[field]=entry[field]
        verified=verify(context,collection)
        if event_callback:event_callback({'stage':'AI','status':'STARTED','cve_id':entry['cve_id']})
        depth_options={'analysis_depth':'pc','max_calls':12,'timeout_seconds':145} if analysis_depth=='pc' else {}
        if analysis_depth not in {'focused','pc'}:raise ValueError('Unknown AI analysis depth')
        ai=investigate(context,verified,assessment,user_context,mode='LIVE',env_file=env_file,**depth_options,
                       **({'public_record':entry['public_cve_record']} if 'public_cve_record' in entry else {}))
        if event_callback:event_callback({'stage':'AI','status':ai['status'],'cve_id':entry['cve_id']})
        followup=reassess_after_investigation(context,assessment,ai) if ai['status'] in {'COMPLETED','NEEDS_USER_INPUT'} else None
        results.append({'cve_id':entry['cve_id'],'engineering_assessment_id':assessment['assessment_id'],'ai':ai,'investigation_verification':followup})
    return {'schema_version':'1.0','context_hash':context.context_hash,'mode':'LIVE','analyses':results,
            'status':'NOT_RUN' if not results else 'COMPLETED' if all(x['ai']['status'] in {'COMPLETED','NEEDS_USER_INPUT'} for x in results) else 'INCOMPLETE'}
