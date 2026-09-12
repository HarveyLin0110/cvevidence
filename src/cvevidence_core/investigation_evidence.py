"""Re-verify dynamically found source observations before a rules reassessment."""
from .integrity import IntegrityError,digest
from .sources import read_excerpt,verify_excerpt
from .queries import collect_evidence
from .verifier import verify
from .assessment import assess

def reassess_after_investigation(context,previous_assessment,investigation,statements=()):
    """Raw observations are facts about bytes, never inferred condition booleans.

    A new material snapshot is analyzed independently. An AI finding on the same
    snapshot can add a verified source observation; only registered deterministic
    extractors can turn its contents into a formal CVE condition.
    """
    context.assert_current()
    if investigation.get('context_hash')!=context.context_hash or previous_assessment.get('context_hash')!=context.context_hash:
        raise IntegrityError('追加調查不能跨快照搬用證據')
    if investigation.get('engineering_assessment_id')!=previous_assessment.get('assessment_id'):
        raise IntegrityError('追加調查未綁定原工程判定')
    if previous_assessment.get('assessment_id')!='A-'+digest({k:v for k,v in previous_assessment.items() if k!='assessment_id'}):
        raise IntegrityError('原工程判定已被改動')
    cve=previous_assessment['cve_id'];observations={};queries=[]
    for task in investigation.get('tasks',[]):
        if task.get('status')!='COMPLETED':continue
        action=task.get('action');output=task.get('result',{});excerpts=[]
        if action=='READ' and output.get('excerpt_id'):excerpts=[output]
        elif action=='SEARCH':excerpts=output.get('matches',[])
        ids=[]
        for excerpt in excerpts:
            if not verify_excerpt(context,excerpt):raise IntegrityError('AI 新取得的原文與目前快照不一致')
            raw=read_excerpt(context,excerpt['source_id'],excerpt['start_line'],excerpt['end_line'])
            payload={'fact_key':'source_excerpt','kind':'SOURCE_OBSERVATION','artifact_sha256':context.manifest['primary_artifact']['sha256'],
                     'source_id':raw['source_id'],'file_sha256':raw['file_sha256'],'start_line':raw['start_line'],'end_line':raw['end_line'],'value':raw['text']}
            eid='E-'+digest(payload)
            observations[eid]={'evidence_id':eid,**payload,'context_hash':context.context_hash,'verification':'EXACT_BYTES_AND_LOCATOR','condition_inference_verified':False}
            ids.append(eid)
        queries.append({'investigation_id':task.get('task_id'),'question':task.get('question'),'reason':task.get('reason'),'action':action,
                        'evidence_ids':ids,'required_files':task.get('required_files',[])})
    collection=collect_evidence(context,cve);verified=verify(context,collection)
    if not statements and previous_assessment.get('statement_context'):
        statements=[{'text':row['text'],'material_id':row.get('statement_id'),
                     'source_context_hash':row.get('source_context_hash',context.context_hash)}
                    for row in previous_assessment['statement_context']]
    current=assess(context,verified,statements)
    # If the caller retained a statement review but did not supply the original
    # statement material, keep its previous review state instead of dropping it.
    if previous_assessment.get('statement_reviews') and not statements:
        if previous_assessment['conditions']!=current['conditions']:raise IntegrityError('原聲明覆核狀態與目前條件不一致')
        if previous_assessment['verdict']=='NEEDS_INVESTIGATION':current=previous_assessment
        elif previous_assessment['verdict']!=current['verdict']:raise IntegrityError('聲明不能使未支持的安全判定被沿用')
    context.assert_current()
    changed=current['verdict']!=previous_assessment['verdict']
    return {'schema_version':'1.0','context_hash':context.context_hash,'cve_id':cve,'queries':queries,
            'new_evidence':list(observations.values()),'assessment':current,'verdict_changed':changed,
            'status':'REVERIFIED_AND_REASSESSED','condition_promotion':'DETERMINISTIC_PROFILE_ONLY',
            'explanation':'已把 AI 新找到的原文重新核對並記為來源觀測，再重跑 profile 與 Verifier。自由文字推論不升格為條件；若只是查閱同一快照，結果可能維持不變。'}
