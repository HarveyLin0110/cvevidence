"""Trusted per-attempt controls; never configured by model or uploaded text."""
from contextvars import ContextVar
from copy import deepcopy
from .integrity import digest,IntegrityError
from .sources import verify_excerpt
control=ContextVar('investigation_control',default={})


def usage(calls):
    totals={'input_tokens':0,'output_tokens':0,'total_tokens':0};known=0
    for call in calls:
        raw=call.get('usage')
        if not isinstance(raw,dict):continue
        known+=1
        for k in totals:
            value=raw.get(k)
            if isinstance(value,int) and not isinstance(value,bool) and value>=0:totals[k]+=value
        if 'total_tokens' not in raw:totals['total_tokens']+=sum(raw.get(k,0) for k in ('input_tokens','output_tokens') if isinstance(raw.get(k,0),int))
    return {**totals,'reported_calls':known,'total_calls':len(calls),'complete':known==len(calls),
        'note':'供應者回報用量；非費用。達門檻後停止下一次呼叫，進行中的呼叫可能超出門檻。'}


def continuation(context,cve,previous):
    if not previous:return None
    if previous.get('cve_id')!=cve:raise IntegrityError('Continuation CVE mismatch')
    if previous.get('record_hash')!=digest({k:v for k,v in previous.items() if k!='record_hash'}):raise IntegrityError('Continuation hash mismatch')
    plan=previous.get('condition_plan')
    if not plan:return {'previous_record_hash':previous['record_hash'],'note':'前次尚未建立條件；需重新規劃。'}
    if plan.get('plan_hash')!=digest(plan['conditions']):raise IntegrityError('Continuation plan changed')
    retained=[];stale=[]
    for x in previous.get('excerpts',[]):
        mapped={**x,'context_hash':context.context_hash}
        if verify_excerpt(context,mapped):retained.append(mapped)
        else:stale.append(x['excerpt_id'])
    known={x['excerpt_id'] for x in retained}
    conditions=deepcopy(plan['conditions'])
    for row in conditions:
        original=list(row['citations']);row['citations']=[x for x in original if x in known]
        # New materials may resolve an old gap. Every continuation reviews again.
        if any(x not in known for x in original) or row['state'] in ('USER_MATERIAL_MISSING','CAPABILITY_GAP','CONFLICT'):
            row.update(state='NOT_REVIEWED',explanation='前次觀察：'+row['explanation'][:400]+'；本輪須重新查核新增材料。')
    return {'previous_record_hash':previous['record_hash'],'conditions':conditions,'excerpts':retained,
        'stale_excerpt_ids':stale,'public_sources':deepcopy(previous.get('public_sources',{})),
        'previous_questions':[{'question':t.get('question'),'finding':t.get('finding'),'required_files':t.get('required_files',[])}
            for t in previous.get('tasks',[]) if t.get('status')=='COMPLETED' and t.get('action') in ('ASK_USER','COMPLETE')][-3:],
        'note':'沿用的是重新核對相同 bytes 的觀察；未回答問題與新增材料必須再 REVIEW，不能沿用舊正式判定。'}


def publish(result, excerpts, *, phase):
    callback=control.get().get('progress')
    if callback:
        snapshot=deepcopy(result);snapshot['excerpts']=list(excerpts.values());snapshot['progress_phase']=phase
        snapshot['usage_summary']=usage(snapshot.get('calls',[]))
        snapshot['record_hash']=digest({k:v for k,v in snapshot.items() if k!='record_hash'})
        callback(snapshot)
