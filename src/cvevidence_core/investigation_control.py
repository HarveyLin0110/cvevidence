"""Trusted per-attempt controls; never configured by model or uploaded text."""
from contextvars import ContextVar
from copy import deepcopy
from .integrity import digest,IntegrityError
from .sources import verify_excerpt
control=ContextVar('investigation_control',default={})


def budget_forecast(calls,threshold,remaining_calls,review_pending):
    """Conservative scheduling advice from receipts, never a token hard cap."""
    reported=usage(calls)
    costs=[usage([call])['total_tokens'] for call in calls
           if usage([call])['complete'] and usage([call])['total_tokens']>0]
    left=max(0,threshold-reported['total_tokens'])
    # Account for growing context and room for a larger structured REVIEW.
    estimate=max(costs[-2:])+max(0,costs[-1]-costs[-2] if len(costs)>1 else 0)+9000 if costs else None
    affordable=min(remaining_calls,max(1,left//estimate)) if estimate else remaining_calls
    reserve=2 if review_pending else 1
    phase=('REPORT_NOW' if review_pending and affordable<=1 else
           'REVIEW_NOW' if review_pending and affordable<=reserve else
           'FINALIZE_NOW' if not review_pending and affordable<=reserve else 'INVESTIGATE')
    return {'remaining_reported_token_allowance':left,'estimated_next_call_tokens':estimate,
        'estimated_affordable_calls_including_current':affordable,'recommended_phase':phase,
        'estimate_note':'依供應者用量估算，非保證。只剩一次且已可交覆核時用 REPORT 同次提交條件與摘要；需要補件仍須合法 REVIEW／ASK_USER。查不完保留 NOT_REVIEWED 並接續，不捏造支持。'}


def usage(calls):
    """Sum known counts without turning absent provider fields into zero usage."""
    totals={'input_tokens':0,'output_tokens':0,'total_tokens':0}
    known=0; complete_calls=0
    for call in calls:
        raw=call.get('usage')
        if not isinstance(raw,dict):continue
        values={k:v for k,v in raw.items() if k in totals and type(v) is int and v>=0}
        if not values:continue
        known+=1
        for key in ('input_tokens','output_tokens'):
            totals[key]+=values.get(key,0)
        # Cached input is a subset of input, not an additional chargeable count.
        totals['total_tokens']+=values.get('total_tokens',sum(values.get(k,0) for k in ('input_tokens','output_tokens')))
        if 'total_tokens' in values or all(k in values for k in ('input_tokens','output_tokens')):
            complete_calls+=1
    return {**totals,'reported_calls':known,'total_calls':len(calls),'complete':complete_calls==len(calls),
        'note':'供應者回報用量；缺少總數時加總已知輸入／輸出，缺值不代表零用量，非費用。達門檻後停止下一次呼叫，進行中的呼叫可能超出門檻。'}


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
    read_ids=set(previous.get('retained_read_excerpt_ids',[])) & known
    from .source_reading import completed_reads
    for task in previous.get('tasks',[]):
        for excerpt in completed_reads(task):
            if excerpt.get('excerpt_id') in known and verify_excerpt(context,{**excerpt,'context_hash':context.context_hash}):
                read_ids.add(excerpt['excerpt_id'])
    conditions=deepcopy(plan['conditions'])
    for row in conditions:
        original=list(row['citations']);row['citations']=[x for x in original if x in known]
        if 'evidence_quotes' in row:
            row['evidence_quotes']=[q for q in row['evidence_quotes'] if q['excerpt_id'] in row['citations']]
        # New materials may resolve an old gap. Every continuation reviews again.
        if any(x not in known for x in original) or row['state'] in ('USER_MATERIAL_MISSING','CAPABILITY_GAP','CONFLICT'):
            row.update(state='NOT_REVIEWED',explanation='前次觀察：'+row['explanation'][:400]+'；本輪須重新查核新增材料。')
    return {'previous_record_hash':previous['record_hash'],'conditions':conditions,'excerpts':retained,
        'retained_read_excerpt_ids':sorted(read_ids),
        'stale_excerpt_ids':stale,'public_sources':deepcopy(previous.get('public_sources',{})),
        'previous_questions':[{'question':t.get('question'),'finding':t.get('finding'),'required_files':t.get('required_files',[])}
            for t in previous.get('tasks',[]) if t.get('status')=='COMPLETED' and t.get('action') in ('ASK_USER','COMPLETE','REPORT')][-3:],
        'note':'沿用的是重新核對相同 bytes 的觀察；未回答問題與新增材料必須再 REVIEW，不能沿用舊正式判定。'}


def publish(result, excerpts, *, phase):
    callback=control.get().get('progress')
    if callback:
        snapshot=deepcopy(result);snapshot['excerpts']=list(excerpts.values());snapshot['progress_phase']=phase
        snapshot['usage_summary']=usage(snapshot.get('calls',[]))
        snapshot['record_hash']=digest({k:v for k,v in snapshot.items() if k!='record_hash'})
        callback(snapshot)
