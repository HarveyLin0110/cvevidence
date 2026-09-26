"""Auditable investigation metrics; no model self-grade or correctness claim."""

def evaluate(ai, *, expected_paths=(), previous=None):
    tasks=[t for t in ai.get('tasks',[]) if t.get('status')=='COMPLETED']
    requests=[r for t in tasks if t.get('action')=='ASK_USER' for r in t.get('evidence_requests',[])]
    rows=(ai.get('condition_dossier') or {}).get('conditions',[])
    paths={e['path'] for row in rows for e in row.get('evidence',[])}
    available={e['source_id'] for e in ai.get('excerpts',[]) if e.get('source_id')}
    available.update(e['source_id'] for e in ai.get('initial_product_excerpts',[]) if e.get('source_id'))
    read_ids={t['result']['source_id'] for t in tasks if t.get('action')=='READ'
              and isinstance(t.get('result'),dict) and t['result'].get('source_id')}
    cited_ids={e['source_id'] for row in rows for e in row.get('evidence',[]) if e.get('source_id')}
    errors={}
    for task in ai.get('tasks',[]):
        if task.get('status')!='COMPLETED':
            action=task.get('action','UNKNOWN');errors[action]=errors.get(action,0)+1
    old={r['material'].casefold() for t in (previous or {}).get('tasks',[]) for r in t.get('evidence_requests',[])}
    expected=set(expected_paths)
    return {'status':ai.get('status'),'mode':ai.get('mode'),'call_count':len(ai.get('calls',[])),
        'condition_count':len(rows),'condition_layers':sorted({r['layer'] for r in rows}),
        'conditions_with_product_excerpts':sum(bool(r.get('evidence')) for r in rows),
        'expected_key_paths_found':sorted(paths&expected),'expected_key_paths_missing':sorted(expected-paths),
        'available_excerpt_source_ids':sorted(available),
        'explicit_read_source_ids':sorted(read_ids),
        'condition_cited_source_ids':sorted(cited_ids),
        'available_but_not_condition_cited_source_ids':sorted((available|read_ids)-cited_ids),
        'failed_steps_by_action':errors,
        'request_count':len(requests),'request_condition_count':len({r['condition_id'] for r in requests}),
        'repeated_materials':[r['material'] for r in requests if r['material'].casefold() in old],
        'rejected_or_failed_steps':sum(t.get('status')!='COMPLETED' for t in ai.get('tasks',[])),
        'continuation_linked':bool(ai.get('continuation_from')),'semantic_correctness':'REQUIRES_INDEPENDENT_REVIEW',
        'usage':ai.get('usage_summary'),'note':'expected_key_paths 衡量條件引用，不等於讀取覆蓋率。原文可用、明確 READ 與條件引用分開統計；未引用不代表未讀，已取得不代表模型理解或語意支持。量測不重新驗證原檔，不能取代人工判讀。'}
