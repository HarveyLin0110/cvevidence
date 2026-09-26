"""Auditable investigation metrics; no model self-grade or correctness claim."""

def evaluate(ai, *, expected_paths=(), previous=None):
    tasks=[t for t in ai.get('tasks',[]) if t.get('status')=='COMPLETED']
    requests=[r for t in tasks if t.get('action')=='ASK_USER' for r in t.get('evidence_requests',[])]
    rows=(ai.get('condition_dossier') or {}).get('conditions',[])
    paths={e['path'] for row in rows for e in row.get('evidence',[])}
    old={r['material'].casefold() for t in (previous or {}).get('tasks',[]) for r in t.get('evidence_requests',[])}
    expected=set(expected_paths)
    return {'status':ai.get('status'),'mode':ai.get('mode'),'call_count':len(ai.get('calls',[])),
        'condition_count':len(rows),'condition_layers':sorted({r['layer'] for r in rows}),
        'conditions_with_product_excerpts':sum(bool(r.get('evidence')) for r in rows),
        'expected_key_paths_found':sorted(paths&expected),'expected_key_paths_missing':sorted(expected-paths),
        'request_count':len(requests),'request_condition_count':len({r['condition_id'] for r in requests}),
        'repeated_materials':[r['material'] for r in requests if r['material'].casefold() in old],
        'rejected_or_failed_steps':sum(t.get('status')!='COMPLETED' for t in ai.get('tasks',[])),
        'continuation_linked':bool(ai.get('continuation_from')),'semantic_correctness':'REQUIRES_INDEPENDENT_REVIEW',
        'usage':ai.get('usage_summary'),'note':'量測是否讀取、引用與限量補件；不能取代人工判讀漏洞結論是否正確。'}
