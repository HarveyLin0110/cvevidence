"""Versioned, operator-reviewed investigation rules. Never executable verdicts.

Drafts contain public condition definitions only, not product evidence or results.
Activation is a local operator operation, outside every model/upload tool.
"""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from .integrity import digest, IntegrityError
from .condition_plan import validate


def _cve(cve):
    if not isinstance(cve,str) or not re.fullmatch(r'CVE-\d{4}-\d{4,20}',cve):raise ValueError('Invalid CVE')
    return cve


def _seal(value):
    return {**value,'rule_hash':digest(value)}


def check(value):
    if not isinstance(value,dict) or value.get('rule_hash')!=digest({k:v for k,v in value.items() if k!='rule_hash'}):
        raise IntegrityError('Rule bytes changed')
    _cve(value['cve_id'])
    if value.get('kind')!='INVESTIGATION_RULE' or value.get('schema_version')!='1.0':raise ValueError('Unsupported rule')
    if value.get('status') not in ('DRAFT','REVIEWED'):raise ValueError('Invalid rule status')
    if value.get('formal_verdict_enabled') is not False:raise ValueError('Rule cannot authorize verdicts')
    for s in value['public_sources']:
        if s.get('text_sha256')!=hashlib.sha256(s['text'].encode()).hexdigest():raise IntegrityError('Rule source changed')
        if not isinstance(s.get('url'),str) or not s['url'].startswith('https://'):raise ValueError('Public URL required')
    validate(value['conditions'], value['public_sources'])
    if value['status']=='REVIEWED':
        review=value.get('review',{})
        for key in ('reviewer','rationale','applicability','validation_reference'):
            if not isinstance(review.get(key),str) or not review[key].strip():raise ValueError('Review incomplete')
        if review.get('all_conditions_reviewed') is not True:raise ValueError('Review all conditions')
    return value


def draft(investigation):
    if investigation.get('record_hash')!=digest({k:v for k,v in investigation.items() if k!='record_hash'}):
        raise IntegrityError('Investigation changed')
    plan=investigation.get('condition_plan') or {}
    if (plan.get('plan_hash')!=digest(plan.get('conditions',[])) or plan.get('cve_id')!=investigation.get('cve_id')
            or not plan.get('context_hash') or plan.get('context_hash')!=investigation.get('context_hash')):
        raise ValueError('No verified condition plan')
    public=(investigation.get('public_sources') or {}).get('sources',[])
    used={r['public_source_id'] for r in plan['conditions']}
    sources=[{k:r[k] for k in ('source_id','url','text','text_sha256')} for r in public if r['source_id'] in used]
    rows=[{**r,'state':'NOT_REVIEWED','citations':[],'explanation':'依本次產品材料重新查核，不沿用其他案件結論。'} for r in plan['conditions']]
    validate(rows,sources)
    result=_seal({'schema_version':'1.0','kind':'INVESTIGATION_RULE','status':'DRAFT',
        'cve_id':_cve(investigation['cve_id']),'conditions':rows,'public_sources':sources,
        'created_at':datetime.now(timezone.utc).isoformat(),'formal_verdict_enabled':False,
        'origin':'PUBLIC_CONDITION_DEFINITIONS_FROM_INVESTIGATION',
        'review_required':True})
    return check(result)


def review(draft_rule, *, reviewer, rationale, applicability, validation_reference):
    check(draft_rule)
    if draft_rule['status']!='DRAFT':raise ValueError('Review a draft, not an existing release')
    result={k:deepcopy(v) for k,v in draft_rule.items() if k!='rule_hash'}
    result.update(status='REVIEWED',review_required=False,draft_hash=draft_rule['rule_hash'],
        review={'reviewer':reviewer,'rationale':rationale,'applicability':applicability,
                'validation_reference':validation_reference,'all_conditions_reviewed':True,
                'reviewer_authenticated':False,'reviewed_at':datetime.now(timezone.utc).isoformat()})
    return check(_seal(result))


def root():
    return Path(os.environ.get('CVEVIDENCE_RULE_LIBRARY', str(Path(__file__).resolve().parents[2]/'var/rule-library')))


def _read(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size>2_000_000:raise ValueError('Invalid rule file')
    return json.loads(path.read_text())


def install(rule, directory=None):
    check(rule)
    if rule['status']!='REVIEWED':raise ValueError('Only reviewed rules can be installed')
    serialized=json.dumps(rule,ensure_ascii=False,indent=2)
    if len(serialized.encode('utf-8'))>2_000_000:raise ValueError('Rule exceeds storage limit')
    base=Path(directory) if directory is not None else root()
    base.mkdir(parents=True,exist_ok=True)
    file=base/(rule['cve_id']+'-'+rule['rule_hash']+'.json')
    with file.open('x',encoding='utf-8') as out:
        os.chmod(file,0o600);out.write(serialized)
    return file


def activate(cve, rule_hash, directory=None):
    _cve(cve)
    if not re.fullmatch(r'[a-f0-9]{64}',rule_hash):raise ValueError('Invalid revision')
    base=Path(directory) if directory is not None else root()
    rule=check(_read(base/(cve+'-'+rule_hash+'.json')))
    if rule['status']!='REVIEWED' or rule['cve_id']!=cve:raise ValueError('Cannot activate rule')
    pointer=base/(cve+'.active.json')
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w',dir=base,delete=False) as f:
        json.dump({'cve_id':cve,'rule_hash':rule_hash},f);temporary=Path(f.name)
    os.replace(temporary,pointer)


def select(cve, current_sources, directory=None):
    """Unavailable/stale sources cause fresh planning, never silently reuse old rules."""
    _cve(cve);base=Path(directory) if directory is not None else root()
    pointer=base/(cve+'.active.json')
    if not pointer.exists():return {'status':'NO_ACTIVE_RULE'}
    try:
        active=_read(pointer);rh=active['rule_hash']
        if not re.fullmatch(r'[a-f0-9]{64}',rh) or active['cve_id']!=cve:raise ValueError('Invalid pointer')
        rule=check(_read(base/(cve+'-'+rh+'.json')))
        if rule['cve_id']!=cve or rule['status']!='REVIEWED':raise ValueError('Invalid active rule')
        by_url={s['url']:s for s in current_sources}
        mapping={}
        for s in rule['public_sources']:
            current=by_url.get(s['url'])
            if (not current or current.get('text_sha256')!=s['text_sha256']
                or hashlib.sha256(current['text'].encode()).hexdigest()!=s['text_sha256']):
                return {'status':'SOURCE_CHANGED_OR_UNAVAILABLE','rule_hash':rh,
                    'reason':'公告已變更或本輪未取得，須建立新草稿並覆核；舊版本留存。'}
            mapping[s['source_id']]=current['source_id']
        conditions=[{**r,'public_source_id':mapping[r['public_source_id']]} for r in rule['conditions']]
        validate(conditions,current_sources)
        return {'status':'CURRENT_REVIEWED_RULE','rule_hash':rh,'conditions':conditions,
            'applicability':rule['review']['applicability'],'formal_verdict_enabled':False}
    except (OSError,ValueError,KeyError,TypeError):
        return {'status':'INVALID_RULE','reason':'規則或啟用指標無法核對；改採本次公告重新規劃。'}
