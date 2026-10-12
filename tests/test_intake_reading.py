"""TEST_ONLY initial evidence delivery; never real build/CVE certification."""
from copy import deepcopy
import hashlib
import pytest
from tests.test_turnkey import context
from cvevidence_core.intake_reading import prepare,ROLE_BYTES,ROLE_ATTEMPTS
from cvevidence_core.integrity import IntegrityError,digest
from cvevidence_core.sources import verify_excerpt


def test_supporting_originals_are_complete_before_plan_without_reading_code(tmp_path):
    c=context(tmp_path,[('build/receipt.json',('TEST_ONLY unsigned receipt\n'+'declared field\n'*78+'TEST_ONLY output relation\n').encode()),
        ('runtime/input.txt',b'4 17\n'),('runtime/normal.txt',b'TEST_ONLY normal operation\n'),
        ('source/main.c',b'TEST_ONLY implementation must be investigated')])
    r=prepare(c,[]);by_path={x['path']:x for x in r['reading']['records']}
    assert set(by_path)=={'build/receipt.json','runtime/input.txt','runtime/normal.txt'}
    assert all(x['complete_text'] and not x['same_build_verified'] and not x['semantic_verification'] for x in by_path.values())
    assert by_path['build/receipt.json']['end_line']==80
    assert any(x['text']=='4 17' for x in r['excerpts'])
    assert all(verify_excerpt(c,x) for x in r['excerpts'])
    assert r['reading']['deferred_count']==0


def test_each_role_has_an_independent_utf8_budget_and_omitted_files_remain_discoverable(tmp_path):
    c=context(tmp_path,[('build/a.json',('中文'*1300).encode()),('build/b.json',b'TEST_ONLY '+b'x'*1000),
        ('runtime/input.txt',b'4 17\n'),('runtime/normal.txt',b'TEST_ONLY normal output'),
        ('runtime/too-many-lines.txt',b'x\n'*201),('runtime/too-large.txt',b'x'*(ROLE_BYTES+1))])
    r=prepare(c,[]);paths={x['path'] for x in r['reading']['records']}
    assert paths=={'build/a.json','runtime/input.txt','runtime/normal.txt'}
    deferred={x['path']:x for x in r['reading']['deferred']}
    assert deferred['build/b.json']['reason']=='ROLE_BYTE_LIMIT'
    assert deferred['runtime/too-many-lines.txt']['reason']=='LONG_FILE_NEEDS_TARGETED_READ'
    assert deferred['runtime/too-large.txt']['reason']=='LARGE_FILE_NEEDS_TARGETED_READ'
    assert all(not x['user_material_missing'] for x in deferred.values())
    assert all(c.sources[x['source_id']]['path']==x['path'] for x in deferred.values())
    assert r['reading']['utf8_bytes']==sum(len(x['text'].encode()) for x in r['excerpts'])


def test_large_identity_retains_existing_partial_read_without_claiming_full_text(tmp_path):
    c=context(tmp_path,[('sbom.cdx.json',b'TEST_ONLY inventory line\n'*400),('build/receipt.json',b'TEST_ONLY separate build record')])
    row=c.by_path('sbom.cdx.json')[1];r=prepare(c,[row]);initial=r['reading']['records'][0]
    assert initial['path']=='sbom.cdx.json' and initial['end_line']==60 and not initial['complete_text']
    assert r['reading']['records'][1]['path']=='build/receipt.json'
    assert all(verify_excerpt(c,x) for x in r['excerpts'])


def test_invalid_text_and_role_limits_are_bounded_without_claiming_missing_material(tmp_path):
    c=context(tmp_path,[(f'runtime/{i:02}.txt',b'\xff TEST_ONLY') for i in range(26)])
    r=prepare(c,[])
    assert not r['excerpts'] and len(r['errors'])==ROLE_ATTEMPTS
    assert r['reading']['deferred_count']==26 and r['reading']['deferred_list_truncated']
    assert len(r['reading']['deferred'])==20
    assert r['reading']['deferred'][-1]['reason']=='ROLE_READ_ATTEMPT_LIMIT'


def test_per_role_file_limit_leaves_other_roles_available(tmp_path):
    c=context(tmp_path,[(f'build/{i}.json',b'TEST_ONLY record') for i in range(4)]+[
        (f'runtime/{i}.txt',b'TEST_ONLY record') for i in range(4)])
    r=prepare(c,[]);records=r['reading']['records']
    assert len([x for x in records if x['role_hint']=='BUILD_CONTEXT'])==2
    assert len([x for x in records if x['role_hint']=='RUNTIME_CONTEXT'])==3
    assert all(x['reason']=='ROLE_FILE_LIMIT' for x in r['reading']['deferred'])


def test_changed_scoped_source_fails_closed(tmp_path):
    c=context(tmp_path,[('build/receipt.json',b'TEST_ONLY original')])
    (c.root/'build/receipt.json').write_bytes(b'TEST_ONLY changed')
    with pytest.raises(IntegrityError):prepare(c,[])


@pytest.mark.parametrize('provider_id',['openai_api','codex_cli'])
def test_initial_supporting_text_is_citable_without_redundant_model_read(tmp_path,monkeypatch,provider_id):
    from tests.test_ai_provider_core import SimulatedProvider,decision
    from tests.test_general_triage import public_record
    from tests.test_condition_plan import conditions,PUBLIC
    from cvevidence_core.ai import investigate
    from cvevidence_core.queries import collect_evidence
    from cvevidence_core.verifier import verify
    from cvevidence_core.assessment import assess
    c=context(tmp_path,[('build/receipt.json',b'TEST_ONLY unsigned build declaration'),
        ('runtime/input.txt',b'4 17\n'),('source/main.c',b'TEST_ONLY uninspected implementation')])
    public={'sources':[{**r,'text_sha256':hashlib.sha256(r['text'].encode()).hexdigest()} for r in PUBLIC]}
    monkeypatch.setattr('cvevidence_core.public_sources.collect',lambda *a,**kw:deepcopy(public))
    def finish(kw):
        packet=kw['packet'];pool={r['excerpt_id']:r for r in packet['initial_product_excerpts']}
        reads={r['path']:r for r in packet['initial_reading']['records']}
        assert 'source/main.c' not in reads and reads['runtime/input.txt']['complete_text']
        x=pool[reads['runtime/input.txt']['excerpt_id']];rows=conditions()
        for row in rows:row.update(citations=[x['excerpt_id']],evidence_quotes=[{'excerpt_id':x['excerpt_id'],'quote':'4 17'}],
            explanation='TEST_ONLY 已讀輸入但尚未核對成品與實作；條件保持未完成。')
        return decision('REPORT',conditions=rows,citations=[x['excerpt_id']],finding='PC1 未完成。PC2 未完成。PC3 只見正常輸入，未綁定成品。')
    provider=SimulatedProvider([decision('PLAN',conditions=conditions()),finish]);provider.provider_id=provider_id
    v=verify(c,collect_evidence(c,'CVE-2099-0001'));a=assess(c,v);before=deepcopy(a)
    r=investigate(c,v,a,mode='LIVE',provider=provider,max_calls=2,analysis_depth='pc',public_record=public_record('CVE-2099-0001'))
    assert r['status']=='COMPLETED' and r['investigation_outcome']['status']=='INCOMPLETE' and a==before
    assert [t['action'] for t in r['tasks']]==['PLAN','REPORT']
    assert r['initial_reading']==provider.seen[0]['packet']['initial_reading']
    assert r['record_hash']==digest({k:v for k,v in r.items() if k!='record_hash'})
    assert r['condition_dossier']['conditions'][-1]['focus'][0]['text']=='4 17'
