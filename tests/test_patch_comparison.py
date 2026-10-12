"""TEST_ONLY literal comparisons; these tests do not certify CVE semantics."""
from copy import deepcopy
import hashlib
import pytest
from tests.test_turnkey import context
from cvevidence_core.patch_comparison import compare,hunks,check_exclusions,MAX_SOURCE_BYTES
from cvevidence_core.sources import read_excerpt
from cvevidence_core.integrity import IntegrityError

PATCH='''diff --git a/src/check.c b/src/check.c
--- a/src/check.c
+++ b/src/check.c
@@ -1,3 +1,3 @@
 TEST_ONLY header
-old marker
+new marker
 context
@@ -5,3 +5,3 @@
 TEST_ONLY loop
-while (unknown) {}
+for (i = 0; i < limit; ++i) {}
 TEST_ONLY exit
'''
OLD='TEST_ONLY header\nold marker\ncontext\n\nTEST_ONLY loop\nwhile (unknown) {}\nTEST_ONLY exit\n'
NEW=OLD.replace('old marker','new marker').replace('while (unknown) {}','for (i = 0; i < limit; ++i) {}')


def bundle(text=PATCH,**kw):
    return {'sources':[{'source_id':'P-test','text':text,'text_sha256':hashlib.sha256(text.encode()).hexdigest(),**kw}]}


@pytest.mark.parametrize('body,status',[ (OLD,'BEFORE_TEXT_MATCH'),(NEW,'AFTER_TEXT_MATCH'),
    (NEW.replace('new marker','old marker'),'PARTIAL_OR_DIFFERENT'),
    ('unrelated TEST_ONLY file','PARTIAL_OR_DIFFERENT'),(NEW+NEW,'PARTIAL_OR_DIFFERENT'),
    (NEW.replace('for (','for  ('),'PARTIAL_OR_DIFFERENT')])
def test_exact_whole_hunks_distinguish_before_after_partial_and_duplicate(tmp_path,body,status):
    c=context(tmp_path,[('vendor/src/check.c',body.encode())]);sid=c.by_path('vendor/src/check.c')[1]['source_id']
    r=compare(c,sid,bundle())[0]
    assert r['status']==status and len(r['hunks'])==2
    assert r['file_sha256']==c.sources[sid]['sha256'] and r['context_hash']==c.context_hash
    assert not r['semantic_verification'] and not r['same_build_verified'] and not r['all_product_copies_verified']
    for h in r['hunks']:
        for side in ('before','after'):
            for hit in h[side+'_locations']:
                assert 1<=hit['start_line']<=hit['end_line']<=len(body.splitlines())


@pytest.mark.parametrize('bad',[PATCH[:-20],PATCH.replace('-1,3','-1,2000'),PATCH.replace('+++ b/','+++ c/'),
    PATCH.replace('src/check.c','../check.c'),PATCH.replace('@@ -5,3','@@@ -5,3'),
    PATCH+'\nGIT binary patch\n',PATCH.replace('-1,3','-1,2'),PATCH+'+unaccounted\n',
    PATCH+'diff --git a/other.c b/other.c\n'])
def test_malformed_patch_never_accepts_valid_prefix(bad):
    with pytest.raises(ValueError):hunks(bad)


def test_public_truncation_missing_patch_and_unrelated_names_do_not_imply_safety(tmp_path):
    c=context(tmp_path,[('check.c',NEW.encode()),('another.c',NEW.encode())])
    assert not compare(c,c.by_path('check.c')[1]['source_id'],bundle(truncated=True))
    assert not compare(c,c.by_path('check.c')[1]['source_id'],bundle('TEST_ONLY no patch'))
    assert not compare(c,c.by_path('another.c')[1]['source_id'],bundle())


def test_byte_cap_and_input_integrity_are_not_downgraded_to_safe(tmp_path):
    c=context(tmp_path,[('check.c',b'x'*(MAX_SOURCE_BYTES+1))]);sid=c.by_path('check.c')[1]['source_id']
    assert compare(c,sid,bundle())[0]['status']=='SOURCE_BYTE_LIMIT'
    (c.root/'check.c').write_bytes(NEW.encode())
    with pytest.raises(IntegrityError):compare(c,sid,bundle())


def test_public_snapshot_hash_is_rechecked(tmp_path):
    c=context(tmp_path,[('check.c',NEW.encode())]);b=bundle();b['sources'][0]['text']+='tampered'
    with pytest.raises(IntegrityError):compare(c,c.by_path('check.c')[1]['source_id'],b)


def test_exclusion_guard_does_not_treat_normal_input_or_unsupported_claim_as_exclusion(tmp_path):
    c=context(tmp_path,[('check.c',NEW.encode()),('runtime/input.txt',b'4 17\n')])
    sid=c.by_path('check.c')[1]['source_id'];x=read_excerpt(c,sid,1,7)
    runtime=read_excerpt(c,c.by_path('runtime/input.txt')[1]['source_id'])
    pool={e['excerpt_id']:e for e in (x,runtime)};comparisons=compare(c,sid,bundle())
    row={'condition_id':'C2','layer':'PC2','state':'OBSERVED_EXCLUSION','citations':[x['excerpt_id']]}
    assert check_exclusions([row],pool,comparisons)[0]['scope']=='MATCHED_SOURCE_TEXT_ONLY'
    for change in ({'layer':'PC3'},{'layer':'PC1'},{'citations':[runtime['excerpt_id']]}):
        with pytest.raises(ValueError,match='排除依據'):check_exclusions([{**row,**change}],pool,comparisons)
    with pytest.raises(ValueError):check_exclusions([row],pool,[])
    before=deepcopy(row)
    with pytest.raises(ValueError):check_exclusions([row],pool,[{**comparisons[0],'status':'BEFORE_TEXT_MATCH'}])
    assert row==before
    # Partial observations remain saveable; the guard does not invent a state.
    assert check_exclusions([{**row,'state':'NOT_REVIEWED'}],pool,[])==[]


@pytest.mark.parametrize('body,expected',[(NEW,'COMPLETED'),(OLD,'TOOL_ERROR')])
def test_live_provider_path_compares_reads_and_gates_report_without_changing_engineering(tmp_path,monkeypatch,body,expected):
    from tests.test_ai_provider_core import SimulatedProvider,decision
    from tests.test_condition_plan import conditions,PUBLIC
    from tests.test_general_triage import public_record
    from cvevidence_core.ai import investigate
    from cvevidence_core.queries import collect_evidence
    from cvevidence_core.verifier import verify
    from cvevidence_core.assessment import assess
    c=context(tmp_path,[('check.c',body.encode())]);sid=c.by_path('check.c')[1]['source_id']
    b=bundle(PUBLIC[0]['text']+'\n'+PATCH)
    monkeypatch.setattr('cvevidence_core.public_sources.collect',lambda *a,**kw:b)
    def finish(kw):
        read=kw['history'][-1]['result'];x=read['excerpt_id']
        assert read['patch_comparisons'][0]['status']==('AFTER_TEXT_MATCH' if body==NEW else 'BEFORE_TEXT_MATCH')
        rows=conditions();rows[1].update(state='OBSERVED_EXCLUSION',citations=[x],
            evidence_quotes=[{'excerpt_id':x,'quote':body.strip()}],explanation='TEST_ONLY 原碼逐行比對，成品仍未綁定')
        rows[0].update(state='OBSERVED_SUPPORT',citations=[x],
            evidence_quotes=[{'excerpt_id':x,'quote':'TEST_ONLY header'}],explanation='TEST_ONLY 合成元件觀察，非實際建置驗證')
        rows[2]['state']='USER_MATERIAL_MISSING'
        return decision('REPORT',conditions=rows,citations=[x],finding='PC1 未完成；PC2 TEST_ONLY 原碼比較；PC3 未確認。')
    p=SimulatedProvider([decision('PLAN',conditions=conditions()),decision('READ',source_ids=[sid],end_line=20),finish])
    v=verify(c,collect_evidence(c,'CVE-2099-0001'));a=assess(c,v);before=deepcopy(a)
    r=investigate(c,v,a,mode='LIVE',provider=p,max_calls=3,analysis_depth='pc',public_record=public_record('CVE-2099-0001'))
    assert r['tasks'][-1]['status']==expected and a==before
    assert r['tasks'][1]['result']['text']==body.strip() and 'patch_comparisons' not in r['tasks'][1]['result']
    if body==NEW:
        assert r['investigation_outcome']['status']=='EXCLUSION_OBSERVED'
        assert r['condition_plan']['conditions'][2]['state']=='USER_MATERIAL_MISSING'
    else:
        assert r['investigation_outcome']['status']=='INCOMPLETE'
        assert all(row['state']=='NOT_REVIEWED' for row in r['condition_plan']['conditions'])


@pytest.mark.parametrize('state',['USER_MATERIAL_MISSING','NOT_REVIEWED','CAPABILITY_GAP','CONFLICT'])
@pytest.mark.parametrize('layer',['PC1','PC2'])
def test_even_a_complete_patch_cannot_bypass_unresolved_product_identity_or_binding(state,layer):
    patch={'condition_id':'C2','layer':'PC2','necessity':'REQUIRED','state':'OBSERVED_EXCLUSION','citations':['X-source']}
    identity={'condition_id':'C1','layer':layer,'necessity':'REQUIRED','state':state,'citations':[]}
    comparisons=[{'source_id':'S-source','status':'AFTER_TEXT_MATCH','comparison_id':'M-test'}]
    with pytest.raises(ValueError,match='其他必要產品'):
        check_exclusions([identity,patch],{'X-source':{'source_id':'S-source'}},comparisons)
    # Unknown optional routes/PC3 do not independently invalidate a bound patch observation.
    identity['necessity']='ALTERNATIVE_PATH'
    assert check_exclusions([identity,patch],{'X-source':{'source_id':'S-source'}},comparisons)
