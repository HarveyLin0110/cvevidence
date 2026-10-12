"""TEST_ONLY unsigned statements; no authenticated build or CVE assertions."""
import json
from copy import deepcopy
import pytest
from cvevidence_core.partial_intake import create
from cvevidence_core.integrity import safe_extract,ingest_package,IntegrityError
from cvevidence_core.build_provenance import inspect


def setup_context(tmp_path,change=None):
    import hashlib
    h=lambda b:hashlib.sha256(b).hexdigest()
    data={'_type':'https://in-toto.io/Statement/v1','predicateType':'https://slsa.dev/provenance/v1',
          'subject':[{'name':'product.elf','digest':{'sha256':h(b'TEST_BINARY')}}],
          'predicate':{'buildDefinition':{'buildType':'https://example.com/test-only',
             'externalParameters':{},'resolvedDependencies':[{'name':'source.c','digest':{'sha256':h(b'TEST_SOURCE')}}]},
             'runDetails':{'builder':{'id':'https://example.com/UNTRUSTED'}}}}
    if change:change(data)
    create([('product.elf',b'TEST_BINARY'),('source.c',b'TEST_SOURCE'),('provenance.json',json.dumps(data).encode())],tmp_path/'p.tgz')
    safe_extract(tmp_path/'p.tgz',tmp_path/'p');return ingest_package(tmp_path/'p')


def test_digest_match_is_not_authenticated_same_build(tmp_path):
    ctx=setup_context(tmp_path);result=inspect(ctx);row=result['records'][0]
    assert row['status']=='DECLARED_DIGESTS_MATCH'
    assert not any(row[k] for k in ('signature_verified','builder_authenticated','same_build_verified'))
    assert all(r['state']=='MATCHES_DELIVERED_BYTES' for r in row['references'])
    assert row['references'][0]['matched_source_ids']==[ctx.by_path('product.elf')[1]['source_id']]
    from cvevidence_core.catalog import discover_candidates
    from cvevidence_core.investigation_intake import prepare
    assert discover_candidates(ctx)['build_provenance']==result
    assert prepare(ctx,[])['build_provenance']==result


def test_wrong_named_artifact_digest_is_visible_conflict(tmp_path):
    ctx=setup_context(tmp_path,lambda d:d['subject'][0]['digest'].update(sha256='a'*64))
    row=inspect(ctx)['records'][0]
    assert row['status']=='NAMED_SOURCE_CONFLICT'
    assert row['references'][0]['named_source_conflict']
    assert row['references'][0]['state']=='NOT_IN_SNAPSHOT'


def test_unsupported_digest_and_missing_dependency_are_not_matches(tmp_path):
    def change(d):d['predicate']['buildDefinition']['resolvedDependencies']=[{'uri':'git+https://example.com/repo','digest':{'gitCommit':'123'}}]
    row=inspect(setup_context(tmp_path,change))['records'][0]
    assert row['status']=='PARTIAL_DIGEST_COVERAGE'
    assert row['references'][1]['state']=='NO_SUPPORTED_DIGEST'


@pytest.mark.parametrize('change',[
    lambda d:d.update(predicate=[]),
    lambda d:d['predicate'].update(buildDefinition=[]),
    lambda d:d['subject'][0].update(digest={'sha256':'bad'}),
])
def test_malformed_claim_is_reported_without_crashing(tmp_path,change):
    assert inspect(setup_context(tmp_path,change))['records'][0]['status']=='MALFORMED_DECLARATION'


def test_mutated_matched_source_is_not_silently_accepted(tmp_path):
    ctx=setup_context(tmp_path);(ctx.root/'source.c').write_bytes(b'CHANGED')
    with pytest.raises(IntegrityError):inspect(ctx)


def test_envelope_and_reference_limit_are_explicit(tmp_path):
    def envelope(d):d.clear();d.update(payloadType='application/vnd.in-toto+json',payload='ignored',signatures=[])
    assert inspect(setup_context(tmp_path,envelope))['records'][0]['status']=='ENVELOPE_NOT_SUPPORTED'
    other=tmp_path/'other';other.mkdir()
    def too_many(d):d['subject']*=33
    assert inspect(setup_context(other,too_many))['records'][0]['status']=='REFERENCE_LIMIT'


def test_supplement_preserves_parent_and_checks_new_statement(tmp_path):
    from cvevidence.runner import Runner
    from cvevidence.storage import RunStore
    ctx=setup_context(tmp_path)
    create([('product.elf',b'TEST_BINARY'),('source.c',b'TEST_SOURCE')],tmp_path/'base.tgz')
    runner=Runner(RunStore(tmp_path/'runtime'));parent=runner.start_file(tmp_path/'base.tgz')
    before=runner.store._run_path(parent.run_id).read_bytes()
    child=runner.supplement_partial(parent.run_id,[('provenance.json',(ctx.root/'provenance.json').read_bytes())])
    assert not child.error and child.parent_run_id==parent.run_id
    assert child.candidates['build_provenance']['records'][0]['status']=='DECLARED_DIGESTS_MATCH'
    assert runner.store._run_path(parent.run_id).read_bytes()==before


def test_web_presents_hash_match_with_unverified_origin(tmp_path):
    from streamlit.testing.v1 import AppTest
    from tests.test_package_inventory import inventory_app
    from cvevidence.runner import Runner
    from cvevidence.storage import RunStore
    from cvevidence.workflow_navigation import PAGES
    setup_context(tmp_path);runner=Runner(RunStore(tmp_path/'runtime'));run=runner.start_file(tmp_path/'p.tgz')
    app=AppTest.from_function(inventory_app,default_timeout=20)
    app.session_state['test_store']=str(tmp_path/'runtime')
    app.session_state['selected_run']=run.run_id;app.session_state['step']=PAGES[1]
    app.run();assert not app.exception
    assert any('未認證來源' in e.label for e in app.expander)
    assert any('未驗簽' in c.value and '不能直接' in c.value for c in app.caption)
    assert any('SHA256 與交付檔案吻合' in str(d.value.to_dict()) and 'product.elf' in str(d.value.to_dict()) for d in app.dataframe)
