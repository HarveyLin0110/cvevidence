import pytest
from cvevidence.runner import Runner
from cvevidence.storage import RunStore
from cvevidence.reports import report, compare, excerpt
from tests.test_runner_v2 import package

def test_replacement_preserves_parent_and_resolves_missing(tmp_path):
    store=RunStore(tmp_path); runner=Runner(store)
    parent=runner.start(package(missing=True),"TEST","CVE-2014-0160")
    before=(tmp_path/"runs"/(parent.run_id+".json")).read_bytes()
    child=runner.supplement(parent.run_id,package())
    assert child.parent_run_id==parent.run_id
    assert compare(parent,child)["resolved_missing"]==["test.txt"]
    assert child.assessment is None
    assert (tmp_path/"runs"/(parent.run_id+".json")).read_bytes()==before

@pytest.mark.parametrize("payload",[package(build="OTHER"),package(content=b"changed"),package(missing=True)])
def test_replacement_cannot_change_build_or_existing_bytes(tmp_path,payload):
    runner=Runner(RunStore(tmp_path))
    parent=runner.start(package(),"TEST","CVE-2014-0160")
    child=runner.supplement(parent.run_id,payload)
    assert child.error.code=="INTEGRITY_ERROR"
    assert child.assessment is None and not child.evidence
    assert compare(parent,child)["status"]=="REJECTED"

def test_note_never_changes_facts(tmp_path):
    store=RunStore(tmp_path); runner=Runner(store)
    parent=runner.start(package(missing=True),"TEST","CVE-2014-0160")
    child=runner.supplement(parent.run_id,note="Supplier says safe — TEST ONLY")
    assert child.missing==parent.missing and child.assessment is None
    assert child.supplement.review_required
    assert "unverified" in report(child).lower()

def test_excerpt_scope_and_report(tmp_path):
    store=RunStore(tmp_path); runner=Runner(store)
    parent=runner.start(package(),"TEST","CVE-2014-0160")
    assert excerpt(store,parent.run_id,"E-001")=="TEST ONLY"
    with pytest.raises(ValueError): excerpt(store,parent.run_id,"OTHER")
    assert "NOT_ASSESSED" in report(parent)
