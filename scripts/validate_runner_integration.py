"""Explicit actual-artifact integration validation; never executed by the analyzer."""
import argparse
import json
from pathlib import Path
from cvevidence.runner import Runner
from cvevidence.storage import RunStore
from cvevidence.reports import compare, report

def validate(catalog_path, store_path):
    catalog_path=Path(catalog_path).resolve()
    root=catalog_path.parents[2]
    catalog=json.loads(catalog_path.read_text())
    entries={e["package_id"]:e for e in catalog["packages"]}
    runner=Runner(RunStore(store_path))
    runs={}
    for name,item in entries.items():
        if item["kind"]!="initial": continue
        run=runner.start_file(root/item["archive"].get("repo_path",item["archive"]["relative_path"]),
            archive_sha256=item["archive"]["sha256"],manifest_sha256=item["manifest_sha256"])
        assert run.error is None, run.error
        assert run.input_package.product_id==item["product_id"]
        assert len(run.sources)==item["file_count"]
        assert not run.evidence and run.assessment is None and run.ai_status=="NOT_RUN"
        runs[name]=run
    supplement=next(item for item in entries.values() if item["kind"]=="supplement")
    parent=runs[supplement["base_package_id"]]
    before=runner.store._run_path(parent.run_id).read_bytes()
    supplement_path=root/supplement["archive"].get("repo_path",supplement["archive"]["relative_path"])
    child=runner.supplement_file(parent.run_id,path=supplement_path,
        archive_sha256=supplement["archive"]["sha256"],manifest_sha256=supplement["manifest_sha256"])
    assert child.error is None, child.error
    diff=compare(parent,child)
    assert diff["added"] and not diff["removed"] and not diff["changed"]
    assert runner.store._run_path(parent.run_id).read_bytes()==before
    assert child.input_package.context_hash!=parent.input_package.context_hash
    assert child.parent_run_id==parent.run_id and child.assessment is None
    family=parent.input_package.format
    source_path={"cmake":"source/update_reader.c","rom":"source/device.c","curl":"install/download-update.sh"}[family]
    source=next(s for s in child.sources if s.path==source_path)
    original=runner.source_tool(child.run_id,"excerpt",source_id=source.source_id,start_line=1,end_line=60)
    assert original["text"] and original["context_hash"]==child.input_package.context_hash
    search=runner.source_tool(child.run_id,"search",term={"cmake":"inflate","rom":"SSL","curl":"socks"}[family],limit=3)
    assert search["matches"]
    listing=runner.source_tool(child.run_id,"list",contains=source_path,limit=100)
    assert listing["total"]>0
    comparison=runner.source_tool(child.run_id,"compare",left_id=source.source_id,right_id=source.source_id)
    assert comparison["identical_bytes"]
    invalid_parent=next(r for r in runs.values() if r.input_package.declared_build_id!=parent.input_package.declared_build_id)
    rejected=runner.supplement_file(invalid_parent.run_id,path=supplement_path)
    assert rejected.error and rejected.assessment is None and not rejected.sources
    text=report(child)
    assert "NOT_ASSESSED" in text and source.sha256 in text
    return {"dataset":catalog["dataset_version"],"initial_packages_passed":len(runs),
        "parent_run_id":parent.run_id,"child_run_id":child.run_id,
        "sources_before":len(parent.sources),"sources_after":len(child.sources),
        "added":len(diff["added"]),"wrong_build_rejected":True,
        "source_list_search_excerpt_compare":"PASS","report":"PASS",
        "engineering":"NOT_RUN","AI":"NOT_RUN",
        "archive_hashes":{name:item["archive"]["sha256"] for name,item in entries.items()}}

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("catalog")
    p.add_argument("--store",default="var/runtime")
    p.add_argument("--output",default="var/integration-summary.json")
    a=p.parse_args()
    result=validate(a.catalog,a.store)
    Path(a.output).write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
