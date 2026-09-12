import json
from cvevidence.core_service import catalog_entries
from cvevidence.runner import Runner
from cvevidence.storage import RunStore
from tests.test_real_bridge import archive

def test_git_catalog_path_and_selection(tmp_path):
    folder=tmp_path/"data/catalogs"
    folder.mkdir(parents=True)
    package=tmp_path/"demo-inputs/a.tar.gz"
    package.parent.mkdir()
    package.write_bytes(b"test")
    (folder/"index.json").write_text(json.dumps({"selected_datasets":["official"]}))
    item={"package_id":"a","archive":{"repo_path":"demo-inputs/a.tar.gz","relative_path":"var/artifacts/missing"}}
    (folder/"official.json").write_text(json.dumps({"dataset_version":"official","packages":[item]}))
    entry=catalog_entries(tmp_path)[0]
    assert entry["available"] and entry["selected"] and entry["local_path"]==str(package)
    item["archive"]["repo_path"]="../outside.tar.gz"
    (folder/"official.json").write_text(json.dumps({"dataset_version":"official","packages":[item]}))
    assert catalog_entries(tmp_path)==[]

def test_catalog_supplement_hashes_checked(tmp_path):
    runner=Runner(RunStore(tmp_path/"store"))
    parent=runner.start_file(archive(tmp_path))
    delta=archive(tmp_path,"delta",delta=True)
    for fields in ({"archive_sha256":"0"*64},{"manifest_sha256":"0"*64}):
        result=runner.supplement_file(parent.run_id,path=delta,**fields)
        assert result.error and not result.sources
        assert result.parent_run_id==parent.run_id
