from pathlib import Path
from uuid import uuid4
import pytest
from streamlit.testing.v1 import AppTest
from cvevidence.storage import RunStore
from cvevidence.runner import Runner
from tests.test_runner_v2 import package

def test_bad_history_does_not_hide_valid_runs(tmp_path,monkeypatch):
    store=RunStore(tmp_path/"store")
    good=Runner(store).start(package(),"TEST","CVE-2014-0160")
    broken=store.root/"runs"/(str(uuid4())+".json")
    broken.write_text('{"incomplete":')
    original=broken.read_bytes()
    valid,rejected=store.inspect_history()
    assert [r.run_id for r in valid]==[good.run_id] and len(rejected)==1
    with pytest.raises(ValueError): store.read(broken.stem)
    monkeypatch.setenv("CVEVIDENCE_STORE",str(store.root))
    app=AppTest.from_file(str(Path(__file__).resolve().parents[1]/"runner_app.py")).run()
    assert not app.exception and app.sidebar.warning
    assert broken.read_bytes()==original

def test_stale_selection_is_recoverable(tmp_path,monkeypatch):
    monkeypatch.setenv("CVEVIDENCE_STORE",str(tmp_path))
    app=AppTest.from_file(str(Path(__file__).resolve().parents[1]/"runner_app.py")).run()
    app.session_state["selected_run"]=str(uuid4())
    app.run()
    assert not app.exception and app.error

def test_runtime_guard_fails_closed(monkeypatch):
    from cvevidence import runtime_guard
    monkeypatch.setattr(runtime_guard,"fingerprint",lambda:"changed")
    assert not runtime_guard.current()
