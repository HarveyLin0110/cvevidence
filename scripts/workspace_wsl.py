"""Run the local service with analysis storage on WSL's Linux filesystem."""
import hashlib
import json
import os
from pathlib import Path
import runpy


ROOT = Path(__file__).resolve().parents[1]
project_key = hashlib.sha256(str(ROOT).encode()).hexdigest()[:12]
data_home = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share")))
default_store = data_home / "cvevidence" / f"{ROOT.name}-{project_key}" / "runtime"
os.environ.setdefault("CVEVIDENCE_STORE", str(default_store))

if __name__ == "__main__":
    state = ROOT / "var/service"
    state.mkdir(parents=True, exist_ok=True)
    (state / "wsl-storage.json").write_text(
        json.dumps({"store": os.environ["CVEVIDENCE_STORE"]}, indent=2) + "\n"
    )
    runpy.run_path(str(ROOT / "scripts/workspace_service.py"), run_name="__main__")
