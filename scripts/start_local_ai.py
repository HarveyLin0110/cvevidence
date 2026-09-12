"""Start only this checkout's local 8506 workspace with operator AI settings."""
import os
from pathlib import Path
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
if os.name != "posix":
    raise SystemExit("Run this script in WSL/Linux using the project venv.")
path = ROOT / ".env.local"
if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
    raise SystemExit("A private .env.local (chmod 600) is required.")
os.environ["CVEVIDENCE_AI_ENV_FILE"] = str(path)
os.environ["CVEVIDENCE_AI_ENABLED"] = "1"
from cvevidence.ai_service import operator_config
if not operator_config()[1]["configured"]:
    raise SystemExit("Local AI settings are incomplete; no service was changed.")
subprocess.run([sys.executable, str(ROOT / "scripts/workspace_service.py"), "restart", "--port", "8506"], check=True)
