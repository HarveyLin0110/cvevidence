"""Detect changed Python files before mixing cached models with new stored data."""
import hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def fingerprint():
    digest=hashlib.sha256()
    for path in [ROOT/"runner_app.py", *sorted((ROOT/"src").rglob("*.py"))]:
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()

LOADED=fingerprint()

def current():
    return LOADED==fingerprint()
