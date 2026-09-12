"""Run with PYTHONPATH=src python scripts/export_contracts.py."""
import json
from pathlib import Path
from cvevidence.contracts import RunEnvelope
target = Path(__file__).resolve().parents[1] / "contracts" / "schemas" / "run-envelope.json"
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(json.dumps(RunEnvelope.model_json_schema(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
