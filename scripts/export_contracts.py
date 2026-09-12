"""Run with PYTHONPATH=src python scripts/export_contracts.py."""
import json
from pathlib import Path
from cvevidence.contracts import RunEnvelope
target = Path(__file__).resolve().parents[1] / "contracts" / "schemas" / "run-envelope.json"
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(json.dumps(RunEnvelope.model_json_schema(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
from cvevidence.request_contracts import RequestResult
request_target = target.with_name("request-result.json")
request_target.write_text(json.dumps(RequestResult.model_json_schema(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
from cvevidence.ai_store import AIRequest, AIRequestV2, AIOutcome
for name, model in (("ai-request.json", AIRequest), ("ai-request-v2.json", AIRequestV2), ("ai-outcome.json", AIOutcome)):
    target.with_name(name).write_text(json.dumps(model.model_json_schema(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
