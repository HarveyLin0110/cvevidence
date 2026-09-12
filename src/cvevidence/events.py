"""Local immutable receipts for manual source-tool calls; no source text in receipts."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4
from pydantic import Field
from .contracts import Model

class ToolStart(Model):
    event_id: str
    run_id: str
    created_at: str
    operation: Literal["list", "search", "excerpt", "compare"]
    context_hash: str | None = None
    arguments_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    actor: Literal["MANUAL_TOOL_CALL"] = "MANUAL_TOOL_CALL"

class ToolEnd(Model):
    event_id: str
    run_id: str
    created_at: str
    status: Literal["SUCCESS", "FAILED"]
    result_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    error_category: Literal["INVALID_INPUT_OR_INTEGRITY", "STORAGE", "CORE_FAILURE"] | None = None

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,allow_nan=False).encode()).hexdigest()

class EventStore:
    def __init__(self, store):
        self.store=store
        self.root=store.root/"events"
        if self.root.is_symlink(): raise ValueError("Event root cannot be a symlink")
        self.root.mkdir(exist_ok=True,mode=0o700)

    def folder(self, run_id):
        self.store._run_path(run_id)
        folder=self.root/run_id
        if folder.is_symlink(): raise ValueError("Event folder cannot be a symlink")
        folder.mkdir(exist_ok=True,mode=0o700)
        return folder

    def begin(self, run, operation, arguments):
        start=ToolStart(event_id=str(uuid4()),run_id=run.run_id,
            created_at=datetime.now(timezone.utc).isoformat(),operation=operation,
            context_hash=run.input_package.context_hash if run.input_package else None,
            arguments_sha256=digest(arguments))
        self.store._atomic_new(self.folder(run.run_id)/(start.event_id+".start.json"),
            start.model_dump_json().encode())
        return start

    def finish(self, start, result=None, error=None):
        category=None
        if error is not None:
            category=("INVALID_INPUT_OR_INTEGRITY" if isinstance(error,ValueError) else
                      "STORAGE" if isinstance(error,OSError) else "CORE_FAILURE")
        end=ToolEnd(event_id=start.event_id,run_id=start.run_id,
            created_at=datetime.now(timezone.utc).isoformat(),
            status="FAILED" if error is not None else "SUCCESS",
            result_sha256=None if error is not None else digest(result),error_category=category)
        self.store._atomic_new(self.folder(start.run_id)/(start.event_id+".end.json"),
            end.model_dump_json().encode())

    def read(self, run_id):
        run=self.store.read(run_id)
        context=run.input_package.context_hash if run.input_package else None
        records,invalid=[],[]
        for path in self.folder(run_id).glob("*.start.json"):
            try:
                if path.is_symlink(): raise ValueError("Symlink receipt")
                start=ToolStart.model_validate_json(path.read_bytes())
                if (str(UUID(start.event_id))!=start.event_id or path.name!=start.event_id+".start.json"
                        or start.run_id!=run_id or start.context_hash!=context):
                    raise ValueError("Receipt scope mismatch")
                end_path=path.with_name(start.event_id+".end.json")
                value=start.model_dump()
                if end_path.exists():
                    if end_path.is_symlink(): raise ValueError("Symlink receipt")
                    end=ToolEnd.model_validate_json(end_path.read_bytes())
                    if end.event_id!=start.event_id or end.run_id!=run_id:
                        raise ValueError("Terminal receipt scope mismatch")
                    if ((end.status=="SUCCESS") != (end.result_sha256 is not None)
                            or (end.status=="FAILED") != (end.error_category is not None)):
                        raise ValueError("Inconsistent terminal receipt")
                    value.update(status=end.status,finished_at=end.created_at,
                        result_sha256=end.result_sha256,error_category=end.error_category)
                else:
                    value.update(status="NO_TERMINAL_RECEIPT",finished_at=None,
                        result_sha256=None,error_category=None)
                records.append(value)
            except (ValueError,OSError):
                invalid.append(path.name)
        return {"run_id":run_id,"events":sorted(records,key=lambda e:e["created_at"]),"invalid_receipts":invalid}

def invoke_with_receipt(runner, run_id, operation, arguments):
    from .core_service import CoreService
    run=runner.store.read(run_id)
    events=EventStore(runner.store)
    start=events.begin(run,operation,arguments)
    try:
        result=CoreService(runner.store).tool(run_id,operation,**arguments)
    except (ValueError,OSError,RuntimeError) as exc:
        events.finish(start,error=exc)
        raise
    events.finish(start,result=result)
    return result
