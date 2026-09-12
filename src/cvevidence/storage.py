"""Private local run store; terminal run envelopes are immutable."""
import hashlib
import os
from pathlib import Path
from uuid import UUID, uuid4
from .contracts import RunEnvelope

class RunStore:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        for name in ("runs", "blobs"):
            path = self.root / name
            if path.is_symlink():
                raise ValueError("store directory cannot be a symlink")
            path.mkdir(exist_ok=True, mode=0o700)

    def _run_path(self, run_id):
        if str(UUID(run_id)) != run_id:
            raise ValueError("canonical run UUID required")
        return self.root / "runs" / (run_id + ".json")

    def _atomic_new(self, target, data):
        temporary = target.parent / (".pending-" + uuid4().hex)
        try:
            with temporary.open("xb") as handle:
                os.chmod(temporary, 0o600)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            # Link is atomic and refuses to replace an existing result.
            os.link(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)

    def put_blob(self, data):
        digest = hashlib.sha256(data).hexdigest()
        target = self.root / "blobs" / digest
        try:
            self._atomic_new(target, data)
        except FileExistsError:
            if target.is_symlink() or hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                raise ValueError("stored blob integrity error")
        return digest

    def read_blob(self, digest):
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("invalid blob digest")
        path = self.root / "blobs" / digest
        if path.is_symlink():
            raise ValueError("blob cannot be a symlink")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("stored blob integrity error")
        return data

    def save(self, run):
        # Revalidate even if an adapter bypassed model construction.
        run = RunEnvelope.model_validate_json(run.model_dump_json())
        self._atomic_new(self._run_path(run.run_id), run.model_dump_json(indent=2).encode())

    def read(self, run_id):
        path = self._run_path(run_id)
        if path.is_symlink():
            raise ValueError("run cannot be a symlink")
        run = RunEnvelope.model_validate_json(path.read_bytes())
        if run.run_id != run_id:
            raise ValueError("run identity mismatch")
        return run

    def list_runs(self):
        return sorted((self.read(p.stem) for p in (self.root/"runs").glob("*.json")),
                      key=lambda r: r.created_at, reverse=True)
