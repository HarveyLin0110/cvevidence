"""Frankie's persistence and bounded calls to the delivered Horace core."""
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from time import monotonic
from pathlib import Path
from uuid import uuid4
from datetime import datetime, timezone
from .contracts import RunEnvelope, InputPackage, SourceRecord, RunError, Supplement

MAX_ARCHIVE = 512 * 1024 * 1024

class CoreService:
    @staticmethod
    def remaining(deadline):
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired("core pipeline", 0)
        return remaining

    def __init__(self, store):
        self.store = store
        self.temp = store.root / "temporary"
        if self.temp.is_symlink():
            raise ValueError("Temporary root cannot be a symlink")
        self.temp.mkdir(exist_ok=True, mode=0o700)

    def retain(self, path, expected=None):
        path = Path(path)
        if path.is_symlink() or not path.is_file():
            raise ValueError("Regular archive file required")
        with path.open("rb") as handle:
            return self.retain_stream(handle, expected)

    def retain_stream(self, handle, expected=None):
        digest = hashlib.sha256()
        total = 0
        # Stream to a private file before hashing/publishing; never trust the caller's changing path.
        with tempfile.NamedTemporaryFile(dir=self.temp) as output:
            os.chmod(output.name, 0o600)
            while block := handle.read(1024 * 1024):
                total += len(block)
                if total > MAX_ARCHIVE:
                    raise ValueError("Archive exceeds 512 MiB")
                digest.update(block)
                output.write(block)
            output.flush()
            if total == 0 or (expected and expected != digest.hexdigest()):
                raise ValueError("Empty archive or catalog hash mismatch")
            sha = digest.hexdigest()
            target = self.store.root / "blobs" / sha
            try:
                os.link(output.name, target)
            except FileExistsError:
                if target.is_symlink() or self.file_digest(target) != sha:
                    raise ValueError("Stored archive integrity failure")
            return sha

    @staticmethod
    def file_digest(path):
        value = hashlib.sha256()
        with Path(path).open("rb") as handle:
            while block := handle.read(1024 * 1024):
                value.update(block)
        return value.hexdigest()

    def invoke(self, operation, sha, context_hash=None, timeout=120, **kwargs):
        if not re.fullmatch(r"[a-f0-9]{64}", sha):
            raise ValueError("Invalid archive digest")
        if not 0 < timeout <= 300:
            raise ValueError("Invalid deadline")
        request = dict(operation=operation, archive=str(self.store.root / "blobs" / sha),
            archive_sha256=sha, context_hash=context_hash, temporary_root=str(self.temp), **kwargs)
        source = str(Path(__file__).resolve().parents[1])
        # Do not forward model keys / OAuth secrets into intake processes.
        env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "LANG") if key in os.environ}
        env["PYTHONPATH"] = source
        if os.environ.get('CVEVIDENCE_PUBLIC_CVE_LOOKUP') == '0':
            env['CVEVIDENCE_PUBLIC_CVE_LOOKUP'] = '0'
        result = subprocess.run([sys.executable, "-m", "cvevidence.core_worker"],
            input=json.dumps(request), text=True, capture_output=True, env=env, timeout=timeout)
        if result.returncode == 2:
            raise ValueError("Core rejected archive, context or operation")
        if result.returncode:
            raise RuntimeError("Core worker failed")
        return json.loads(result.stdout)

    def collect_digest(self, sha, cve="", symptom="", timeout=120, manifest_sha256=None):
        if not re.fullmatch(r"(CVE-\d{4}-\d{4,})?", cve):
            raise ValueError("Invalid CVE")
        result = self.invoke("collect", sha, timeout=timeout,
            cves=[cve] if cve else [], symptom=symptom, manifest_sha256=manifest_sha256)
        records = [SourceRecord(**{k: row[k] for k in
            ("source_id", "path", "sha256", "size", "kind", "target") if k in row})
            for row in result["sources"]]
        return RunEnvelope(run_id=str(uuid4()), created_at=datetime.now(timezone.utc).isoformat(),
            cve_id=cve, status="COLLECTED",
            input_package=InputPackage(product_id=result["product_id"], release_id=result["release_id"],
                declared_build_id=result["build_id"], package_id=result["package_id"],
                format=result["format"], context_hash=result["context_hash"], archive_sha256=sha),
            sources=records, candidates=result["candidates"], missing=result["missing"],
            limitations=["Horace intake/source tools connected; source records are not verified engineering facts.",
                "Q1-Q5, assessment and runtime AI NOT_RUN.", "Hash consistency is not supplier provenance."])

    def failed(self, cve, exc, parent=None, supplement=None):
        timeout = isinstance(exc, subprocess.TimeoutExpired)
        return RunEnvelope(run_id=str(uuid4()), created_at=datetime.now(timezone.utc).isoformat(),
            cve_id=cve, status="TIMED_OUT" if timeout else "FAILED",
            parent_run_id=parent, supplement=supplement,
            error=RunError(code="TIMEOUT" if timeout else "INTEGRITY_ERROR" if isinstance(exc, ValueError)
                else "SYSTEM_ERROR", message="Core operation failed; no partial analysis published."))

    def start(self, path=None, cve="", symptom="", stream=None, archive_sha256=None,
              manifest_sha256=None, timeout=120):
        if not re.fullmatch(r"(CVE-\d{4}-\d{4,})?", cve):
            raise ValueError("Invalid CVE")
        if not 0 < timeout <= 300:
            raise ValueError("Invalid deadline")
        deadline = monotonic() + timeout
        try:
            sha = self.retain_stream(stream, archive_sha256) if stream is not None else self.retain(path, archive_sha256)
            run = self.collect_digest(sha, cve, symptom, self.remaining(deadline), manifest_sha256)
            if symptom.strip():
                run.limitations.append("User symptom (unverified): " + symptom[:4000])
        except (ValueError, OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            run = self.failed(cve, exc)
        self.store.save(run)
        return run

    def tool(self, run_id, operation, **arguments):
        run = self.store.read(run_id)
        if run.error or not run.input_package or not run.input_package.context_hash:
            raise ValueError("A real collected run is required")
        if operation not in ("list", "search", "excerpt", "compare"):
            raise ValueError("Read-only source operation required")
        try:
            return self.invoke(operation, run.input_package.archive_sha256,
                run.input_package.context_hash, arguments=arguments)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Source operation timed out") from exc

    def analyze_offline(self, parent_id, *, cve_id=None, symptom="", timeout=120):
        from .engineering import validate_payload
        from .analysis_context import read_analysis_context
        parent = self.store.read(parent_id)
        package = parent.input_package
        cve = parent.cve_id if cve_id is None else cve_id
        if not isinstance(cve, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            raise ValueError("Select one CVE before analysis")
        if parent.cve_id and cve != parent.cve_id:
            raise ValueError("CVE differs from parent; create a separate request")
        if parent.status != "COLLECTED" or parent.error or not package or not package.context_hash:
            raise ValueError("A real collected snapshot is required")
        if not 0 < timeout <= 300 or not isinstance(symptom, str) or len(symptom) > 4000:
            raise ValueError("Invalid deadline or symptom")
        deadline = monotonic() + timeout
        try:
            history = read_analysis_context(self.store, parent_id, cve_id=cve,
                check_budget=lambda: self.remaining(deadline))
            payload = self.invoke("analyze_offline", package.archive_sha256, package.context_hash,
                timeout=self.remaining(deadline), cve_id=cve,
                symptom=symptom if symptom.strip() else history["symptom"],
                statements=history["statements"])
            engineering, ai = validate_payload(payload, package, cve)
            digest = self.store.put_blob(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode())
            run = RunEnvelope(run_id=str(uuid4()), parent_run_id=parent_id,
                created_at=datetime.now(timezone.utc).isoformat(), cve_id=cve, status="COMPLETED",
                input_package=package.model_copy(deep=True), sources=parent.sources,
                engineering_status=engineering, ai_status=ai, engineering_payload_sha256=digest,
                limitations=["Core queries, verification and assessment executed in one worker; saved JSON is not a Verifier certificate.",
                    "OFFLINE: no model API call. Engineering result requires human review; provenance remains unverified."])
        except (ValueError, KeyError, TypeError, OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            run = self.failed(cve, exc, parent_id)
        self.store.save(run)
        return run

    def supplement(self, parent_id, path=None, stream=None, note="", timeout=120,
                   archive_sha256=None, manifest_sha256=None):
        if not 0 < timeout <= 300:
            raise ValueError("Invalid deadline")
        deadline = monotonic() + timeout
        parent = self.store.read(parent_id)
        if parent.error or not parent.input_package or not parent.input_package.context_hash:
            raise ValueError("Cannot supplement failed or legacy intake")
        has_delta = path is not None or stream is not None
        metadata = Supplement(parent_run_id=parent_id, kind="DELTA" if has_delta else "NOTE", note=note)
        if not has_delta and not note.strip():
            raise ValueError("Provide a delta or statement")
        try:
            if has_delta:
                sha = self.retain_stream(stream,archive_sha256) if stream is not None else self.retain(path,archive_sha256)
                with tempfile.TemporaryDirectory(dir=self.temp) as temp:
                    output = Path(temp) / "merged.tar.gz"
                    self.invoke("delta", parent.input_package.archive_sha256,
                        parent.input_package.context_hash, timeout=self.remaining(deadline),
                        supplement=str(self.store.root / "blobs" / sha), output=str(output),
                        supplement_sha256=sha, supplement_manifest_sha256=manifest_sha256,
                        child_package_id="supplemented-" + uuid4().hex)
                    merged_sha = self.retain(output)
                    child = self.collect_digest(merged_sha, parent.cve_id, timeout=self.remaining(deadline))
            else:
                # Recheck the actual saved context before accepting even a textual supplement.
                self.invoke("list", parent.input_package.archive_sha256, parent.input_package.context_hash,
                    timeout=self.remaining(deadline), arguments={"limit": 1})
                child = parent.model_copy(deep=True)
                child.run_id = str(uuid4())
                child.created_at = datetime.now(timezone.utc).isoformat()
                child.assessment = None
                child.advice = None
                child.status = "COLLECTED"
                child.engineering_payload_sha256 = None
                child.engineering_status = "NOT_RUN"
                child.ai_status = "NOT_RUN"
            if note.strip():
                from cvevidence_core.supplements import interpret_statement
                interpret_statement(note, parent.input_package.context_hash)
                child.limitations.append("User statement remains unverified; does not resolve missing facts.")
            child.parent_run_id = parent_id
            child.supplement = metadata
        except (ValueError, OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            child = self.failed(parent.cve_id, exc, parent_id, metadata)
        self.store.save(child)
        return child

def catalog_entries(root):
    """Catalog is trusted repo/operator configuration, never an uploaded locator."""
    root = Path(root).resolve()
    entries = []
    index=root / "data/catalogs/index.json"
    selected=set(json.loads(index.read_text()).get("selected_datasets",[])) if index.exists() else set()
    for path in sorted((root / "data/catalogs").glob("*.json")):
        catalog = json.loads(path.read_text())
        for item in catalog.get("packages", []):
            archive = root / item["archive"].get("repo_path",item["archive"]["relative_path"])
            resolved = archive.resolve()
            if not any(resolved.is_relative_to(allowed) for allowed in (root/"var/artifacts",root/"demo-inputs")):
                continue
            entries.append(dict(item, dataset=catalog["dataset_version"],
                local_path=str(resolved), available=resolved.is_file(), selected=catalog["dataset_version"] in selected))
    return sorted(entries,key=lambda e:(not e["selected"],e["package_id"],e["dataset"]))
