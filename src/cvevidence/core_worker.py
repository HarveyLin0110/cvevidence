"""Fixed, file-backed bridge to Horace. No submitted module, shell or URL."""
import json
import sys
import tarfile
import zipfile
import tempfile
import shutil
from pathlib import Path
from cvevidence_core.integrity import ingest_package, safe_extract, file_hash, IntegrityError, scan
from cvevidence_core import sources
from cvevidence_core.catalog import discover_candidates
from cvevidence_core.supplements import validate_supplement
MAX_ARCHIVE = 512 * 1024 * 1024

def checked_archive(path, expected=None):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_ARCHIVE:
        raise IntegrityError("Invalid archive reference")
    actual = file_hash(path)
    if expected and actual != expected:
        raise IntegrityError("Archive integrity mismatch")
    return path, actual

def execute(req):
    archive, actual = checked_archive(req["archive"], req.get("archive_sha256"))
    with tempfile.TemporaryDirectory(prefix="read-", dir=req["temporary_root"]) as temp:
        root = Path(temp)
        safe_extract(archive, root / "package")
        context = ingest_package(root / "package", expected_manifest_hash=req.get("manifest_sha256"))
        if req.get("context_hash") and context.context_hash != req["context_hash"]:
            raise IntegrityError("Run context changed")
        op = req["operation"]
        if op == "collect":
            result = context.public()
            result["archive_sha256"] = actual
            result["candidates"] = discover_candidates(context, symptom=req.get("symptom", ""),
                requested_cves=req.get("cves") or None)
            return result
        if op == "list":
            return sources.list_sources(context, **req.get("arguments", {}))
        if op == "search":
            return sources.search_sources(context, **req["arguments"])
        if op == "excerpt":
            result = sources.read_excerpt(context, **req["arguments"])
            if not sources.verify_excerpt(context, result):
                raise IntegrityError("Excerpt failed verification")
            return result
        if op == "compare":
            return sources.compare_sources(context, **req["arguments"])
        if op != "delta":
            raise ValueError("Unsupported operation")
        supplement, _ = checked_archive(req["supplement"],req.get("supplement_sha256"))
        safe_extract(supplement, root / "supplement")
        expected=req.get("supplement_manifest_sha256")
        if expected and file_hash(root / "supplement/manifest.json")!=expected:
            raise IntegrityError("Supplement catalog manifest hash mismatch")
        validation = validate_supplement(context, root / "supplement")
        if not validation["can_merge"]:
            raise IntegrityError("Supplement belongs to a different build")
        merged = root / "merged"
        shutil.copytree(context.root, merged, symlinks=True)
        for row in validation["added_files"]:
            dest = merged / row["path"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            if row["kind"] == "symlink":
                dest.symlink_to(row["target"])
            else:
                shutil.copy2(root / "supplement" / row["path"], dest)
        manifest = dict(context.manifest)
        manifest.update(package_id=req["child_package_id"], files=scan(merged),
            parent_context_hash=context.context_hash, supplement_hash=validation["supplement_hash"])
        (merged / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2))
        ingest_package(merged)
        with tarfile.open(req["output"], "x:gz", dereference=False) as output:
            for entry in sorted(merged.iterdir()):
                output.add(entry, arcname=entry.name)
        return validation

def main():
    try:
        request = json.loads(sys.stdin.read(16000))
        result = execute(request)
        print(json.dumps(result))
        return 0
    except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile):
        # Untrusted content and paths are deliberately not printed.
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
