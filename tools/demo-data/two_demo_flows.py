"""Package two presentation flows from today's fixed PC3 materials only."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source_root.resolve(), args.output_root.resolve()
    sys.path.insert(0, str(source / "src"))
    from cvevidence.core_worker import execute
    catalog = json.loads((source / "data/catalogs/fresh-pc3-runtime-v2.json").read_text())
    inputs = {r["package_id"]: r for r in catalog["packages"]}
    initial, delta = (inputs[k] for k in ("pc3_cmake_static", "supplement_pc3_cmake_runtime"))
    initial_path = source / initial["archive"]["repo_path"]
    delta_path = source / delta["archive"]["repo_path"]
    for path, entry in ((initial_path, initial), (delta_path, delta)):
        if sha(path) != entry["archive"]["sha256"]:
            raise ValueError("Today input archive differs from reviewed catalog")
    temporary_root = output / "var/validation"
    temporary_root.mkdir(parents=True, exist_ok=True)
    target = output / "demo-inputs/two-flows"
    target.mkdir(parents=True, exist_ok=False)
    complete = target / "01_complete/demo_1_complete.tar.gz"
    incomplete = target / "02_requires_evidence/demo_2_requires_evidence.tar.gz"
    complete.parent.mkdir()
    incomplete.parent.mkdir()
    with tempfile.TemporaryDirectory(prefix="two-flows-", dir=temporary_root) as tmp:
        execute(dict(operation="delta", archive=str(initial_path), archive_sha256=sha(initial_path),
                     supplement=str(delta_path), supplement_sha256=sha(delta_path),
                     temporary_root=tmp, output=str(complete), child_package_id="demo_cmake_complete_v2"))
    shutil.copyfile(initial_path, incomplete)
    entries = []
    for archive in (complete, incomplete):
        with tarfile.open(archive) as handle:
            raw = handle.extractfile("manifest.json").read()
            manifest = json.loads(raw)
        if manifest["primary_artifact"] != initial["primary_artifact"]:
            raise ValueError("Demo must retain the same today-built product")
        entry = {k: manifest[k] for k in ("package_id", "kind", "format", "product_id", "release_id", "build_id", "primary_artifact")}
        entry.update(manifest_sha256=hashlib.sha256(raw).hexdigest(), file_count=len(manifest["files"]),
                     base_package_id=None, archive=dict(filename=archive.name, repo_path=str(archive.relative_to(output)),
                                                       relative_path=str(archive.relative_to(output)),
                                                       sha256=sha(archive), size_bytes=archive.stat().st_size))
        entries.append(entry)
    result = {"schema_version": "1.0", "dataset_version": "fresh-demo-two-flows-v2",
              "created_at": datetime.now(timezone.utc).isoformat(), "packages": entries,
              "input_archive_hashes": [initial["archive"]["sha256"], delta["archive"]["sha256"]],
              "notes": ["Two presentation inputs assembled from today's fixed same-build PC3 materials.",
                        "The second presentation stops at the explanation of missing materials.",
                        "No expected verdict is supplied to the analysis engine."]}
    (target / "catalog.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    (output / "data/catalogs/fresh-demo-two-flows-v2.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    (target / "SHA256SUMS").write_text("".join(sha(p) + "  " + str(p.relative_to(target)) + "\n" for p in (complete, incomplete)))
    print(json.dumps({"created": str(target), "files": [e["archive"] for e in entries]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
