"""Content identities for the trusted implementation and model instructions."""
import hashlib
import json
from pathlib import Path


def execution_versions():
    from cvevidence_core.ai import SYSTEM, PC_REVIEW_INSTRUCTIONS, TOOL
    from cvevidence_core import providers

    packages = (Path(__file__).resolve().parent, Path(providers.__file__).resolve().parent)
    digest = hashlib.sha256()
    for package in packages:
        for path in sorted(package.rglob("*")):
            if path.is_file() and path.suffix in {".py", ".json"}:
                digest.update((package.name + "/" + path.relative_to(package).as_posix()).encode())
                digest.update(b"\0")
                digest.update(path.read_bytes())
                digest.update(b"\0")
    prompt = json.dumps({"system": SYSTEM, "pc": PC_REVIEW_INSTRUCTIONS, "tool": TOOL},
                        ensure_ascii=False, sort_keys=True, allow_nan=False).encode()
    return {"code_sha256": digest.hexdigest(), "prompt_sha256": hashlib.sha256(prompt).hexdigest(),
            "contract_version": "2.0"}
