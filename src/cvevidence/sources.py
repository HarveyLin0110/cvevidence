"""Resolve paths within one operator-configured root; never execute artifacts."""
from pathlib import Path

def read_package(root, relative_path, limit=20*1024*1024):
    root=Path(root).resolve(strict=True)
    request=Path(relative_path)
    if request.is_absolute() or ".." in request.parts:
        raise ValueError("use a relative path inside the configured artifact root")
    target=(root/request).resolve(strict=True)
    if not target.is_relative_to(root) or not target.is_file():
        raise ValueError("source outside artifact root or not a regular file")
    with target.open("rb") as handle:
        payload=handle.read(limit+1)
    if len(payload)>limit:
        raise ValueError("package exceeds configured intake limit")
    return payload
