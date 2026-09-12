"""Recover unverified text from this run's bounded, explicit ancestry only."""
import re

from cvevidence_core.supplements import interpret_statement
from .engineering import read_engineering

MAX_ANCESTORS = 32
MAX_STATEMENTS = 128


def read_analysis_context(store, run_id, *, cve_id=None, check_budget=None):
    """Return original statements and symptom, never inherited condition values.

    DELTA may change archive/context, but product, release, build and CVE stay
    scoped. Corrupt or truncated ancestry fails visibly instead of losing text.
    """
    current = store.read(run_id)
    expected = current.input_package
    if not expected or not expected.context_hash:
        raise ValueError("Analysis context requires a collected package")
    cve = current.cve_id if cve_id is None else cve_id
    lineage, seen = [], set()
    while True:
        if check_budget:
            check_budget()
        if current.run_id in seen or len(lineage) >= MAX_ANCESTORS:
            raise ValueError("Analysis ancestry is cyclic or exceeds its bound")
        seen.add(current.run_id)
        package = current.input_package
        if (current.error or not package or not package.context_hash
                or current.cve_id not in ("", cve)
                or any(getattr(package, key) != getattr(expected, key) for key in
                       ("product_id", "release_id", "declared_build_id", "format"))):
            raise ValueError("Analysis ancestry has a different or invalid scope")
        if current.supplement and current.supplement.parent_run_id != current.parent_run_id:
            raise ValueError("Statement parent differs from run ancestry")
        lineage.append(current)
        if not current.parent_run_id:
            break
        parent = store.read(current.parent_run_id)
        if (current.supplement and current.supplement.kind == "NOTE"
                and parent.input_package != package):
            raise ValueError("A statement cannot change the collected package")
        current = parent

    statements, known, contexts, symptom = [], set(), set(), ""

    def add(text, source_context, statement_id=None):
        if not isinstance(source_context, str) or not re.fullmatch(r"[a-f0-9]{64}", source_context):
            raise ValueError("Invalid statement source context")
        if source_context not in contexts:
            raise ValueError("Statement source is outside the run ancestry")
        material = interpret_statement(text, source_context)
        if statement_id is not None and statement_id != material["material_id"]:
            raise ValueError("Saved statement identity mismatch")
        if material["material_id"] not in known:
            if len(statements) >= MAX_STATEMENTS:
                raise ValueError("Statement history exceeds its bound")
            known.add(material["material_id"])
            statements.append(material)

    def keep_symptom(value):
        nonlocal symptom
        if not isinstance(value, str) or len(value) > 4000:
            raise ValueError("Invalid saved symptom")
        if value.strip():
            symptom = value

    for run in reversed(lineage):
        if check_budget:
            check_budget()
        contexts.add(run.input_package.context_hash)
        keep_symptom(run.candidates.get("symptom", ""))
        if run.supplement and run.supplement.note.strip():
            add(run.supplement.note, run.input_package.context_hash)
        if run.engineering_payload_sha256:
            payload = read_engineering(store, run.run_id)
            discovery = payload.get("discovery", {})
            if not isinstance(discovery, dict):
                raise ValueError("Invalid saved discovery context")
            keep_symptom(discovery.get("symptom", ""))
            assessment = payload["analyses"][0].get("assessment") or {}
            rows = assessment.get("statement_context", assessment.get("statement_reviews", []))
            if not isinstance(rows, list) or len(rows) > MAX_STATEMENTS:
                raise ValueError("Invalid saved statement history")
            for row in rows:
                if not isinstance(row, dict):
                    raise ValueError("Invalid saved statement")
                add(row["text"], row["source_context_hash"], row["statement_id"])
    return {"symptom": symptom, "statements": statements}
