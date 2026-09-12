"""Read saved core JSON with hash and run scope checks; never a Verifier certificate."""
import json

def validate_payload(payload, package, cve_id):
    if not isinstance(payload, dict) or payload.get("status") != "COMPLETED":
        raise ValueError("Core did not complete")
    if payload.get("context_hash") != package.context_hash or payload.get("archive_sha256") != package.archive_sha256:
        raise ValueError("Engineering archive/context mismatch")
    identity = payload.get("input", {})
    for key, expected in (("product_id", package.product_id), ("release_id", package.release_id),
                          ("build_id", package.declared_build_id), ("package_id", package.package_id),
                          ("context_hash", package.context_hash), ("format", package.format)):
        if identity.get(key) != expected:
            raise ValueError("Engineering product scope mismatch")
    entries = payload.get("analyses")
    if not isinstance(entries, list) or len(entries) != 1 or entries[0].get("cve_id") != cve_id:
        raise ValueError("Exactly one matching CVE is required")
    entry = entries[0]
    assessment = entry.get("assessment")
    if entry.get("status") == "UNSUPPORTED_CVE":
        if assessment is not None or entry.get("ai") is not None or payload.get("engineering_status") != "NOT_RUN" or payload.get("ai_status") != "NOT_RUN":
            raise ValueError("Unsupported CVE cannot have a verdict")
        return "UNSUPPORTED_CVE", "NOT_RUN"
    if (entry.get("status") != "COMPLETED" or not isinstance(assessment, dict)
            or assessment.get("cve_id") != cve_id or assessment.get("context_hash") != package.context_hash
            or assessment.get("verdict") not in ("AFFECTED", "NOT_AFFECTED", "NEEDS_INVESTIGATION")
            or payload.get("engineering_status") != "COMPLETED" or payload.get("ai_status") != "OFFLINE"
            or entry.get("ai", {}).get("status") != "OFFLINE"):
        raise ValueError("Invalid OFFLINE engineering assessment")
    evidence = entry.get("evidence", [])
    ids = [row["evidence_id"] for row in evidence]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate engineering evidence")
    refs = list(assessment.get("evidence_ids", []))
    conditions = assessment.get("conditions", [])
    from cvevidence_core.catalog import CATALOG
    if cve_id not in CATALOG and assessment.get('assessment_kind') != 'GENERAL_TRIAGE':
        raise ValueError('Unreviewed CVE requires explicit general triage')
    if assessment.get('assessment_kind') == 'GENERAL_TRIAGE':
        from cvevidence_core.general_triage import PROFILE_VERSION
        from cvevidence_core.public_cve import brief
        if (cve_id in CATALOG or assessment.get('profile_version') != PROFILE_VERSION
                or assessment.get('verdict') != 'NEEDS_INVESTIGATION'
                or assessment.get('cve_condition_verification_status') != 'NOT_RUN'
                or assessment.get('inventory_status') != 'COMPLETED'
                or any(c.get('state') != 'UNKNOWN' for c in conditions)):
            raise ValueError('General triage cannot claim a verified CVE condition')
        if brief(entry.get('public_cve_record'))['cve_id'] != cve_id:
            raise ValueError('Public CVE record scope mismatch')
    if not conditions or any(row.get("state") not in ("SUPPORTED", "BLOCKED", "UNKNOWN") for row in conditions):
        raise ValueError("Invalid condition state")
    for row in conditions:
        refs.extend(row.get("evidence_ids", []))
    if not set(refs) <= set(ids):
        raise ValueError("Assessment references evidence outside payload")
    return "COMPLETED", "OFFLINE"

def read_engineering(store, run_id):
    run = store.read(run_id)
    if not run.engineering_payload_sha256 or not run.input_package:
        raise ValueError("Run has no saved engineering payload")
    payload = json.loads(store.read_blob(run.engineering_payload_sha256))
    states = validate_payload(payload, run.input_package, run.cve_id)
    if states != (run.engineering_status, run.ai_status):
        raise ValueError("Saved engineering status mismatch")
    parent = store.read(run.parent_run_id)
    if not parent.input_package or parent.input_package != run.input_package:
        raise ValueError("Engineering parent snapshot mismatch")
    return payload
