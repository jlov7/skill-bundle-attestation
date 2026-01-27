from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import sba_attest
import sba_verify


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_audit_and_approval_chain(repo_root: Path, tmp_path: Path) -> None:
    bundle_path = repo_root / "test-vectors" / "tv-1-minimal"
    content_statement = sba_attest.create_content_statement(bundle_path, is_archive=False)

    content_att_path = tmp_path / "content.json"
    content_att_path.write_text(json.dumps(content_statement), encoding="utf-8")

    content_digest = sba_verify._compute_statement_digest(content_statement)
    bundle_digest = content_statement["predicate"]["bundle"]["digest"]

    audit_statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": content_statement["predicate"]["skill"]["name"],
                "digest": {"sha256": bundle_digest.replace("sha256:", "")},
            }
        ],
        "predicateType": "https://jlov7.github.io/sba/predicates/sba-audit-v1",
        "predicate": {
            "skill": {"name": content_statement["predicate"]["skill"]["name"]},
            "bundle": {
                "digest": bundle_digest,
                "contentAttestationDigest": content_digest,
            },
            "audit": {
                "tool": {"name": "unit-test-audit", "version": "0.1.0"},
                "timestamp": _iso_now(),
                "result": "PASS",
            },
        },
    }

    audit_att_path = tmp_path / "audit.json"
    audit_att_path.write_text(json.dumps(audit_statement), encoding="utf-8")

    audit_digest = sba_verify._compute_statement_digest(audit_statement)

    approval_statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": content_statement["predicate"]["skill"]["name"],
                "digest": {"sha256": bundle_digest.replace("sha256:", "")},
            }
        ],
        "predicateType": "https://jlov7.github.io/sba/predicates/sba-approval-v1",
        "predicate": {
            "skill": {"name": content_statement["predicate"]["skill"]["name"]},
            "bundle": {
                "digest": bundle_digest,
                "contentAttestationDigest": content_digest,
                "auditAttestationDigest": audit_digest,
            },
            "approval": {
                "decision": "APPROVED",
                "timestamp": _iso_now(),
                "scope": "PROJECT",
            },
            "reviewedArtifacts": [
                {"type": "sba-content-v1", "digest": content_digest},
                {"type": "sba-audit-v1", "digest": audit_digest},
            ],
        },
    }

    approval_att_path = tmp_path / "approval.json"
    approval_att_path.write_text(json.dumps(approval_statement), encoding="utf-8")

    audit_report = sba_verify.verify_attestation(
        audit_att_path,
        bundle_path=bundle_path,
        content_attestation=content_att_path,
    )
    assert audit_report.passed

    approval_report = sba_verify.verify_attestation(
        approval_att_path,
        bundle_path=bundle_path,
        content_attestation=content_att_path,
        audit_attestation=audit_att_path,
    )
    assert approval_report.passed
