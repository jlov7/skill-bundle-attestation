#!/usr/bin/env python3
"""Verify SBA attestations against skill bundles.

This tool implements the normative verification rules defined in
sba-statement-v1.schema.json. It can verify:
- Content attestations against directories or archives
- Attestation chain integrity (content -> audit -> approval)
- Schema compliance

Usage:
    # Verify a content attestation against a bundle
    python sba_verify.py attestation.json --bundle path/to/skill

    # Verify an archive attestation
    python sba_verify.py attestation.json --bundle skill.zip --archive

    # Verify schema compliance only
    python sba_verify.py attestation.json --schema-only

Exit codes:
    0 = Verification passed
    1 = Verification failed
    2 = Error (invalid input, etc.)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import sba_archive
import sba_crypto
from sba_digest import compute_archive_digest, compute_bundle_digest, normalize_path

# =============================================================================
# Constants
# =============================================================================

INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

PREDICATE_TYPES = {
    "content": "https://jlov7.github.io/sba/predicates/sba-content-v1",
    "audit": "https://jlov7.github.io/sba/predicates/sba-audit-v1",
    "approval": "https://jlov7.github.io/sba/predicates/sba-approval-v1",
}

# (Exclusion constants are centralized in sba_digest.py)


# =============================================================================
# Verification result types
# =============================================================================


class Severity(Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


@dataclass
class VerificationResult:
    rule_id: str
    passed: bool
    severity: Severity
    message: str
    details: Optional[str] = None


class VerificationReport:
    def __init__(self):
        self.results: List[VerificationResult] = []

    def add(self, result: VerificationResult):
        self.results.append(result)

    def add_error(self, rule_id: str, message: str, details: Optional[str] = None):
        self.add(VerificationResult(rule_id, False, Severity.ERROR, message, details))

    def add_warning(self, rule_id: str, message: str, details: Optional[str] = None):
        self.add(VerificationResult(rule_id, False, Severity.WARNING, message, details))

    def add_pass(self, rule_id: str, message: str):
        self.add(VerificationResult(rule_id, True, Severity.INFO, message))

    @property
    def passed(self) -> bool:
        return not any(r.severity == Severity.ERROR and not r.passed for r in self.results)

    @property
    def has_warnings(self) -> bool:
        return any(r.severity == Severity.WARNING and not r.passed for r in self.results)

    def print_report(self, verbose: bool = False):
        print("\n" + "=" * 60)
        print("SBA VERIFICATION REPORT")
        print("=" * 60)

        errors = [r for r in self.results if r.severity == Severity.ERROR and not r.passed]
        warnings = [r for r in self.results if r.severity == Severity.WARNING and not r.passed]
        passes = [r for r in self.results if r.passed]

        if errors:
            print(f"\n❌ ERRORS ({len(errors)}):")
            for r in errors:
                print(f"  [{r.rule_id}] {r.message}")
                if r.details and verbose:
                    print(f"      Details: {r.details}")

        if warnings:
            print(f"\n⚠️  WARNINGS ({len(warnings)}):")
            for r in warnings:
                print(f"  [{r.rule_id}] {r.message}")
                if r.details and verbose:
                    print(f"      Details: {r.details}")

        if verbose and passes:
            print(f"\n✅ PASSED ({len(passes)}):")
            for r in passes:
                print(f"  [{r.rule_id}] {r.message}")

        print("\n" + "-" * 60)
        if self.passed:
            if self.has_warnings:
                print("RESULT: ⚠️  PASSED WITH WARNINGS")
            else:
                print("RESULT: ✅ PASSED")
        else:
            print("RESULT: ❌ FAILED")
        print("-" * 60 + "\n")


# =============================================================================
# Digest computation helpers
# =============================================================================


def _canonical_json_bytes(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode(
        "utf-8"
    )


def _compute_statement_digest(statement: Dict[str, Any]) -> str:
    digest = hashlib.sha256(_canonical_json_bytes(statement)).hexdigest()
    return f"sha256:{digest}"


def _extract_statement_for_digest(data: Dict[str, Any]) -> Dict[str, Any]:
    if "payloadType" in data:
        payload_b64 = data.get("payload", "")
        try:
            payload = base64.b64decode(payload_b64, validate=True)
        except Exception as exc:
            raise ValueError("Invalid base64 payload in DSSE envelope") from exc
        return json.loads(payload.decode("utf-8"))
    return data


def _load_statement_file(path: pathlib.Path) -> Dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return _extract_statement_for_digest(raw)


def _bundle_digest_info(bundle_path: pathlib.Path) -> Dict[str, Any]:
    result = compute_bundle_digest(bundle_path)
    return {
        "bundleDigest": f"sha256:{result.digest}",
        "entryCount": result.entry_count,
        "totalBytes": result.total_bytes,
    }


def _bundle_digest_for_target(
    bundle_path: pathlib.Path,
    is_archive: bool,
    archive_root: Optional[str] = None,
) -> Dict[str, Any]:
    if not is_archive:
        return _bundle_digest_info(bundle_path)
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = pathlib.Path(tmpdir)
        bundle_root, _ = sba_archive.extract_archive(
            bundle_path, tmppath, archive_root=archive_root
        )
        return _bundle_digest_info(bundle_root)


# =============================================================================
# Verification functions
# =============================================================================


def verify_statement_structure(statement: Dict[str, Any], report: VerificationReport):
    """Verify basic in-toto Statement structure (VR-000)."""

    # Check _type
    if statement.get("_type") != INTOTO_STATEMENT_TYPE:
        report.add_error(
            "VR-000a",
            f"Invalid _type: expected '{INTOTO_STATEMENT_TYPE}'",
            f"Got: {statement.get('_type')}",
        )
    else:
        report.add_pass("VR-000a", "Statement _type is valid")

    # Check subject exists and has required fields
    subjects = statement.get("subject", [])
    if not subjects:
        report.add_error("VR-000b", "Statement has no subjects")
    elif len(subjects) != 1:
        report.add_warning("VR-000b", f"Statement has {len(subjects)} subjects, expected 1")
    else:
        subject = subjects[0]
        if "digest" not in subject or "sha256" not in subject.get("digest", {}):
            report.add_error("VR-000c", "Subject missing digest.sha256")
        else:
            report.add_pass("VR-000c", "Subject has valid digest")

    # Check predicateType
    predicate_type = statement.get("predicateType")
    if predicate_type not in PREDICATE_TYPES.values():
        report.add_error(
            "VR-000d",
            f"Unknown predicateType: {predicate_type}",
            f"Valid types: {list(PREDICATE_TYPES.values())}",
        )
    else:
        report.add_pass("VR-000d", "predicateType is valid")

    # Check predicate exists
    if "predicate" not in statement:
        report.add_error("VR-000e", "Statement missing predicate")
    else:
        report.add_pass("VR-000e", "Statement has predicate")


def verify_content_predicate(
    statement: Dict[str, Any],
    bundle_path: Optional[pathlib.Path],
    is_archive: bool,
    report: VerificationReport,
    archive_root: Optional[str] = None,
):
    """Verify sba-content-v1 predicate against a bundle."""

    predicate = statement.get("predicate", {})
    subject = statement.get("subject", [{}])[0]

    # Extract claimed values
    claimed_digest = predicate.get("bundle", {}).get("digest", "")
    claimed_entry_count = predicate.get("bundle", {}).get("entryCount")
    claimed_total_bytes = predicate.get("bundle", {}).get("totalBytes")
    claimed_archive_digest = predicate.get("bundle", {}).get("archiveDigest")
    bundle_type = predicate.get("bundle", {}).get("bundleType", "directory")
    predicate_meta = (
        predicate.get("metadata", {}) if isinstance(predicate.get("metadata", {}), dict) else {}
    )
    claimed_archive_root = predicate_meta.get("archiveRoot")

    subject_digest = subject.get("digest", {}).get("sha256", "")

    if bundle_type not in {"directory", "archive"}:
        report.add_error(
            "VR-007",
            "Invalid bundleType in predicate.bundle",
            f"bundleType: {bundle_type!r}",
        )
        return

    if not claimed_digest:
        report.add_error("VR-001", "Missing predicate.bundle.digest")
        return

    # VR-002/VR-003: Subject digest binding
    if bundle_type == "directory":
        # Subject should match bundle digest
        expected_subject = claimed_digest.replace("sha256:", "")
        if subject_digest != expected_subject:
            report.add_error(
                "VR-002",
                "Subject digest does not match predicate.bundle.digest",
                f"Subject: {subject_digest}, Bundle: {expected_subject}",
            )
        else:
            report.add_pass("VR-002", "Subject digest matches bundle digest")
    else:
        # Archive: subject should match archive digest
        if not claimed_archive_digest:
            report.add_error(
                "VR-003a",
                "Missing predicate.bundle.archiveDigest for archive bundleType",
            )
        else:
            expected_subject = claimed_archive_digest.replace("sha256:", "")
            if subject_digest != expected_subject:
                report.add_error(
                    "VR-003",
                    "Subject digest does not match predicate.bundle.archiveDigest",
                    f"Subject: {subject_digest}, Archive: {expected_subject}",
                )
            else:
                report.add_pass("VR-003", "Subject digest matches archive digest")

    # VR-006: Name consistency check
    subject_name = subject.get("name", "")
    skill_name = predicate.get("skill", {}).get("name", "")
    if subject_name != skill_name:
        report.add_warning(
            "VR-006",
            "Subject name does not match skill name",
            f"Subject: '{subject_name}', Skill: '{skill_name}'",
        )
    else:
        report.add_pass("VR-006", "Subject name matches skill name")

    if archive_root and claimed_archive_root:
        if normalize_path(archive_root) != normalize_path(str(claimed_archive_root)):
            report.add_error(
                "VR-009",
                "Archive root mismatch between CLI and attestation metadata",
                f"CLI: {archive_root}, Attestation: {claimed_archive_root}",
            )

    archive_root_used = archive_root or claimed_archive_root

    # If bundle path provided, verify against actual content
    if bundle_path:
        if is_archive and bundle_type != "archive":
            report.add_error(
                "VR-008",
                "Bundle type mismatch: predicate expects directory, but --archive was used",
            )
        if not is_archive and bundle_type != "directory":
            report.add_error(
                "VR-008",
                "Bundle type mismatch: predicate expects archive, but --archive was not used",
            )
        if is_archive:
            verify_archive_content(
                bundle_path,
                claimed_digest,
                claimed_archive_digest,
                claimed_entry_count,
                claimed_total_bytes,
                report,
                archive_root=archive_root_used,
            )
        else:
            verify_directory_content(
                bundle_path, claimed_digest, claimed_entry_count, claimed_total_bytes, report
            )


def _verify_subject_matches_bundle(
    subject: Dict[str, Any], predicate_bundle_digest: str, report: VerificationReport, rule_id: str
) -> None:
    subject_digest = subject.get("digest", {}).get("sha256", "")
    expected = predicate_bundle_digest.replace("sha256:", "")
    if subject_digest != expected:
        report.add_error(
            rule_id,
            "Subject digest does not match predicate.bundle.digest",
            f"Subject: {subject_digest}, Bundle: {expected}",
        )
    else:
        report.add_pass(rule_id, "Subject digest matches predicate.bundle.digest")


def _verify_content_attestation_reference(
    content_attestation: pathlib.Path,
    bundle_path: Optional[pathlib.Path],
    report: VerificationReport,
    is_archive: bool,
    archive_root: Optional[str],
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    statement: Optional[Dict[str, Any]] = None
    is_archive_attestation = is_archive
    try:
        statement = _load_statement_file(content_attestation)
        bundle_type = (
            statement.get("predicate", {}).get("bundle", {}).get("bundleType", "directory")
        )
        is_archive_attestation = bundle_type == "archive"
    except Exception as exc:
        report.add_error(
            "CHAIN-000",
            "Failed to load content attestation",
            str(exc),
        )

    report_inner = verify_attestation(
        content_attestation,
        bundle_path=bundle_path,
        is_archive=is_archive_attestation,
        schema_only=False,
        archive_root=archive_root,
    )
    if not report_inner.passed:
        report.add_error("CHAIN-001", "Content attestation verification failed")

    if statement is None:
        return None, None
    if is_archive_attestation and not is_archive:
        report.add_warning(
            "CHAIN-003",
            "Content attestation is for an archive, but verification input is a directory",
        )
    if not is_archive_attestation and is_archive:
        report.add_warning(
            "CHAIN-003",
            "Content attestation is for a directory, but verification input is an archive",
        )

    digest = _compute_statement_digest(statement)
    return statement, digest


def _verify_audit_attestation_reference(
    audit_attestation: pathlib.Path,
    bundle_path: Optional[pathlib.Path],
    report: VerificationReport,
    content_attestation: Optional[pathlib.Path] = None,
    is_archive: bool = False,
    archive_root: Optional[str] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    report_inner = verify_attestation(
        audit_attestation,
        bundle_path=bundle_path,
        is_archive=is_archive,
        schema_only=False,
        content_attestation=content_attestation,
        archive_root=archive_root,
    )
    if not report_inner.passed:
        report.add_error("CHAIN-002", "Audit attestation verification failed")
    try:
        statement = _load_statement_file(audit_attestation)
    except Exception as exc:
        report.add_error(
            "CHAIN-000",
            "Failed to load audit attestation",
            str(exc),
        )
        return None, None

    digest = _compute_statement_digest(statement)
    return statement, digest


def verify_audit_predicate(
    statement: Dict[str, Any],
    bundle_path: Optional[pathlib.Path],
    report: VerificationReport,
    content_attestation: Optional[pathlib.Path] = None,
    is_archive: bool = False,
    archive_root: Optional[str] = None,
) -> None:
    predicate = statement.get("predicate", {})
    subject = statement.get("subject", [{}])[0]
    bundle = predicate.get("bundle", {})

    claimed_digest = bundle.get("digest", "")
    if not claimed_digest:
        report.add_error("AR-000", "Missing predicate.bundle.digest")
        return

    _verify_subject_matches_bundle(subject, claimed_digest, report, "AR-001")

    if bundle_path:
        computed = _bundle_digest_for_target(bundle_path, is_archive, archive_root=archive_root)
        if computed["bundleDigest"] != claimed_digest:
            report.add_error(
                "AR-002",
                "Computed digest does not match audit predicate bundle.digest",
                f"Computed: {computed['bundleDigest']}, Claimed: {claimed_digest}",
            )
        else:
            report.add_pass("AR-002", "Bundle digest matches audit predicate")

    if content_attestation:
        content_statement, content_digest = _verify_content_attestation_reference(
            content_attestation,
            bundle_path,
            report,
            is_archive=is_archive,
            archive_root=archive_root,
        )
        claimed_content_digest = bundle.get("contentAttestationDigest")
        if claimed_content_digest:
            if claimed_content_digest != content_digest:
                report.add_error(
                    "AR-003",
                    "contentAttestationDigest does not match computed digest",
                    f"Computed: {content_digest}, Claimed: {claimed_content_digest}",
                )
            else:
                report.add_pass("AR-003", "contentAttestationDigest matches")
        else:
            report.add_warning(
                "AR-003",
                "contentAttestationDigest missing (content attestation provided)",
            )

        if content_statement:
            content_bundle_digest = (
                content_statement.get("predicate", {}).get("bundle", {}).get("digest", "")
            )
            if content_bundle_digest and content_bundle_digest != claimed_digest:
                report.add_error(
                    "AR-004",
                    "Audit predicate bundle.digest does not match content attestation",
                    f"Audit: {claimed_digest}, Content: {content_bundle_digest}",
                )
            else:
                report.add_pass("AR-004", "Audit digest matches content attestation")


def verify_approval_predicate(
    statement: Dict[str, Any],
    bundle_path: Optional[pathlib.Path],
    report: VerificationReport,
    content_attestation: Optional[pathlib.Path] = None,
    audit_attestation: Optional[pathlib.Path] = None,
    is_archive: bool = False,
    archive_root: Optional[str] = None,
) -> None:
    predicate = statement.get("predicate", {})
    subject = statement.get("subject", [{}])[0]
    bundle = predicate.get("bundle", {})

    claimed_digest = bundle.get("digest", "")
    if not claimed_digest:
        report.add_error("AP-000", "Missing predicate.bundle.digest")
        return

    _verify_subject_matches_bundle(subject, claimed_digest, report, "AP-001")

    if bundle_path:
        computed = _bundle_digest_for_target(bundle_path, is_archive, archive_root=archive_root)
        if computed["bundleDigest"] != claimed_digest:
            report.add_error(
                "AP-002",
                "Computed digest does not match approval predicate bundle.digest",
                f"Computed: {computed['bundleDigest']}, Claimed: {claimed_digest}",
            )
        else:
            report.add_pass("AP-002", "Bundle digest matches approval predicate")

    content_digest_value = None
    if content_attestation:
        content_statement, content_digest = _verify_content_attestation_reference(
            content_attestation,
            bundle_path,
            report,
            is_archive=is_archive,
            archive_root=archive_root,
        )
        content_digest_value = content_digest
        claimed_content_digest = bundle.get("contentAttestationDigest")
        if claimed_content_digest:
            if claimed_content_digest != content_digest:
                report.add_error(
                    "AP-003",
                    "contentAttestationDigest does not match computed digest",
                    f"Computed: {content_digest}, Claimed: {claimed_content_digest}",
                )
            else:
                report.add_pass("AP-003", "contentAttestationDigest matches")
        else:
            report.add_warning(
                "AP-003",
                "contentAttestationDigest missing (content attestation provided)",
            )

        if content_statement:
            content_bundle_digest = (
                content_statement.get("predicate", {}).get("bundle", {}).get("digest", "")
            )
            if content_bundle_digest and content_bundle_digest != claimed_digest:
                report.add_error(
                    "AP-004",
                    "Approval predicate bundle.digest does not match content attestation",
                    f"Approval: {claimed_digest}, Content: {content_bundle_digest}",
                )
            else:
                report.add_pass("AP-004", "Approval digest matches content attestation")

    audit_digest_value = None
    if audit_attestation:
        audit_statement, audit_digest = _verify_audit_attestation_reference(
            audit_attestation,
            bundle_path,
            report,
            content_attestation=content_attestation,
            is_archive=is_archive,
            archive_root=archive_root,
        )
        audit_digest_value = audit_digest
        claimed_audit_digest = bundle.get("auditAttestationDigest")
        if claimed_audit_digest:
            if claimed_audit_digest != audit_digest:
                report.add_error(
                    "AP-005",
                    "auditAttestationDigest does not match computed digest",
                    f"Computed: {audit_digest}, Claimed: {claimed_audit_digest}",
                )
            else:
                report.add_pass("AP-005", "auditAttestationDigest matches")
        else:
            report.add_warning(
                "AP-005",
                "auditAttestationDigest missing (audit attestation provided)",
            )

        if audit_statement:
            audit_bundle_digest = (
                audit_statement.get("predicate", {}).get("bundle", {}).get("digest", "")
            )
            if audit_bundle_digest and audit_bundle_digest != claimed_digest:
                report.add_error(
                    "AP-006",
                    "Approval predicate bundle.digest does not match audit attestation",
                    f"Approval: {claimed_digest}, Audit: {audit_bundle_digest}",
                )
            else:
                report.add_pass("AP-006", "Approval digest matches audit attestation")

    reviewed = predicate.get("reviewedArtifacts", [])
    if isinstance(reviewed, list) and reviewed:
        for artifact in reviewed:
            if not isinstance(artifact, dict):
                continue
            art_type = artifact.get("type")
            art_digest = artifact.get("digest")
            if art_type == "sba-content-v1" and content_digest_value and art_digest:
                if art_digest != content_digest_value:
                    report.add_error(
                        "AP-007",
                        "reviewedArtifacts content digest mismatch",
                        f"Reviewed: {art_digest}, Content: {content_digest_value}",
                    )
            if art_type == "sba-audit-v1" and audit_digest_value and art_digest:
                if art_digest != audit_digest_value:
                    report.add_error(
                        "AP-008",
                        "reviewedArtifacts audit digest mismatch",
                        f"Reviewed: {art_digest}, Audit: {audit_digest_value}",
                    )


def verify_directory_content(
    bundle_path: pathlib.Path,
    claimed_digest: str,
    claimed_entry_count: int,
    claimed_total_bytes: int,
    report: VerificationReport,
):
    """Verify a directory bundle against claimed values."""

    try:
        computed = _bundle_digest_info(bundle_path)
    except Exception as e:
        report.add_error("VR-001", f"Failed to compute digest: {e}")
        return

    # VR-001: Digest match
    if computed["bundleDigest"] != claimed_digest:
        report.add_error(
            "VR-001",
            "Computed digest does not match claimed digest",
            f"Computed: {computed['bundleDigest']}, Claimed: {claimed_digest}",
        )
    else:
        report.add_pass("VR-001", f"Digest verified: {claimed_digest}")

    # VR-004: Entry count
    if computed["entryCount"] != claimed_entry_count:
        report.add_error(
            "VR-004",
            "Entry count mismatch",
            f"Computed: {computed['entryCount']}, Claimed: {claimed_entry_count}",
        )
    else:
        report.add_pass("VR-004", f"Entry count verified: {claimed_entry_count}")

    # VR-005: Total bytes
    if computed["totalBytes"] != claimed_total_bytes:
        report.add_error(
            "VR-005",
            "Total bytes mismatch",
            f"Computed: {computed['totalBytes']}, Claimed: {claimed_total_bytes}",
        )
    else:
        report.add_pass("VR-005", f"Total bytes verified: {claimed_total_bytes}")


def verify_archive_content(
    archive_path: pathlib.Path,
    claimed_digest: str,
    claimed_archive_digest: Optional[str],
    claimed_entry_count: int,
    claimed_total_bytes: int,
    report: VerificationReport,
    archive_root: Optional[str] = None,
):
    """Verify an archive bundle against claimed values."""

    # Verify archive digest
    if claimed_archive_digest:
        try:
            computed_archive_hex, _ = compute_archive_digest(archive_path)
            computed_archive = f"sha256:{computed_archive_hex}"
            if computed_archive != claimed_archive_digest:
                report.add_error(
                    "VR-001a",
                    "Archive digest mismatch",
                    f"Computed: {computed_archive}, Claimed: {claimed_archive_digest}",
                )
            else:
                report.add_pass("VR-001a", f"Archive digest verified: {claimed_archive_digest}")
        except Exception as e:
            report.add_error("VR-001a", f"Failed to compute archive digest: {e}")

    # Extract and verify directory digest
    import tempfile

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = pathlib.Path(tmpdir)
            bundle_root, _ = sba_archive.extract_archive(
                archive_path, tmppath, archive_root=archive_root
            )

            verify_directory_content(
                bundle_root, claimed_digest, claimed_entry_count, claimed_total_bytes, report
            )
    except Exception as e:
        report.add_error("VR-001b", f"Failed to extract and verify archive: {e}")


def verify_dsse_signatures(
    envelope: Dict[str, Any],
    payload: bytes,
    report: VerificationReport,
    public_keys: Optional[List[pathlib.Path]] = None,
    require_signatures: bool = False,
    signature_algorithm: str = "auto",
) -> None:
    """Verify DSSE signatures using provided public keys."""
    signatures = envelope.get("signatures", [])
    if not signatures:
        if require_signatures:
            report.add_error("DSSE-003", "DSSE envelope has no signatures")
        else:
            report.add_warning("DSSE-003", "DSSE envelope has no signatures")
        return

    if not public_keys:
        report.add_error("DSSE-004", "Public keys required for DSSE signature verification")
        return

    try:
        keys = sba_crypto.load_public_keys(public_keys)
    except Exception as e:
        report.add_error("DSSE-004", f"Failed to load public keys: {e}")
        return

    verified = False
    payload_type = envelope.get("payloadType", "")
    for signature in signatures:
        sig_b64 = signature.get("sig", "")
        if not sig_b64:
            continue
        try:
            sig_bytes = base64.b64decode(sig_b64, validate=True)
        except Exception as e:
            report.add_error("DSSE-004", f"Invalid DSSE signature encoding: {e}")
            return
        try:
            if sba_crypto.verify_dsse_signature(
                payload_type,
                payload,
                sig_bytes,
                keys,
                signature_algorithm=signature_algorithm,
            ):
                verified = True
                break
        except Exception as e:
            report.add_error("DSSE-004", f"Signature verification error: {e}")
            return

    if verified:
        report.add_pass("DSSE-005", "At least one DSSE signature verified")
    else:
        report.add_error("DSSE-005", "No DSSE signatures verified")


def verify_dsse_envelope(
    envelope: Dict[str, Any],
    report: VerificationReport,
    verify_signatures: bool = False,
    public_keys: Optional[List[pathlib.Path]] = None,
    require_signatures: bool = False,
    signature_algorithm: str = "auto",
) -> Optional[Dict[str, Any]]:
    """Verify DSSE envelope and extract statement."""

    if envelope.get("payloadType") != "application/vnd.in-toto+json":
        report.add_error("DSSE-001", "Invalid payloadType", f"Got: {envelope.get('payloadType')}")
        return None

    payload_b64 = envelope.get("payload", "")
    try:
        payload = base64.b64decode(payload_b64, validate=True)
        payload_json = payload.decode("utf-8")
        statement = json.loads(payload_json)
        report.add_pass("DSSE-001", "DSSE envelope valid, statement extracted")
        if verify_signatures or require_signatures:
            verify_dsse_signatures(
                envelope,
                payload,
                report,
                public_keys=public_keys,
                require_signatures=require_signatures,
                signature_algorithm=signature_algorithm,
            )
        return statement
    except Exception as e:
        report.add_error("DSSE-002", f"Failed to decode payload: {e}")
        return None


# =============================================================================
# Sigstore verification
# =============================================================================


def verify_sigstore_bundle(
    bundle_path: pathlib.Path,
    statement: Dict[str, Any],
    report: VerificationReport,
    identity: Optional[str] = None,
    issuer: Optional[str] = None,
    offline: bool = False,
) -> None:
    """Verify a Sigstore bundle and ensure it matches the attestation."""
    try:
        from sigstore.models import Bundle
        from sigstore.verify import Verifier, policy
    except Exception as e:
        report.add_error(
            "SIGSTORE-000",
            "sigstore library not installed; cannot verify bundle",
            str(e),
        )
        return

    try:
        bundle = Bundle.from_json(bundle_path.read_bytes())
    except Exception as e:
        report.add_error("SIGSTORE-001", f"Failed to parse bundle: {e}")
        return

    try:
        verifier = Verifier.production(offline=offline)
    except Exception as e:
        report.add_error("SIGSTORE-002", f"Failed to initialize Sigstore verifier: {e}")
        return

    policy_obj: policy.VerificationPolicy
    if identity:
        policy_obj = policy.Identity(identity=identity, issuer=issuer)
    elif issuer:
        policy_obj = policy.OIDCIssuer(issuer)
    else:
        policy_obj = policy.UnsafeNoOp()

    try:
        payload_type, payload = verifier.verify_dsse(bundle, policy_obj)
        report.add_pass("SIGSTORE-003", "Sigstore bundle signature verified")
    except Exception as e:
        report.add_error("SIGSTORE-003", f"Sigstore bundle verification failed: {e}")
        return

    try:
        bundle_statement = json.loads(payload.decode("utf-8"))
    except Exception as e:
        report.add_error("SIGSTORE-004", f"Failed to decode bundle payload: {e}")
        return

    if bundle_statement != statement:
        report.add_error("SIGSTORE-005", "Bundle payload does not match attestation")
        return

    if payload_type != "application/vnd.in-toto+json":
        report.add_warning(
            "SIGSTORE-006",
            f"Unexpected DSSE payloadType from bundle: {payload_type}",
        )


# =============================================================================
# Schema validation
# =============================================================================


def _format_schema_errors(errors: List[Any]) -> str:
    lines = []
    for err in errors[:5]:
        path = err.json_path or "$"
        lines.append(f"{path}: {err.message}")
    if len(errors) > 5:
        lines.append(f"... {len(errors) - 5} more")
    return "\n".join(lines)


def _load_schema(schema_name: str) -> Optional[Dict[str, Any]]:
    try:
        from importlib import resources

        data = resources.files("sba_schemas").joinpath(schema_name).read_text(encoding="utf-8")
        return json.loads(data)
    except Exception:
        pass

    schema_dir = pathlib.Path(__file__).parent
    candidate = schema_dir / schema_name
    if not candidate.exists():
        fallback = schema_dir.parent / schema_name
        if fallback.exists():
            candidate = fallback
        else:
            return None

    with candidate.open(encoding="utf-8") as f:
        return json.load(f)


def validate_schema(
    statement: Dict[str, Any],
    predicate_type: Optional[str],
    report: VerificationReport,
    required: bool = False,
) -> None:
    """Validate statement (and predicate when possible) against JSON Schemas."""
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        if required:
            report.add_error(
                "SCHEMA-000",
                "jsonschema not installed; cannot validate schemas",
                "Install with: pip install jsonschema",
            )
        else:
            report.add_warning(
                "SCHEMA-000",
                "jsonschema not installed; skipping schema validation",
            )
        return

    try:
        statement_schema = _load_schema("sba-statement-v1.schema.json")
        if statement_schema is None:
            report.add_error(
                "SCHEMA-001",
                "Statement schema not found",
                "Install SBA schemas or ensure schema files are available",
            )
            return
        Draft202012Validator.check_schema(statement_schema)
        validator = Draft202012Validator(statement_schema)
        errors = sorted(validator.iter_errors(statement), key=lambda e: e.json_path)
        if errors:
            report.add_error(
                "SCHEMA-001",
                "Statement schema validation failed",
                _format_schema_errors(errors),
            )
        else:
            report.add_pass("SCHEMA-001", "Statement schema validation passed")
    except Exception as e:
        report.add_error("SCHEMA-001", f"Statement schema validation error: {e}")
        return

    predicate_schema_map = {
        PREDICATE_TYPES["content"]: "sba-content-v1.schema.json",
        PREDICATE_TYPES["audit"]: "sba-audit-v1.schema.json",
        PREDICATE_TYPES["approval"]: "sba-approval-v1.schema.json",
    }

    schema_name = predicate_schema_map.get(predicate_type or "")
    if not schema_name:
        return

    try:
        predicate_schema = _load_schema(schema_name)
        if predicate_schema is None:
            report.add_error(
                "SCHEMA-002",
                f"Predicate schema not found ({schema_name})",
                "Install SBA schemas or ensure schema files are available",
            )
            return
        Draft202012Validator.check_schema(predicate_schema)
        validator = Draft202012Validator(predicate_schema)
        errors = sorted(
            validator.iter_errors(statement.get("predicate", {})),
            key=lambda e: e.json_path,
        )
        if errors:
            report.add_error(
                "SCHEMA-002",
                f"Predicate schema validation failed ({schema_name})",
                _format_schema_errors(errors),
            )
        else:
            report.add_pass("SCHEMA-002", f"Predicate schema validation passed ({schema_name})")
    except Exception as e:
        report.add_error("SCHEMA-002", f"Predicate schema validation error: {e}")


# =============================================================================
# Main verification function
# =============================================================================


def verify_attestation(
    attestation_path: pathlib.Path,
    bundle_path: Optional[pathlib.Path] = None,
    is_archive: bool = False,
    schema_only: bool = False,
    verify_signatures: bool = False,
    public_keys: Optional[List[pathlib.Path]] = None,
    require_signatures: bool = False,
    signature_algorithm: str = "auto",
    archive_root: Optional[str] = None,
    content_attestation: Optional[pathlib.Path] = None,
    audit_attestation: Optional[pathlib.Path] = None,
    sigstore_bundle: Optional[pathlib.Path] = None,
    sigstore_identity: Optional[str] = None,
    sigstore_issuer: Optional[str] = None,
    sigstore_offline: bool = False,
) -> VerificationReport:
    """Main verification entry point."""

    report = VerificationReport()

    # Load attestation
    try:
        content = attestation_path.read_text(encoding="utf-8")
        data = json.loads(content)
    except Exception as e:
        report.add_error("LOAD-001", f"Failed to load attestation: {e}")
        return report

    # Check if DSSE envelope
    if "payloadType" in data:
        statement = verify_dsse_envelope(
            data,
            report,
            verify_signatures=verify_signatures or require_signatures,
            public_keys=public_keys,
            require_signatures=require_signatures,
            signature_algorithm=signature_algorithm,
        )
        if not statement:
            return report
    else:
        if verify_signatures or require_signatures:
            report.add_error("DSSE-006", "Signature verification requires a DSSE envelope")
            return report
        statement = data

    if sigstore_bundle:
        verify_sigstore_bundle(
            sigstore_bundle,
            statement,
            report,
            identity=sigstore_identity,
            issuer=sigstore_issuer,
            offline=sigstore_offline,
        )

    # Verify statement structure
    verify_statement_structure(statement, report)

    validate_schema(statement, statement.get("predicateType"), report, required=schema_only)

    if schema_only:
        return report

    # Verify predicate based on type
    predicate_type = statement.get("predicateType")

    if predicate_type == PREDICATE_TYPES["content"]:
        verify_content_predicate(
            statement,
            bundle_path,
            is_archive,
            report,
            archive_root=archive_root,
        )
    elif predicate_type == PREDICATE_TYPES["audit"]:
        verify_audit_predicate(
            statement,
            bundle_path,
            report,
            content_attestation=content_attestation,
            is_archive=is_archive,
            archive_root=archive_root,
        )
    elif predicate_type == PREDICATE_TYPES["approval"]:
        verify_approval_predicate(
            statement,
            bundle_path,
            report,
            content_attestation=content_attestation,
            audit_attestation=audit_attestation,
            is_archive=is_archive,
            archive_root=archive_root,
        )

    return report


# =============================================================================
# CLI
# =============================================================================


# pragma: no mutate
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify SBA attestations against skill bundles",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "attestation",
        type=pathlib.Path,
        help="Path to attestation file (JSON or DSSE envelope)",
    )
    parser.add_argument(
        "--bundle",
        "-b",
        type=pathlib.Path,
        help="Path to skill bundle to verify against",
    )
    parser.add_argument(
        "--archive",
        action="store_true",
        help="Treat bundle as a ZIP or tar archive",
    )
    parser.add_argument(
        "--archive-root",
        type=str,
        help="Bundle root path within the archive (relative)",
    )
    parser.add_argument(
        "--content-attestation",
        type=pathlib.Path,
        help="Path to sba-content-v1 attestation for chain verification",
    )
    parser.add_argument(
        "--audit-attestation",
        type=pathlib.Path,
        help="Path to sba-audit-v1 attestation for chain verification",
    )
    parser.add_argument(
        "--schema-only",
        action="store_true",
        help="Only verify statement structure, not content",
    )
    parser.add_argument(
        "--verify-signatures",
        action="store_true",
        help="Verify DSSE signatures using provided public keys",
    )
    parser.add_argument(
        "--require-signatures",
        action="store_true",
        help="Fail if DSSE envelope has no signatures (implies --verify-signatures)",
    )
    parser.add_argument(
        "--public-key",
        action="append",
        type=pathlib.Path,
        help="PEM public key or certificate for DSSE signature verification",
    )
    parser.add_argument(
        "--signature-alg",
        type=str,
        default="auto",
        choices=sorted(sba_crypto.SUPPORTED_SIGNATURE_ALGS),
        help="Signature algorithm for DSSE verification",
    )
    parser.add_argument(
        "--sigstore-bundle",
        type=pathlib.Path,
        help="Sigstore bundle to verify against (DSSE only)",
    )
    parser.add_argument(
        "--sigstore-identity",
        type=str,
        help="Expected Sigstore identity (email/URI) for bundle verification",
    )
    parser.add_argument(
        "--sigstore-issuer",
        type=str,
        help="Expected Sigstore OIDC issuer for bundle verification",
    )
    parser.add_argument(
        "--sigstore-offline",
        action="store_true",
        help="Use Sigstore TUF cache only (no network)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed output including passed checks",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output report as JSON",
    )

    args = parser.parse_args()

    report = verify_attestation(
        args.attestation,
        bundle_path=args.bundle,
        is_archive=args.archive,
        schema_only=args.schema_only,
        verify_signatures=args.verify_signatures or args.require_signatures,
        public_keys=args.public_key,
        require_signatures=args.require_signatures,
        signature_algorithm=args.signature_alg,
        archive_root=args.archive_root,
        content_attestation=args.content_attestation,
        audit_attestation=args.audit_attestation,
        sigstore_bundle=args.sigstore_bundle,
        sigstore_identity=args.sigstore_identity,
        sigstore_issuer=args.sigstore_issuer,
        sigstore_offline=args.sigstore_offline,
    )

    if args.json:
        output = {
            "passed": report.passed,
            "has_warnings": report.has_warnings,
            "results": [
                {
                    "rule_id": r.rule_id,
                    "passed": r.passed,
                    "severity": r.severity.value,
                    "message": r.message,
                    "details": r.details,
                }
                for r in report.results
            ],
        }
        print(json.dumps(output, indent=2))
    else:
        report.print_report(verbose=args.verbose)

    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
