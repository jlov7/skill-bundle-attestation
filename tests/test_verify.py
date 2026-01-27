from __future__ import annotations

import json
import shutil
import tarfile
from pathlib import Path
from types import SimpleNamespace

import sba_attest
import sba_verify


def test_verify_rejects_missing_archive_digest(repo_root: Path, tmp_path: Path) -> None:
    example = repo_root / "examples" / "tv-3-attestation.json"
    data = json.loads(example.read_text(encoding="utf-8"))
    data["predicate"]["bundle"].pop("archiveDigest", None)

    att_path = tmp_path / "attestation.json"
    att_path.write_text(json.dumps(data), encoding="utf-8")

    report = sba_verify.verify_attestation(
        att_path,
        bundle_path=repo_root / "test-vectors" / "tv-3-archive.zip",
        is_archive=True,
    )
    assert not report.passed
    assert any(r.rule_id == "VR-003a" for r in report.results)


def test_verify_detects_tampered_bundle(repo_root: Path, tmp_path: Path) -> None:
    original = repo_root / "test-vectors" / "tv-1-minimal"
    tampered = tmp_path / "tv-1-minimal"
    shutil.copytree(original, tampered)

    skill_md = tampered / "SKILL.md"
    skill_md.write_text(skill_md.read_text(encoding="utf-8") + "\n# tamper", encoding="utf-8")

    attestation = repo_root / "examples" / "tv-1-attestation.json"
    report = sba_verify.verify_attestation(attestation, bundle_path=tampered)

    assert not report.passed
    assert any(r.rule_id == "VR-001" and not r.passed for r in report.results)


def test_dsse_envelope_roundtrip(repo_root: Path) -> None:
    statement = sba_attest.create_content_statement(
        repo_root / "test-vectors" / "tv-1-minimal",
        is_archive=False,
    )
    envelope = sba_attest.create_dsse_envelope(statement)

    report = sba_verify.VerificationReport()
    extracted = sba_verify.verify_dsse_envelope(envelope, report)

    assert extracted == statement
    assert report.passed


def test_format_schema_errors_summary() -> None:
    errors = [
        SimpleNamespace(json_path="$.predicate", message="missing field"),
        SimpleNamespace(json_path="$.subject[0]", message="invalid digest"),
    ]
    rendered = sba_verify._format_schema_errors(errors)
    assert "$.predicate" in rendered
    assert "missing field" in rendered
    assert "$.subject[0]" in rendered
    assert "invalid digest" in rendered


def test_report_warning_and_print(capfd) -> None:
    report = sba_verify.VerificationReport()
    report.add_warning("VW-001", "Warning message")
    report.add_error("VE-001", "Error message")

    report.print_report(verbose=True)
    output = capfd.readouterr().out
    assert "WARNINGS" in output
    assert "ERRORS" in output


def _write_skill_bundle(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text(
        "---\nname: verify-skill\ndescription: verify bundle\nversion: 0.1.0\n---\n",
        encoding="utf-8",
    )


def test_verify_invalid_bundle_type(repo_root: Path, tmp_path: Path) -> None:
    bundle_path = repo_root / "test-vectors" / "tv-1-minimal"
    statement = sba_attest.create_content_statement(bundle_path, is_archive=False)
    statement["predicate"]["bundle"]["bundleType"] = "weird"

    att_path = tmp_path / "attestation.json"
    att_path.write_text(json.dumps(statement), encoding="utf-8")

    report = sba_verify.verify_attestation(att_path, bundle_path=bundle_path)
    assert not report.passed
    assert any(r.rule_id == "VR-007" for r in report.results)


def test_verify_archive_root_mismatch(tmp_path: Path) -> None:
    bundle_root = tmp_path / "bundle"
    _write_skill_bundle(bundle_root)

    archive_path = tmp_path / "bundle.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tf:
        tf.add(bundle_root, arcname="bundle")

    statement = sba_attest.create_content_statement(archive_path, is_archive=True)
    att_path = tmp_path / "attestation.json"
    att_path.write_text(json.dumps(statement), encoding="utf-8")

    report = sba_verify.verify_attestation(
        att_path,
        bundle_path=None,
        is_archive=True,
        archive_root="wrong-root",
    )
    assert not report.passed
    assert any(r.rule_id == "VR-009" for r in report.results)


def test_verify_dsse_invalid_payload_base64(tmp_path: Path) -> None:
    envelope = {
        "payloadType": "application/vnd.in-toto+json",
        "payload": "not-base64!!!",
        "signatures": [],
    }
    att_path = tmp_path / "attestation.json"
    att_path.write_text(json.dumps(envelope), encoding="utf-8")

    report = sba_verify.verify_attestation(att_path)
    assert not report.passed
    assert any(r.rule_id == "DSSE-002" for r in report.results)


def test_chain_reference_invalid_content_attestation(repo_root: Path, tmp_path: Path) -> None:
    bundle_path = repo_root / "test-vectors" / "tv-1-minimal"
    content_statement = sba_attest.create_content_statement(bundle_path, is_archive=False)
    bundle_digest = content_statement["predicate"]["bundle"]["digest"]
    skill_name = content_statement["predicate"]["skill"]["name"]

    invalid_content = {
        "payloadType": "application/vnd.in-toto+json",
        "payload": "###",
        "signatures": [],
    }
    content_path = tmp_path / "content.json"
    content_path.write_text(json.dumps(invalid_content), encoding="utf-8")

    subject_digest = bundle_digest.replace("sha256:", "")
    audit_statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": skill_name, "digest": {"sha256": subject_digest}}],
        "predicateType": "https://jlov7.github.io/sba/predicates/sba-audit-v1",
        "predicate": {
            "skill": {"name": skill_name},
            "bundle": {"digest": bundle_digest},
            "audit": {
                "tool": {"name": "unit-test", "version": "0.1.0"},
                "timestamp": "2026-01-01T00:00:00Z",
                "result": "PASS",
            },
        },
    }
    audit_path = tmp_path / "audit.json"
    audit_path.write_text(json.dumps(audit_statement), encoding="utf-8")

    report = sba_verify.verify_attestation(
        audit_path,
        bundle_path=bundle_path,
        content_attestation=content_path,
    )
    assert not report.passed
    assert any(r.rule_id == "CHAIN-000" for r in report.results)


def test_verify_bundle_type_mismatch_reports_error(repo_root: Path, tmp_path: Path) -> None:
    bundle_path = repo_root / "test-vectors" / "tv-1-minimal"
    statement = sba_attest.create_content_statement(bundle_path, is_archive=False)
    att_path = tmp_path / "attestation.json"
    att_path.write_text(json.dumps(statement), encoding="utf-8")
    report = sba_verify.verify_attestation(att_path, bundle_path=bundle_path, is_archive=True)
    assert not report.passed
    assert any(r.rule_id == "VR-008" for r in report.results)


def test_verify_dsse_invalid_payload_type(tmp_path: Path) -> None:
    envelope = {
        "payloadType": "application/json",
        "payload": "e30=",
        "signatures": [],
    }
    att_path = tmp_path / "attestation.json"
    att_path.write_text(json.dumps(envelope), encoding="utf-8")

    report = sba_verify.verify_attestation(att_path)
    assert not report.passed
    assert any(r.rule_id == "DSSE-001" for r in report.results)
