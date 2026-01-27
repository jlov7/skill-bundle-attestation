from __future__ import annotations

import json
from pathlib import Path

import pytest

import sba_attest
import sba_verify


def test_dsse_signature_verification(repo_root: Path, tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path = tmp_path / "ed25519-private.pem"
    public_path = tmp_path / "ed25519-public.pem"
    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)

    statement = sba_attest.create_content_statement(
        repo_root / "test-vectors" / "tv-1-minimal",
        is_archive=False,
    )
    envelope = sba_attest.create_dsse_envelope(statement, unsigned=False)
    envelope = sba_attest.sign_dsse_envelope(envelope, private_path)

    att_path = tmp_path / "attestation.json"
    att_path.write_text(json.dumps(envelope), encoding="utf-8")

    report = sba_verify.verify_attestation(
        att_path,
        bundle_path=repo_root / "test-vectors" / "tv-1-minimal",
        verify_signatures=True,
        public_keys=[public_path],
    )
    assert report.passed


def test_dsse_requires_signatures(repo_root: Path, tmp_path: Path) -> None:
    statement = sba_attest.create_content_statement(
        repo_root / "test-vectors" / "tv-1-minimal",
        is_archive=False,
    )
    envelope = sba_attest.create_dsse_envelope(statement)
    att_path = tmp_path / "attestation.json"
    att_path.write_text(json.dumps(envelope), encoding="utf-8")

    report = sba_verify.verify_attestation(
        att_path,
        bundle_path=repo_root / "test-vectors" / "tv-1-minimal",
        require_signatures=True,
        public_keys=[],
    )
    assert not report.passed
    assert any(r.rule_id == "DSSE-003" for r in report.results)


def test_dsse_requires_public_keys_for_verification(repo_root: Path, tmp_path: Path) -> None:
    statement = sba_attest.create_content_statement(
        repo_root / "test-vectors" / "tv-1-minimal",
        is_archive=False,
    )
    envelope = sba_attest.create_dsse_envelope(statement, unsigned=False)
    envelope["signatures"] = [{"sig": "YWJj"}]
    att_path = tmp_path / "attestation.json"
    att_path.write_text(json.dumps(envelope), encoding="utf-8")

    report = sba_verify.verify_attestation(
        att_path,
        bundle_path=repo_root / "test-vectors" / "tv-1-minimal",
        verify_signatures=True,
        public_keys=None,
    )
    assert not report.passed
    assert any(r.rule_id == "DSSE-004" for r in report.results)


def test_dsse_rejects_invalid_signature_encoding(repo_root: Path, tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_path = tmp_path / "ed25519-public.pem"
    public_path.write_bytes(public_pem)

    statement = sba_attest.create_content_statement(
        repo_root / "test-vectors" / "tv-1-minimal",
        is_archive=False,
    )
    envelope = sba_attest.create_dsse_envelope(statement, unsigned=False)
    envelope["signatures"] = [{"sig": "not-base64!!!"}]

    att_path = tmp_path / "attestation.json"
    att_path.write_text(json.dumps(envelope), encoding="utf-8")

    report = sba_verify.verify_attestation(
        att_path,
        bundle_path=repo_root / "test-vectors" / "tv-1-minimal",
        verify_signatures=True,
        public_keys=[public_path],
    )
    assert not report.passed
    assert any(r.rule_id == "DSSE-004" for r in report.results)


def test_dsse_rejects_wrong_public_key(repo_root: Path, tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    signing_key = ed25519.Ed25519PrivateKey.generate()
    wrong_public = ed25519.Ed25519PrivateKey.generate().public_key()

    private_pem = signing_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    wrong_public_pem = wrong_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path = tmp_path / "signing.pem"
    public_path = tmp_path / "wrong.pub"
    private_path.write_bytes(private_pem)
    public_path.write_bytes(wrong_public_pem)

    statement = sba_attest.create_content_statement(
        repo_root / "test-vectors" / "tv-1-minimal",
        is_archive=False,
    )
    envelope = sba_attest.create_dsse_envelope(statement, unsigned=False)
    envelope = sba_attest.sign_dsse_envelope(envelope, private_path)

    att_path = tmp_path / "attestation.json"
    att_path.write_text(json.dumps(envelope), encoding="utf-8")

    report = sba_verify.verify_attestation(
        att_path,
        bundle_path=repo_root / "test-vectors" / "tv-1-minimal",
        verify_signatures=True,
        public_keys=[public_path],
    )
    assert not report.passed
    assert any(r.rule_id == "DSSE-005" for r in report.results)
