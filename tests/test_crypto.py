from __future__ import annotations

import pytest

import sba_crypto


def test_dsse_pae_format() -> None:
    payload_type = "text/plain"
    payload = b"hi"
    expected = b"DSSEv1 10 text/plain 2 hi"
    assert sba_crypto.dsse_pae(payload_type, payload) == expected


def test_verify_dsse_signature_with_wrong_key() -> None:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = ed25519.Ed25519PrivateKey.generate().public_key()
    payload_type = "application/vnd.in-toto+json"
    payload = b"{}"

    signature = sba_crypto.sign_dsse(
        payload_type, payload, private_key, signature_algorithm="ed25519"
    )
    verified = sba_crypto.verify_dsse_signature(payload_type, payload, signature, [public_key])
    assert verified is False


def test_verify_dsse_signature_with_correct_key() -> None:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    payload_type = "application/vnd.in-toto+json"
    payload = b"{}"

    signature = sba_crypto.sign_dsse(
        payload_type, payload, private_key, signature_algorithm="ed25519"
    )
    verified = sba_crypto.verify_dsse_signature(payload_type, payload, signature, [public_key])
    assert verified is True


def test_sign_dsse_rejects_invalid_algorithm() -> None:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private_key = ed25519.Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="Unsupported signature algorithm"):
        sba_crypto.sign_dsse("text/plain", b"data", private_key, signature_algorithm="nope")
