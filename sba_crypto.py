#!/usr/bin/env python3
"""Cryptographic helpers for DSSE signing and verification.

This module is optional and only requires `cryptography` when used.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional

SUPPORTED_SIGNATURE_ALGS = {
    "auto",
    "ed25519",
    "ecdsa-sha256",
    "rsa-pss-sha256",
    "rsa-pkcs1v15-sha256",
}


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding (PAE)."""
    payload_type_bytes = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(payload_type_bytes)).encode("ascii")
        + b" "
        + payload_type_bytes
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def _load_crypto():
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    except Exception as exc:  # pragma: no cover - depends on optional dependency
        raise RuntimeError(
            "cryptography is required for signature operations. "
            "Install with: pip install cryptography"
        ) from exc
    return x509, hashes, serialization, ed25519, ec, padding, rsa


def load_public_keys(paths: Iterable[Path]) -> list[object]:
    x509, _hashes, serialization, _ed25519, _ec, _padding, _rsa = _load_crypto()
    keys: list[object] = []
    for path in paths:
        data = path.read_bytes()
        try:
            cert = x509.load_pem_x509_certificate(data)
            keys.append(cert.public_key())
            continue
        except Exception:
            pass
        keys.append(serialization.load_pem_public_key(data))
    return keys


def load_private_key(path: Path, passphrase: Optional[str] = None) -> object:
    _x509, _hashes, serialization, _ed25519, _ec, _padding, _rsa = _load_crypto()
    password = passphrase.encode("utf-8") if passphrase else None
    return serialization.load_pem_private_key(path.read_bytes(), password=password)


def _sign_with_key(key: object, payload: bytes, signature_algorithm: str) -> bytes:
    _x509, hashes, _serialization, ed25519, ec, padding, rsa = _load_crypto()

    if signature_algorithm not in SUPPORTED_SIGNATURE_ALGS:
        raise ValueError(f"Unsupported signature algorithm: {signature_algorithm}")

    if signature_algorithm in {"auto", "ed25519"} and isinstance(key, ed25519.Ed25519PrivateKey):
        return key.sign(payload)

    if signature_algorithm in {"auto", "ecdsa-sha256"} and isinstance(
        key, ec.EllipticCurvePrivateKey
    ):
        return key.sign(payload, ec.ECDSA(hashes.SHA256()))

    if isinstance(key, rsa.RSAPrivateKey):
        if signature_algorithm in {"auto", "rsa-pss-sha256"}:
            return key.sign(
                payload,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
        if signature_algorithm == "rsa-pkcs1v15-sha256":
            return key.sign(payload, padding.PKCS1v15(), hashes.SHA256())

    raise ValueError("Private key type does not match requested signature algorithm")


def sign_dsse(
    payload_type: str,
    payload: bytes,
    private_key: object,
    signature_algorithm: str = "auto",
) -> bytes:
    return _sign_with_key(private_key, dsse_pae(payload_type, payload), signature_algorithm)


def _verify_with_key(
    key: object, payload: bytes, signature: bytes, signature_algorithm: str
) -> bool:
    _x509, hashes, _serialization, ed25519, ec, padding, rsa = _load_crypto()

    if signature_algorithm not in SUPPORTED_SIGNATURE_ALGS:
        raise ValueError(f"Unsupported signature algorithm: {signature_algorithm}")

    try:
        if signature_algorithm in {"auto", "ed25519"} and isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, payload)
            return True

        if signature_algorithm in {"auto", "ecdsa-sha256"} and isinstance(
            key, ec.EllipticCurvePublicKey
        ):
            key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
            return True

        if isinstance(key, rsa.RSAPublicKey):
            if signature_algorithm in {"auto", "rsa-pss-sha256"}:
                key.verify(
                    signature,
                    payload,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                return True
            if signature_algorithm in {"auto", "rsa-pkcs1v15-sha256"}:
                key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
                return True
    except Exception:
        return False

    return False


def verify_dsse_signature(
    payload_type: str,
    payload: bytes,
    signature: bytes,
    public_keys: Iterable[object],
    signature_algorithm: str = "auto",
) -> bool:
    pae = dsse_pae(payload_type, payload)
    for key in public_keys:
        if _verify_with_key(key, pae, signature, signature_algorithm):
            return True
    return False
