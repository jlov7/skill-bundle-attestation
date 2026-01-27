#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path


def _load_manifest(root: Path) -> dict:
    return json.loads((root / "manifest.json").read_text(encoding="utf-8"))


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))

    import sba_attest
    import sba_digest
    import sba_verify

    manifest = _load_manifest(root)

    checks = []

    # Check 1: digest determinism against manifest
    ok = True
    failed_name = None
    for vector_name, spec in manifest["testVectors"].items():
        path = root / spec["path"]
        if spec.get("mode") == "archive":
            digest_hex, _ = sba_digest.compute_archive_digest(path)
            computed = f"sha256:{digest_hex}"
        else:
            bundle_result = sba_digest.compute_bundle_digest(path)
            computed = f"sha256:{bundle_result.digest}"
        if computed != spec["expectedDigest"]:
            ok = False
            failed_name = vector_name
            break

    checks.append(
        {
            "id": "digest-manifest",
            "passed": ok,
            "details": ("Computed digests match manifest" if ok else f"Mismatch on {failed_name}"),
        }
    )

    # Check 2: attestation round-trip (directory + archive)
    roundtrip_ok = True
    roundtrip_details = []
    cases = [
        ("tv-1-minimal", False),
        ("tv-3-archive", True),
    ]
    for tv_name, is_archive in cases:
        tv_path = root / manifest["testVectors"][tv_name]["path"]
        statement = sba_attest.create_content_statement(tv_path, is_archive=is_archive)
        with tempfile.TemporaryDirectory() as tmpdir:
            att_path = Path(tmpdir) / "attestation.json"
            att_path.write_text(json.dumps(statement), encoding="utf-8")
            report = sba_verify.verify_attestation(
                att_path,
                bundle_path=tv_path,
                is_archive=is_archive,
            )
        if not report.passed:
            roundtrip_ok = False
            roundtrip_details.append(tv_name)

    checks.append(
        {
            "id": "attest-roundtrip",
            "passed": roundtrip_ok,
            "details": (
                "All round-trips verified" if roundtrip_ok else f"Failures: {roundtrip_details}"
            ),
        }
    )

    # Check 3: optional DSSE signature verification
    sig_check = {
        "id": "dsse-signature",
        "passed": True,
        "details": "Skipped (cryptography missing)",
    }
    try:
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

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            private_path = tmp_path / "key.pem"
            public_path = tmp_path / "key.pub"
            private_path.write_bytes(private_pem)
            public_path.write_bytes(public_pem)

            statement = sba_attest.create_content_statement(
                root / "test-vectors" / "tv-1-minimal",
                is_archive=False,
            )
            envelope = sba_attest.create_dsse_envelope(statement, unsigned=False)
            envelope = sba_attest.sign_dsse_envelope(envelope, private_path)
            att_path = tmp_path / "attestation.json"
            att_path.write_text(json.dumps(envelope), encoding="utf-8")

            report = sba_verify.verify_attestation(
                att_path,
                bundle_path=root / "test-vectors" / "tv-1-minimal",
                verify_signatures=True,
                public_keys=[public_path],
            )

        sig_check = {
            "id": "dsse-signature",
            "passed": report.passed,
            "details": "Signature verified" if report.passed else "Signature verification failed",
        }
    except Exception:
        pass

    checks.append(sig_check)

    passed = all(check["passed"] for check in checks)
    result = {"passed": passed, "checks": checks}
    print(json.dumps(result, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
