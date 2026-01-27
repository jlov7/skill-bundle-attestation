# SBA End-to-End Demo

This example shows a complete SBA flow: digesting a bundle, creating an
attestation, signing it with DSSE, and verifying signatures.

## Files
- `bundle/` demo skill bundle
- `keys/` demo Ed25519 key pair (DO NOT USE IN PRODUCTION)

## Steps

1) Compute the bundle digest
```bash
python3 sba.py digest examples/e2e/bundle --json
```

2) Create a content attestation
```bash
python3 sba.py attest content examples/e2e/bundle \
  --output examples/e2e/content-attestation.json
```

3) Create a DSSE envelope and sign it
```bash
python3 sba.py attest content examples/e2e/bundle \
  --envelope --sign \
  --private-key examples/e2e/keys/ed25519_private.pem \
  --output examples/e2e/content-attestation.dsse.json
```

4) Verify the attestation against the bundle
```bash
python3 sba.py verify examples/e2e/content-attestation.dsse.json \
  --bundle examples/e2e/bundle \
  --verify-signatures \
  --public-key examples/e2e/keys/ed25519_public.pem
```

## Optional: regenerate keys
If you prefer to generate your own keys:
```bash
python3 - <<'PY'
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

out_dir = Path("examples/e2e/keys")
out_dir.mkdir(parents=True, exist_ok=True)

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

(out_dir / "ed25519_private.pem").write_bytes(private_pem)
(out_dir / "ed25519_public.pem").write_bytes(public_pem)
PY
```
