```
   _____ ____   ___
  / ___// __ \ / _ \
  \__ \/ /_/ // ___/
 ___/ /\____//_/    
/____/  Skill Bundle Attestation
```

SBA (Skill Bundle Attestation) provides a deterministic bundle identity, a content attestation format, and verification tooling for agent skill bundles. It is designed to be minimal, reproducible, and supply‑chain friendly.

## Highlights
- Deterministic bundle digest (`sba-directory-v1`)
- in-toto Statement v1 attestations with DSSE envelope support
- Archive + directory verification
- Test vectors + CI validation script

## Installation
```bash
python3 -m pip install -e .
```

## Quickstart
### Unified CLI (recommended)
Use the single entrypoint to access all commands:
```bash
python3 sba.py --help
python3 sba.py digest path/to/skill
python3 sba.py attest content path/to/skill --output attestation.json
python3 sba.py verify attestation.json --bundle path/to/skill
python3 sba.py zip path/to/skill skill.zip
```

### Direct commands

#### Compute a directory digest
```bash
python3 sba_digest.py path/to/skill
```

#### Compute an archive digest
```bash
python3 sba_digest.py path/to/skill.zip --archive
```

#### Generate a content attestation
```bash
python3 sba_attest.py content path/to/skill --output attestation.json
```

#### Verify an attestation
```bash
python3 sba_verify.py attestation.json --bundle path/to/skill
```

#### Archive attestation
```bash
python3 sba_attest.py content path/to/skill.zip --archive --output attestation.json
python3 sba_verify.py attestation.json --bundle path/to/skill.zip --archive
```

#### Archive with nested root
```bash
python3 sba_attest.py content path/to/skill.tar.gz --archive --archive-root skill --output attestation.json
python3 sba_verify.py attestation.json --bundle path/to/skill.tar.gz --archive --archive-root skill
```

#### Sign a DSSE envelope
```bash
python3 sba_attest.py content path/to/skill --envelope --sign --private-key key.pem --output attestation.json
```

#### Verify DSSE signatures
```bash
python3 sba_verify.py attestation.json --bundle path/to/skill --verify-signatures --public-key key.pub
```

#### Verify audit/approval chains
```bash
python3 sba_verify.py audit.json --bundle path/to/skill --content-attestation content.json
python3 sba_verify.py approval.json --bundle path/to/skill \
  --content-attestation content.json \
  --audit-attestation audit.json
```

#### Verify Sigstore bundle (DSSE)
```bash
python3 sba_verify.py attestation.json \
  --bundle path/to/skill \
  --sigstore-bundle bundle.json \
  --sigstore-identity you@example.com \
  --sigstore-issuer https://token.actions.githubusercontent.com
```

## Repo layout
- `sba.py` — unified CLI wrapper
- `sba_digest.py` — canonical digest algorithm
- `sba_attest.py` — attestation generator (Statement + DSSE)
- `sba_verify.py` — verifier + schema checks
- `sba_zip.py` — deterministic ZIP builder for test vectors
- `sba_archive.py` — safe ZIP/tar extraction helpers
- `sba_crypto.py` — optional DSSE signing/verification helpers
- `test-vectors/` — canonical vectors used in CI
- `examples/` — example attestations

## Documentation
- `docs/specification.md` — protocol and algorithm specification
- `docs/threat-model.md` — threat model and mitigations
- `RFC/SBA-Specification-v1.0.0-Draft-202602.pdf` — full RFC/whitepaper (PDF)
- `examples/e2e/README.md` — end-to-end demo walkthrough

## Testing
See `TESTING.md` for setup and `make verify`.

## Security and SBOM
Generate a dependency SBOM and run vulnerability checks:
```bash
make security
```

Regenerate pinned lockfiles used for audits/SBOMs:
```bash
make lock
```

## License
Apache-2.0
