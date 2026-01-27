# SBA Threat Model

## Summary
SBA protects the integrity of skill bundles and their attestations. It assumes
attackers may control bundle inputs, archives, and attestations, but cannot
break standard cryptography (SHA-256, Ed25519, ECDSA, RSA) or compromise trusted
signing keys.

## Assets
- Bundle integrity (directory or archive).
- Attestation integrity and authenticity.
- Verification correctness (schema and digest checks).
- Safe extraction of archives.

## Trust Boundaries
- Bundle producer vs. bundle consumer.
- Local filesystem vs. untrusted archive inputs.
- Offline verification vs. Sigstore online verification.

## Threats and Mitigations

### 1) Archive traversal / path injection
- Threat: Crafted archives attempt `../` traversal or absolute paths.
- Mitigation: Safe extraction rejects traversal, absolute paths, and symlinks.

### 2) Symlink or non-regular file abuse
- Threat: Symlinks/hardlinks to escape bundle root or change content.
- Mitigation: Bundle digest excludes symlinks and non-regular files.

### 3) Case-insensitive collisions
- Threat: `File.txt` and `file.txt` collide on case-insensitive filesystems.
- Mitigation: Bundle digest rejects case-colliding paths by default.

### 4) Attestation tampering
- Threat: Attestation altered to match a malicious bundle.
- Mitigation: DSSE signature verification; optional Sigstore identity checks.

### 5) Schema bypass / format confusion
- Threat: Malformed statement/predicate accepted by parser.
- Mitigation: JSON Schema validation for statement and predicate types.

### 6) Digest confusion (archive vs directory)
- Threat: Substituting an archive digest where a directory digest is expected.
- Mitigation: Separate fields for bundle digest and archive digest; `bundleType`.

### 7) Resource exhaustion (zip bombs / huge trees)
- Threat: Large archives or deep trees cause excessive CPU/memory use.
- Mitigation: Input validation and safe extraction; callers SHOULD apply
  size/time limits appropriate for their environment.

### 8) Missing dependencies
- Threat: Optional crypto/schema dependencies absent, weakening verification.
- Mitigation: Verification reports warnings; `--require-signatures` enforces
  signed envelopes when expected.

## Residual Risks
- Key compromise or weak operational key handling.
- Extremely large bundles causing local resource exhaustion.
- Trust in the Sigstore transparency log and identity providers.

## Recommended Operational Controls
- Require signatures for production verification.
- Pin expected signer identities (Sigstore) or key fingerprints.
- Enforce size and depth limits for untrusted archives.
- Run verification in a sandboxed environment.
