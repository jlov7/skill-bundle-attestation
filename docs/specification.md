# SBA Specification (Draft)

Version: 1.0.0

## 1. Overview
Skill Bundle Attestation (SBA) defines a deterministic bundle identity and
attestation format for agent skill bundles. The system provides:
- A canonical bundle digest algorithm (`sba-directory-v1`).
- Attestations expressed as in-toto Statement v1 with SBA predicates.
- Optional DSSE envelopes and signatures for tamper detection.

This document describes the normative behavior of the SBA tooling as implemented
in this repository.

## 2. Scope and Non-Goals
In scope:
- Deterministic bundle digest computation for directories.
- Archive support and archive-root extraction for digest/attestation.
- Attestation formats and verification logic.

Out of scope:
- Key management, identity provisioning, or PKI policy.
- Secure distribution of bundles or attestations.
- Runtime sandboxing of skill code.

## 3. Terminology
- Bundle: A directory or archive containing a skill and its files.
- Bundle digest: The canonical hash over bundle contents.
- Archive digest: The SHA-256 hash of the archive bytes.
- Attestation: A JSON statement describing bundle contents and metadata.
- DSSE: Dead Simple Signing Envelope for signed statements.

## 4. Bundle Digest (`sba-directory-v1`)
The bundle digest is computed from file paths and content, independent of file
system metadata (mtime/permissions). This algorithm is deterministic across
platforms.

### 4.1 Path normalization and validation
For each candidate file path, the following rules apply:
- Paths MUST use forward slashes (`/`).
- Paths MUST be Unicode NFC normalized.
- Paths MUST NOT start with `/` (no absolute paths).
- Paths MUST NOT contain `..` or `.` segments.
- Paths MUST NOT contain NUL bytes (`\x00`).
- Paths MUST NOT contain backslashes (`\`).
- Path components MUST NOT be empty.
- Path length MUST be <= 4096 characters.
- Path components MUST be <= 255 characters each.

Paths violating these rules are rejected.

### 4.2 Exclusions
The default exclusion set is:
- `.git`, `.attestations`, `.skillcheck`, `.specstory`, `.DS_Store`,
  `Thumbs.db`, `.gitignore`, `.gitattributes`, `__pycache__`,
  `node_modules`, `.venv`

Additionally, any path component starting with `SBA.` or `.sba` is excluded.

### 4.3 Enumeration
The bundle root directory is walked recursively. Only regular files are
included. Symlinks and non-regular files are excluded.

### 4.4 Entry format
For each included file, compute SHA-256 over raw bytes and emit the entry:

```
<path>\0sha256:<hex>\0<size>\n
```

Entries are UTF-8 encoded.

### 4.5 Sorting
Entries MUST be sorted by path using bytewise UTF-8 order.

### 4.6 Final digest
The bundle digest is the SHA-256 hash of the concatenated entry bytes.

## 5. Archive Mode
When operating on archives:
- The archive digest is the SHA-256 hash of the archive file bytes.
- The archive is extracted using safe extraction helpers and an optional
  `archiveRoot` to identify the bundle root within the archive.
- The bundle digest is computed over the extracted bundle root.

The attestation subject digest uses the archive digest for archive bundles.

## 6. Attestation Formats
SBA attestations are in-toto Statement v1 with SBA predicate types:
- `sba-content-v1`
- `sba-audit-v1`
- `sba-approval-v1`

The content attestation predicate includes:
- `skill`: name, description, optional version
- `bundle`: digest algorithm, digest, entry count, total bytes, bundle type
- `metadata`: generatedAt (UTC), generator tool/version, optional archiveRoot

Schemas are provided in:
- `sba-statement-v1.schema.json`
- `sba-content-v1.schema.json`
- `sba-audit-v1.schema.json`
- `sba-approval-v1.schema.json`

## 7. DSSE Envelopes
Statements can be wrapped in a DSSE envelope with:
- `payloadType`: `application/vnd.in-toto+json`
- `payload`: base64 encoded JSON (canonicalized with sorted keys)
- `signatures`: optional signature list

Supported signature algorithms:
- `ed25519`
- `ecdsa-sha256`
- `rsa-pss-sha256`
- `rsa-pkcs1v15-sha256`

## 8. Verification
Verification SHOULD include:
- Schema validation of the statement and predicate.
- Recomputed bundle digest comparison.
- Archive root consistency checks for archive bundles.
- DSSE signature verification when signatures are present and keys provided.

## 9. Security Considerations
See `docs/threat-model.md` for detailed threat modeling and mitigations.
