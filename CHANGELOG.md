# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-27

### Added

- **Specification**: Complete SBA (Skill Bundle Attestation) specification v1.0
  - `sba-directory-v1` canonical digest algorithm for deterministic bundle identification
  - Three predicate types: `sba-content-v1`, `sba-audit-v1`, `sba-approval-v1`
  - Verification rules VR-001 through VR-009 for attestation chain validation

- **Reference Implementation**: Python 3.10+ implementation with CLI tools
  - `sba-digest`: Compute canonical bundle digests
  - `sba-attest`: Generate in-toto Statement v1 attestations
  - `sba-verify`: Validate attestations and verification chains
  - `sba-zip`: Create deterministic ZIP archives

- **Security Features**
  - Path traversal protection in archive extraction
  - Symbolic link rejection to prevent escape attacks
  - Case-collision detection for filesystem safety
  - DSSE envelope support for signed attestations
  - Sigstore integration for identity-based verification

- **Documentation**
  - RFC/whitepaper with complete specification (31 pages)
  - Threat model analysis with mitigations
  - JSON schemas for all attestation formats
  - Quickstart guide and usage examples

- **Testing**
  - 74 tests covering core functionality
  - Test vectors with deterministic expected digests
  - Security-focused test suite for archive handling
  - CI pipeline with automated validation

### Standards Alignment

This release aligns with:
- [SLSA v1.0](https://slsa.dev/spec/v1.0/) - Supply chain Levels for Software Artifacts
- [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) - Attestation format
- [DSSE v1](https://github.com/secure-systems-lab/dsse) - Dead Simple Signing Envelope
- [Sigstore](https://sigstore.dev/) - Keyless signing infrastructure

[1.0.0]: https://github.com/jlov7/skill-bundle-attestation/releases/tag/v1.0.0
