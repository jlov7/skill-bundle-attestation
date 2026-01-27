#!/usr/bin/env python3
"""Generate SBA attestations in in-toto Statement format.

This tool creates attestations for skill bundles that can be:
- Stored locally in .attestations/ directories
- Signed with Sigstore for public verification
- Submitted to transparency logs

Usage:
    # Generate content attestation for a directory
    python sba_attest.py content path/to/skill --output attestation.json

    # Generate content attestation for an archive
    python sba_attest.py content skill.zip --archive --output attestation.json

    # Generate with optional skill metadata
    python sba_attest.py content path/to/skill --version 1.0.0 --output attestation.json

Output format is in-toto Statement v1 with DSSE envelope support.
"""

from __future__ import annotations

import argparse
import base64
import json
import pathlib
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import sba_archive
import sba_crypto
from sba_digest import compute_archive_digest, compute_bundle_digest

# =============================================================================
# Constants
# =============================================================================

INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"

PREDICATE_TYPES = {
    "content": "https://jlov7.github.io/sba/predicates/sba-content-v1",
    "audit": "https://jlov7.github.io/sba/predicates/sba-audit-v1",
    "approval": "https://jlov7.github.io/sba/predicates/sba-approval-v1",
}

TOOL_NAME = "sba-attest"
TOOL_VERSION = "1.0.0"


# =============================================================================
# Digest computation helpers
# =============================================================================


def _bundle_digest_info(bundle_path: pathlib.Path) -> Dict[str, Any]:
    """Compute digest metadata using the canonical SBA algorithm."""
    result = compute_bundle_digest(bundle_path)
    return {
        "bundleDigest": f"sha256:{result.digest}",
        "entryCount": result.entry_count,
        "totalBytes": result.total_bytes,
    }


# =============================================================================
# Skill metadata extraction
# =============================================================================


def _parse_frontmatter(frontmatter: str) -> Dict[str, Any]:
    try:
        import yaml
    except Exception:
        return {}
    try:
        data = yaml.safe_load(frontmatter)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _parse_frontmatter_lines(frontmatter: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for line in frontmatter.split("\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            parsed[key.strip().lower()] = value.strip().strip('"').strip("'")
    return parsed


def _apply_frontmatter(metadata: Dict[str, Any], parsed: Dict[str, Any]) -> None:
    for key, value in parsed.items():
        if value is None:
            continue
        normalized = key.strip().lower()
        if normalized in {"name", "description", "version"}:
            metadata[normalized] = str(value)


def extract_skill_metadata(bundle_path: pathlib.Path) -> Dict[str, Any]:
    """Extract skill name and description from SKILL.md frontmatter."""
    skill_md = bundle_path / "SKILL.md"
    if not skill_md.exists():
        raise FileNotFoundError(f"SKILL.md not found in {bundle_path}")

    content = skill_md.read_text(encoding="utf-8")

    # Parse YAML frontmatter
    metadata = {"name": bundle_path.name, "description": ""}

    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            frontmatter = parts[1].strip()
            parsed = _parse_frontmatter(frontmatter)
            if parsed:
                _apply_frontmatter(metadata, parsed)
            else:
                _apply_frontmatter(metadata, _parse_frontmatter_lines(frontmatter))

    # If no description in frontmatter, try to extract from first paragraph
    if not metadata["description"]:
        # Find first non-empty line after frontmatter/heading
        lines = content.split("\n")
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("---"):
                metadata["description"] = line[:500]  # Limit length
                break

    if not metadata["description"]:
        metadata["description"] = f"Skill bundle: {metadata['name']}"

    return metadata


# =============================================================================
# Statement generation
# =============================================================================


def create_content_statement(
    bundle_path: pathlib.Path,
    is_archive: bool = False,
    version_override: Optional[str] = None,
    archive_root: Optional[str] = None,
) -> Dict[str, Any]:
    """Create an sba-content-v1 attestation statement."""

    if is_archive:
        archive_digest_hex, _ = compute_archive_digest(bundle_path)
        archive_digest = f"sha256:{archive_digest_hex}"

        # Extract to temp location to compute directory digest and get metadata
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = pathlib.Path(tmpdir)
            bundle_root, archive_root_used = sba_archive.extract_archive(
                bundle_path, tmppath, archive_root=archive_root
            )

            digest_info = _bundle_digest_info(bundle_root)
            skill_meta = extract_skill_metadata(bundle_root)

        # For archives, subject digest is the archive hash
        subject_digest = archive_digest.replace("sha256:", "")
        bundle_type = "archive"
    else:
        if archive_root:
            raise ValueError("--archive-root requires --archive")
        digest_info = _bundle_digest_info(bundle_path)
        skill_meta = extract_skill_metadata(bundle_path)
        archive_digest = None
        archive_root_used = None
        subject_digest = digest_info["bundleDigest"].replace("sha256:", "")
        bundle_type = "directory"

    if version_override:
        skill_meta["version"] = version_override

    # Build the predicate
    predicate: Dict[str, Any] = {
        "skill": {
            "name": skill_meta["name"],
            "description": skill_meta["description"],
        },
        "bundle": {
            "digestAlgorithm": "sba-directory-v1",
            "digest": digest_info["bundleDigest"],
            "entryCount": digest_info["entryCount"],
            "totalBytes": digest_info["totalBytes"],
            "bundleType": bundle_type,
        },
        "metadata": {
            "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "generatorTool": TOOL_NAME,
            "generatorVersion": TOOL_VERSION,
        },
    }

    if archive_root_used:
        predicate["metadata"]["archiveRoot"] = archive_root_used

    if skill_meta.get("version"):
        predicate["skill"]["version"] = skill_meta["version"]

    if archive_digest:
        predicate["bundle"]["archiveDigest"] = archive_digest

    # Build the in-toto Statement
    statement = {
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": [
            {
                "name": skill_meta["name"],
                "digest": {
                    "sha256": subject_digest,
                },
            }
        ],
        "predicateType": PREDICATE_TYPES["content"],
        "predicate": predicate,
    }

    return statement


def create_dsse_envelope(statement: Dict[str, Any], unsigned: bool = True) -> Dict[str, Any]:
    """Wrap a statement in a DSSE envelope.

    Note: This creates an UNSIGNED envelope. For production use, integrate
    with Sigstore or another signing mechanism.
    """
    payload_json = json.dumps(statement, separators=(",", ":"), sort_keys=True)
    payload_b64 = base64.b64encode(payload_json.encode("utf-8")).decode("ascii")

    envelope = {
        "payloadType": DSSE_PAYLOAD_TYPE,
        "payload": payload_b64,
        "signatures": [],
    }

    if unsigned:
        envelope["_note"] = "UNSIGNED - for testing only"

    return envelope


def sign_dsse_envelope(
    envelope: Dict[str, Any],
    private_key_path: pathlib.Path,
    signature_algorithm: str = "auto",
    key_id: Optional[str] = None,
    passphrase: Optional[str] = None,
) -> Dict[str, Any]:
    """Sign a DSSE envelope using a local private key."""
    if envelope.get("payloadType") != DSSE_PAYLOAD_TYPE:
        raise ValueError("Invalid DSSE envelope: payloadType mismatch")

    payload_b64 = envelope.get("payload", "")
    payload = base64.b64decode(payload_b64)
    private_key = sba_crypto.load_private_key(private_key_path, passphrase)
    signature = sba_crypto.sign_dsse(
        envelope["payloadType"], payload, private_key, signature_algorithm
    )

    sig_entry = {"sig": base64.b64encode(signature).decode("ascii")}
    if key_id:
        sig_entry["keyid"] = key_id

    envelope.setdefault("signatures", [])
    envelope["signatures"].append(sig_entry)
    envelope.pop("_note", None)
    return envelope


# =============================================================================
# CLI
# =============================================================================


# pragma: no mutate
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate SBA attestations in in-toto Statement format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s content ./my-skill
  %(prog)s content ./my-skill.zip --archive
  %(prog)s content ./my-skill.tar.gz --archive --archive-root my-skill
  %(prog)s content ./my-skill --version 1.0.0 --output attest.json
  %(prog)s content ./my-skill --envelope  # Wrap in DSSE envelope
  %(prog)s content ./my-skill --envelope --sign --private-key key.pem
        """,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Content attestation
    content_parser = subparsers.add_parser(
        "content",
        help="Generate sba-content-v1 attestation",
    )
    content_parser.add_argument(
        "bundle",
        type=pathlib.Path,
        help="Path to skill bundle directory or archive",
    )
    content_parser.add_argument(
        "--archive",
        action="store_true",
        help="Treat input as a ZIP or tar archive",
    )
    content_parser.add_argument(
        "--archive-root",
        type=str,
        help="Bundle root path within the archive (relative)",
    )
    content_parser.add_argument(
        "--version",
        type=str,
        help="Override skill version",
    )
    content_parser.add_argument(
        "--output",
        "-o",
        type=pathlib.Path,
        help="Output file (default: stdout)",
    )
    content_parser.add_argument(
        "--envelope",
        action="store_true",
        help="Wrap output in DSSE envelope",
    )
    content_parser.add_argument(
        "--sign",
        action="store_true",
        help="Sign DSSE envelope using a private key (implies --envelope)",
    )
    content_parser.add_argument(
        "--private-key",
        type=pathlib.Path,
        help="PEM private key for DSSE signing",
    )
    content_parser.add_argument(
        "--private-key-passphrase",
        type=str,
        help="Passphrase for the private key (if encrypted)",
    )
    content_parser.add_argument(
        "--signature-alg",
        type=str,
        default="auto",
        choices=sorted(sba_crypto.SUPPORTED_SIGNATURE_ALGS),
        help="Signature algorithm for DSSE signing",
    )
    content_parser.add_argument(
        "--key-id",
        type=str,
        help="Optional key ID to include in DSSE signatures",
    )
    content_parser.add_argument(
        "--compact",
        action="store_true",
        help="Output compact JSON (no indentation)",
    )

    args = parser.parse_args()

    try:
        if args.command == "content":
            statement = create_content_statement(
                args.bundle,
                is_archive=args.archive,
                version_override=args.version,
                archive_root=args.archive_root,
            )

            if args.sign and not args.private_key:
                raise ValueError("--sign requires --private-key")

            if args.envelope or args.sign:
                output = create_dsse_envelope(statement, unsigned=not args.sign)
                if args.sign:
                    output = sign_dsse_envelope(
                        output,
                        args.private_key,
                        signature_algorithm=args.signature_alg,
                        key_id=args.key_id,
                        passphrase=args.private_key_passphrase,
                    )
            else:
                output = statement

            indent = None if args.compact else 2
            json_str = json.dumps(output, indent=indent, ensure_ascii=False)

            if args.output:
                args.output.write_text(json_str + "\n", encoding="utf-8")
                print(f"Attestation written to {args.output}", file=sys.stderr)
            else:
                print(json_str)

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
