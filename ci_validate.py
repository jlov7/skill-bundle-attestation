#!/usr/bin/env python3
"""CI validation script for SBA test vectors and schemas.

This script validates:
1. All Python tools compile successfully
2. JSON schemas are valid Draft 2020-12
3. Test vector digests match manifest expectations
4. Attestations verify against their bundles
5. Cross-tool consistency (digest, zip, attest, verify)

Usage:
    python ci_validate.py                    # Run all validations
    python ci_validate.py --verbose          # Show detailed output
    python ci_validate.py --schema-only      # Only validate schemas

Exit codes:
    0 = All validations passed
    1 = One or more validations failed
    2 = Script error
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import List, Optional

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR = pathlib.Path(__file__).parent.resolve()

PYTHON_TOOLS = [
    "sba_archive.py",
    "sba_crypto.py",
    "sba_digest.py",
    "sba_zip.py",
    "sba_attest.py",
    "sba_verify.py",
]

SCHEMAS = [
    "sba-content-v1.schema.json",
    "sba-statement-v1.schema.json",
    "sba-audit-v1.schema.json",
    "sba-approval-v1.schema.json",
]

MANIFEST_FILE = "manifest.json"


# =============================================================================
# Validation result tracking
# =============================================================================


@dataclass
class ValidationResult:
    name: str
    passed: bool
    message: str
    details: Optional[str] = None


class ValidationReport:
    def __init__(self):
        self.results: List[ValidationResult] = []

    def add(self, name: str, passed: bool, message: str, details: Optional[str] = None):
        self.results.append(ValidationResult(name, passed, message, details))

    def passed(self) -> bool:
        return all(r.passed for r in self.results)

    def print_report(self, verbose: bool = False):
        print("\n" + "=" * 70)
        print("SBA CI VALIDATION REPORT")
        print("=" * 70)

        passed = [r for r in self.results if r.passed]
        failed = [r for r in self.results if not r.passed]

        if failed:
            print(f"\n❌ FAILED ({len(failed)}):\n")
            for r in failed:
                print(f"  • {r.name}: {r.message}")
                if r.details:
                    for line in r.details.split("\n"):
                        print(f"      {line}")

        if verbose and passed:
            print(f"\n✅ PASSED ({len(passed)}):\n")
            for r in passed:
                print(f"  • {r.name}: {r.message}")

        print("\n" + "-" * 70)
        if self.passed():
            print(f"RESULT: ✅ ALL {len(self.results)} VALIDATIONS PASSED")
        else:
            print(f"RESULT: ❌ {len(failed)}/{len(self.results)} VALIDATIONS FAILED")
        print("-" * 70 + "\n")


# =============================================================================
# Validation functions
# =============================================================================


def validate_python_compilation(report: ValidationReport):
    """Validate all Python tools compile without syntax errors."""
    for tool in PYTHON_TOOLS:
        tool_path = SCRIPT_DIR / tool
        if not tool_path.exists():
            report.add(f"compile:{tool}", False, f"File not found: {tool}")
            continue

        result = subprocess.run(
            [sys.executable, "-m", "py_compile", str(tool_path)],
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            report.add(f"compile:{tool}", True, "Compiles successfully")
        else:
            report.add(
                f"compile:{tool}",
                False,
                "Compilation failed",
                result.stderr.strip(),
            )


def validate_schemas(report: ValidationReport):
    """Validate all JSON schemas are valid Draft 2020-12."""
    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        # Try to use locally installed version
        import sys

        sys.path.insert(0, str(pathlib.Path.home() / ".local/lib/python3.11/site-packages"))
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            report.add(
                "schema:jsonschema",
                False,
                "jsonschema package not installed",
                "Run: pip install jsonschema",
            )
            return

    for schema_name in SCHEMAS:
        schema_path = SCRIPT_DIR / schema_name
        if not schema_path.exists():
            report.add(f"schema:{schema_name}", False, f"File not found: {schema_name}")
            continue

        try:
            with open(schema_path) as f:
                schema = json.load(f)
            Draft202012Validator.check_schema(schema)
            report.add(f"schema:{schema_name}", True, "Valid Draft 2020-12 schema")
        except json.JSONDecodeError as e:
            report.add(f"schema:{schema_name}", False, "Invalid JSON", str(e))
        except Exception as e:
            report.add(f"schema:{schema_name}", False, "Schema validation failed", str(e))


def validate_test_vectors(report: ValidationReport, verbose: bool = False):
    """Validate test vectors match manifest expectations."""
    manifest_path = SCRIPT_DIR / MANIFEST_FILE
    if not manifest_path.exists():
        report.add("manifest", False, f"Manifest not found: {MANIFEST_FILE}")
        return

    try:
        with open(manifest_path) as f:
            manifest = json.load(f)
    except json.JSONDecodeError as e:
        report.add("manifest", False, "Invalid manifest JSON", str(e))
        return

    test_vectors = manifest.get("testVectors", {})

    for tv_name, tv_spec in test_vectors.items():
        tv_path = SCRIPT_DIR / tv_spec["path"]

        if not tv_path.exists():
            report.add(f"tv:{tv_name}", False, f"Path not found: {tv_spec['path']}")
            continue

        mode = tv_spec.get("mode", "directory")
        expected_digest = tv_spec["expectedDigest"]

        # Run sba_digest.py
        cmd = [sys.executable, str(SCRIPT_DIR / "sba_digest.py"), str(tv_path)]
        if mode == "archive":
            cmd.append("--archive")

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            report.add(
                f"tv:{tv_name}",
                False,
                "Digest computation failed",
                result.stderr.strip(),
            )
            continue

        computed_digest = result.stdout.strip()

        if computed_digest == expected_digest:
            report.add(f"tv:{tv_name}", True, f"Digest matches: {computed_digest[:20]}...")
        else:
            report.add(
                f"tv:{tv_name}",
                False,
                "Digest mismatch",
                f"Expected: {expected_digest}\nComputed: {computed_digest}",
            )


def validate_attestation_roundtrip(report: ValidationReport):
    """Validate attestation generation and verification round-trip."""
    manifest_path = SCRIPT_DIR / MANIFEST_FILE
    if not manifest_path.exists():
        return

    with open(manifest_path) as f:
        manifest = json.load(f)

    for tv_name, tv_spec in manifest.get("testVectors", {}).items():
        tv_path = SCRIPT_DIR / tv_spec["path"]
        if not tv_path.exists():
            continue

        mode = tv_spec.get("mode", "directory")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            tmp_path = pathlib.Path(tmp.name)

        try:
            # Generate attestation
            cmd = [
                sys.executable,
                str(SCRIPT_DIR / "sba_attest.py"),
                "content",
                str(tv_path),
                "--output",
                str(tmp_path),
            ]
            if mode == "archive":
                cmd.append("--archive")

            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                report.add(
                    f"attest:{tv_name}",
                    False,
                    "Attestation generation failed",
                    result.stderr.strip(),
                )
                continue

            # Verify attestation
            cmd = [
                sys.executable,
                str(SCRIPT_DIR / "sba_verify.py"),
                str(tmp_path),
                "--bundle",
                str(tv_path),
                "--json",
            ]
            if mode == "archive":
                cmd.append("--archive")

            result = subprocess.run(cmd, capture_output=True, text=True)

            try:
                verify_result = json.loads(result.stdout)
                if verify_result.get("passed"):
                    report.add(
                        f"roundtrip:{tv_name}",
                        True,
                        "Attestation round-trip verified",
                    )
                else:
                    failures = [
                        r["message"]
                        for r in verify_result.get("results", [])
                        if not r.get("passed") and r.get("severity") == "ERROR"
                    ]
                    report.add(
                        f"roundtrip:{tv_name}",
                        False,
                        "Verification failed",
                        "\n".join(failures),
                    )
            except json.JSONDecodeError:
                report.add(
                    f"roundtrip:{tv_name}",
                    False,
                    "Verifier output invalid",
                    result.stdout[:500],
                )

        finally:
            tmp_path.unlink(missing_ok=True)


def validate_exclusion_consistency(report: ValidationReport):
    """Validate exclusion patterns are consistent across all tools and schema."""
    # Extract from schema
    schema_path = SCRIPT_DIR / "sba-content-v1.schema.json"
    with open(schema_path) as f:
        schema = json.load(f)
    schema_excludes = set(
        schema["properties"]["bundle"]["properties"]["excludePatterns"]["default"]
    )

    # Extract from sba_digest.py (parse the file)
    digest_path = SCRIPT_DIR / "sba_digest.py"
    digest_content = digest_path.read_text()

    # Simple extraction - look for DEFAULT_EXCLUDES set
    import re

    match = re.search(
        r"DEFAULT_EXCLUDES[^{]*\{([^}]+)\}",
        digest_content,
        re.DOTALL,
    )
    if match:
        excludes_str = match.group(1)
        digest_excludes = set(re.findall(r'"([^"]+)"', excludes_str))
    else:
        report.add(
            "consistency:excludes",
            False,
            "Could not parse DEFAULT_EXCLUDES from sba_digest.py",
        )
        return

    # Extract ATTESTATION_PREFIXES
    match = re.search(
        r"ATTESTATION_PREFIXES[^{(]*[{(]([^})]+)[})]",
        digest_content,
        re.DOTALL,
    )
    if match:
        prefixes_str = match.group(1)
        digest_prefixes = set(re.findall(r'"([^"]+)"', prefixes_str))
        digest_excludes |= digest_prefixes

    # Compare
    missing_from_digest = schema_excludes - digest_excludes
    extra_in_digest = digest_excludes - schema_excludes

    if missing_from_digest or extra_in_digest:
        details = []
        if missing_from_digest:
            details.append(f"Missing from digest tool: {missing_from_digest}")
        if extra_in_digest:
            details.append(f"Extra in digest tool: {extra_in_digest}")
        report.add(
            "consistency:excludes",
            False,
            "Exclusion pattern mismatch",
            "\n".join(details),
        )
    else:
        report.add(
            "consistency:excludes",
            True,
            f"Exclusion patterns consistent ({len(schema_excludes)} patterns)",
        )


# =============================================================================
# Main
# =============================================================================


def main() -> int:
    parser = argparse.ArgumentParser(description="SBA CI validation")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--schema-only", action="store_true", help="Only validate schemas")
    args = parser.parse_args()

    report = ValidationReport()

    print("Running SBA CI validations...")

    # Always validate compilation and schemas
    validate_python_compilation(report)
    validate_schemas(report)

    if not args.schema_only:
        validate_exclusion_consistency(report)
        validate_test_vectors(report, verbose=args.verbose)
        validate_attestation_roundtrip(report)

    report.print_report(verbose=args.verbose)

    return 0 if report.passed() else 1


if __name__ == "__main__":
    sys.exit(main())
