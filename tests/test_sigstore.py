from __future__ import annotations

import json
from pathlib import Path

import sba_attest
import sba_verify


def test_sigstore_bundle_failure_marks_error(repo_root: Path, tmp_path: Path) -> None:
    statement = sba_attest.create_content_statement(
        repo_root / "test-vectors" / "tv-1-minimal",
        is_archive=False,
    )
    att_path = tmp_path / "attestation.json"
    att_path.write_text(json.dumps(statement), encoding="utf-8")

    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text("{}", encoding="utf-8")

    report = sba_verify.verify_attestation(
        att_path,
        bundle_path=repo_root / "test-vectors" / "tv-1-minimal",
        sigstore_bundle=bundle_path,
        sigstore_offline=True,
    )
    assert not report.passed
    assert any(r.rule_id.startswith("SIGSTORE") for r in report.results)
