from __future__ import annotations

import json
import tarfile
from pathlib import Path

import sba_attest
import sba_verify


def _write_skill_bundle(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    skill_md = root / "SKILL.md"
    skill_md.write_text(
        "---\nname: tar-skill\ndescription: Tar archive test\nversion: 0.1.0\n---\n",
        encoding="utf-8",
    )


def test_tar_archive_roundtrip(tmp_path: Path) -> None:
    bundle_root = tmp_path / "bundle"
    _write_skill_bundle(bundle_root)

    archive_path = tmp_path / "bundle.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tf:
        tf.add(bundle_root, arcname="bundle")

    statement = sba_attest.create_content_statement(
        archive_path,
        is_archive=True,
    )

    assert statement["predicate"]["bundle"]["bundleType"] == "archive"
    assert statement["predicate"]["metadata"]["archiveRoot"] == "bundle"

    att_path = tmp_path / "attestation.json"
    att_path.write_text(json.dumps(statement), encoding="utf-8")

    report = sba_verify.verify_attestation(
        att_path,
        bundle_path=archive_path,
        is_archive=True,
    )
    assert report.passed
