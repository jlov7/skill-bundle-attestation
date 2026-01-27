from __future__ import annotations

import json
from pathlib import Path

import pytest


def _load_schema(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_examples_conform_to_schemas(repo_root: Path) -> None:
    pytest.importorskip("jsonschema")
    from jsonschema import Draft202012Validator

    schema_dir = repo_root
    statement_schema = _load_schema(schema_dir / "sba-statement-v1.schema.json")
    content_schema = _load_schema(schema_dir / "sba-content-v1.schema.json")

    statement_validator = Draft202012Validator(statement_schema)
    content_validator = Draft202012Validator(content_schema)

    for example_path in (repo_root / "examples").glob("*.json"):
        data = json.loads(example_path.read_text(encoding="utf-8"))
        statement_errors = list(statement_validator.iter_errors(data))
        assert not statement_errors, f"{example_path.name}: {statement_errors[0].message}"

        if data.get("predicateType") == "https://jlov7.github.io/sba/predicates/sba-content-v1":
            predicate_errors = list(content_validator.iter_errors(data.get("predicate", {})))
            assert not predicate_errors, f"{example_path.name}: {predicate_errors[0].message}"
