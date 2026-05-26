#!/usr/bin/env python3
"""Validate JSON Schemas and contract examples/fixtures."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urljoin

try:
    import jsonschema
    from jsonschema import Draft202012Validator
    from jsonschema.exceptions import SchemaError
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012
except ImportError:
    print(
        "jsonschema is required; install with `python -m pip install jsonschema`.",
        file=sys.stderr,
    )
    raise SystemExit(1) from None

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"
SCHEMA_BASE = "https://tallow.osl.dev/schemas/"


def load_json(path: Path) -> object:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def schema_uri(path: Path) -> str:
    schema = load_json(path)
    schema_id = schema.get("$id")
    if isinstance(schema_id, str) and schema_id:
        return schema_id
    return (ROOT / path).as_uri()


def schema_path_for_uri(uri: str) -> Path:
    if uri.startswith(SCHEMA_BASE):
        return ROOT / "schemas" / uri.removeprefix(SCHEMA_BASE)
    if uri.startswith("file:"):
        return Path(uri.removeprefix("file://"))
    return ROOT / uri


def check_schemas() -> list[str]:
    errors: list[str] = []
    for path in sorted(SCHEMAS.glob("**/*.schema.json")):
        try:
            schema = load_json(path)
            Draft202012Validator.check_schema(schema)
        except (SchemaError, json.JSONDecodeError) as exc:
            errors.append(f"{path}: invalid schema: {exc}")
    return errors


def retrieve(uri: str) -> Resource:
    path = schema_path_for_uri(uri)
    if not path.exists() and not uri.startswith("file:"):
        path = ROOT / "schemas" / Path(uri).name
    contents = load_json(path)
    return Resource.from_contents(contents, default_specification=DRAFT202012)


def build_registry() -> Registry:
    resources: list[tuple[str, Resource]] = []
    for path in sorted(SCHEMAS.glob("**/*.schema.json")):
        contents = load_json(path)
        uri = schema_uri(path)
        resource = Resource.from_contents(contents, default_specification=DRAFT202012)
        resources.append((uri, resource))
        resources.append((str(path.relative_to(ROOT)), resource))
    return Registry(retrieve=retrieve).with_resources(resources)


def validator_for(relative_schema_path: str, registry: Registry) -> Draft202012Validator:
    path = ROOT / relative_schema_path
    schema = load_json(path)
    return Draft202012Validator(schema, registry=registry)


def validate_examples(registry: Registry) -> list[str]:
    errors: list[str] = []
    example_map = {
        "analyzer-input": "schemas/analyzer-input.schema.json",
        "analyzer-output": "schemas/analyzer-output.schema.json",
    }
    examples_dir = SCHEMAS / "examples"
    if not examples_dir.exists():
        return errors
    for path in sorted(examples_dir.glob("*.json")):
        matched = False
        for prefix, schema_key in example_map.items():
            if path.name.startswith(prefix):
                matched = True
                validator = validator_for(schema_key, registry)
                payload = load_json(path)
                failures = sorted(validator.iter_errors(payload), key=lambda err: list(err.path))
                if failures:
                    errors.append(f"{path}: example failed validation: {failures[0].message}")
                break
        if not matched:
            errors.append(f"{path}: no schema mapping for example")
    return errors


def fixture_kind(path: Path) -> str | None:
    name = path.name
    if name == "unpack-manifest.golden.json":
        return "unpack-manifest"
    prefixes = sorted(
        ["artifact-observed", "envelope", "evidence-ref"],
        key=len,
        reverse=True,
    )
    for prefix in prefixes:
        if name.startswith(prefix):
            return prefix
    return None


def validate_fixtures(registry: Registry) -> list[str]:
    errors: list[str] = []
    schema_map = {
        "envelope": "schemas/events/envelope.v1.schema.json",
        "artifact-observed": "schemas/events/artifact-observed.v1.schema.json",
        "evidence-ref": "schemas/evidence/evidence-ref.v1.schema.json",
        "unpack-manifest": "schemas/unpack-manifest.schema.json",
    }
    extra_fixtures = [ROOT / "testdata/snapshots/unpack-manifest.golden.json"]
    fixture_paths = sorted(SCHEMAS.glob("testdata/**/*.json"))
    fixture_paths.extend(path for path in extra_fixtures if path.exists())
    for path in fixture_paths:
        kind = fixture_kind(path)
        if kind is None:
            errors.append(f"{path}: no schema mapping for fixture")
            continue
        validator = validator_for(schema_map[kind], registry)
        payload = load_json(path)
        invalid = ".invalid." in path.name or path.name.endswith(".invalid.json")
        failures = sorted(validator.iter_errors(payload), key=lambda err: list(err.path))
        if invalid and not failures:
            errors.append(f"{path}: invalid fixture unexpectedly passed JSON Schema")
        if not invalid and failures:
            errors.append(f"{path}: valid fixture failed JSON Schema: {failures[0].message}")
    return errors


def main() -> int:
    errors = check_schemas()
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    registry = build_registry()
    errors.extend(validate_examples(registry))
    errors.extend(validate_fixtures(registry))
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    print("Validated schemas, examples, and fixtures.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
