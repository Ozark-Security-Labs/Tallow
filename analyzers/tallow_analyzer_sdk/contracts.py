"""JSON Schema contract validation helpers."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ValidationError = JsonSchemaValidationError

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS_DIR = REPO_ROOT / "schemas"
SCHEMA_BASE = "https://tallow.osl.dev/schemas/"


def _load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _schema_path_for_uri(uri: str) -> Path:
    if uri.startswith(SCHEMA_BASE):
        return SCHEMAS_DIR / uri.removeprefix(SCHEMA_BASE)
    return SCHEMAS_DIR / Path(uri).name


def _retrieve(uri: str) -> Resource:
    path = _schema_path_for_uri(uri)
    contents = _load_json(path)
    return Resource.from_contents(contents, default_specification=DRAFT202012)


@lru_cache(maxsize=1)
def _registry() -> Registry:
    resources: list[tuple[str, Resource]] = []
    for path in sorted(SCHEMAS_DIR.glob("**/*.schema.json")):
        contents = _load_json(path)
        schema_id = contents.get("$id")
        resource = Resource.from_contents(contents, default_specification=DRAFT202012)
        relative = str(path.relative_to(REPO_ROOT))
        resources.append((relative, resource))
        if isinstance(schema_id, str) and schema_id:
            resources.append((schema_id, resource))
    return Registry(retrieve=_retrieve).with_resources(resources)


@lru_cache(maxsize=8)
def load_schema(name: str) -> dict:
    path = SCHEMAS_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"schema not found: {name}")
    return _load_json(path)


def _validator(schema_name: str) -> Draft202012Validator:
    schema = load_schema(schema_name)
    return Draft202012Validator(schema, registry=_registry())


def validate_analyzer_input(payload: dict) -> None:
    _validator("analyzer-input.schema.json").validate(payload)


def validate_analyzer_output(payload: dict) -> None:
    _validator("analyzer-output.schema.json").validate(payload)


def validate_finding(payload: dict) -> None:
    _validator("finding.schema.json").validate(payload)
