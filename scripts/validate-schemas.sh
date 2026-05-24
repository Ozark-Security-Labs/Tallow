#!/usr/bin/env bash
set -euo pipefail
shopt -s globstar nullglob
schemas=(schemas/**/*.schema.json)
if [ ${#schemas[@]} -eq 0 ]; then
  echo "No JSON schemas found; schema validation skipped explicitly."
  exit 0
fi
python3 - <<'PY'
import json
import pathlib
import sys

try:
    import jsonschema
except ImportError:
    print('jsonschema is required; install with `python -m pip install jsonschema`.', file=sys.stderr)
    sys.exit(1)

root = pathlib.Path('schemas')
for p in root.glob('**/*.schema.json'):
    with p.open() as f:
        schema = json.load(f)
    jsonschema.Draft202012Validator.check_schema(schema)

schema_map = {
    'envelope': root / 'events' / 'envelope.v1.schema.json',
    'artifact-observed': root / 'events' / 'artifact-observed.v1.schema.json',
    'evidence-ref': root / 'evidence' / 'evidence-ref.v1.schema.json',
}
validators = {}
for name, path in schema_map.items():
    with path.open() as f:
        validators[name] = jsonschema.Draft202012Validator(json.load(f), format_checker=jsonschema.FormatChecker())

errors = []
def fixture_kind(path: pathlib.Path):
    name = path.name
    for prefix in sorted(schema_map, key=len, reverse=True):
        if name.startswith(prefix):
            return prefix
    return None

for p in sorted(root.glob('testdata/**/*.json')):
    kind = fixture_kind(p)
    if kind is None:
        errors.append(f'{p}: no schema mapping for fixture')
        continue
    with p.open() as f:
        data = json.load(f)
    invalid = '.invalid.' in p.name or p.name.endswith('.invalid.json')
    failures = sorted(validators[kind].iter_errors(data), key=lambda e: list(e.path))
    if invalid and not failures:
        errors.append(f'{p}: invalid fixture unexpectedly passed JSON Schema')
    if not invalid and failures:
        errors.append(f'{p}: valid fixture failed JSON Schema: {failures[0].message}')

if errors:
    print('\n'.join(errors), file=sys.stderr)
    sys.exit(1)
print('Validated Foundation schemas and valid/invalid fixtures.')
PY
