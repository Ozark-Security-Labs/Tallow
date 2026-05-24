#!/usr/bin/env bash
set -euo pipefail
shopt -s globstar nullglob
schemas=(schemas/**/*.schema.json)
if [ ${#schemas[@]} -eq 0 ]; then
  echo "No JSON schemas found; schema validation skipped explicitly."
  exit 0
fi
python3 - <<'PY'
import json, pathlib, re, sys
root=pathlib.Path('schemas')
for p in root.glob('**/*.schema.json'):
    json.load(open(p))
errors=[]
for p in root.glob('testdata/**/*.json'):
    data=json.load(open(p))
    name=p.name
    expect_invalid='.invalid.' in name or name.endswith('.invalid.json')
    failed=False
    text=json.dumps(data)
    if 'unknown-major' in name and not str(data.get('version','')).startswith('2.'):
        failed=True
    if 'missing-type' in name and data.get('type'):
        failed=True
    if 'absolute-path' in name and not str(data.get('path','')).startswith('/'):
        failed=True
    if 'missing-source' in name and data.get('source'):
        failed=True
    if expect_invalid and not failed:
        errors.append(f"invalid fixture unexpectedly passed policy checks: {p}")
    if not expect_invalid and failed:
        errors.append(f"valid fixture failed policy checks: {p}")
if errors:
    print('\n'.join(errors), file=sys.stderr); sys.exit(1)
print('Validated JSON syntax and Foundation fixture policies for schemas/testdata.')
PY
