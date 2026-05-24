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
def fail(p,msg): errors.append(f'{p}: {msg}')
for p in root.glob('testdata/**/*.json'):
    data=json.load(open(p)); name=p.name; invalid='.invalid.' in name or name.endswith('.invalid.json'); failed=False
    if name.startswith('envelope'):
        req=['id','type','version','occurred_at','producer','trace','data']
        failed = any(k not in data for k in req) or not str(data.get('version','')).startswith('1.')
    elif name.startswith('artifact-observed'):
        req=['package','version','artifact','registry_hashes','source','observed_at']
        failed = any(k not in data for k in req) or not data.get('registry_hashes')
    elif name.startswith('evidence-ref'):
        path=str(data.get('path',''))
        failed = ('kind' not in data or 'artifact_id' not in data or path.startswith('/') or '\\' in path or '..' in path)
    else:
        failed=False
    if invalid and not failed: fail(p,'invalid fixture unexpectedly passed schema policy')
    if not invalid and failed: fail(p,'valid fixture failed schema policy')
if errors:
    print('\n'.join(errors), file=sys.stderr); sys.exit(1)
print('Validated Foundation schemas and valid/invalid fixtures.')
PY
