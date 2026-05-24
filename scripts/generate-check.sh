#!/usr/bin/env bash
set -euo pipefail
make generate
if ! git diff --exit-code -- . ':(exclude)go.sum' >/tmp/tallow-generate.diff; then
  cat >&2 <<'MSG'
Generated contract drift detected.
Run `make generate` locally, commit regenerated sqlc/schema-derived files, and add/update golden fixtures for any public contract change.
MSG
  cat /tmp/tallow-generate.diff >&2
  exit 1
fi
