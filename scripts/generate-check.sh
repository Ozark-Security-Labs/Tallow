#!/usr/bin/env bash
set -euo pipefail
make generate
diff_file="$(mktemp)"
status_file="$(mktemp)"
trap 'rm -f "$diff_file" "$status_file"' EXIT
git diff --exit-code -- . >"$diff_file" || true
git status --porcelain --untracked-files=all -- . >"$status_file"
if [[ -s "$diff_file" || -s "$status_file" ]]; then
  cat >&2 <<'MSG'
Generated contract drift detected.
Run `make generate` locally, commit regenerated sqlc/schema-derived files, and add/update golden fixtures for any public contract change.
MSG
  cat "$diff_file" >&2
  cat "$status_file" >&2
  exit 1
fi
