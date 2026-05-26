#!/usr/bin/env bash
set -euo pipefail
exec python3 scripts/validate_schemas.py "$@"
