#!/usr/bin/env bash
set -euo pipefail
for f in docs/security/threat-model.md docs/security/safe-unpack.md docs/security/auth.md docs/security/llm-usage.md docs/security/release-self-protection.md docs/security/no-execution-policy.md docs/security/prompt-injection.md; do
  test -f "$f" || { echo "missing $f" >&2; exit 1; }
done
if grep -Riq 'privileged:[[:space:]]*true\|/var/run/docker.sock\|network_mode:[[:space:]]*host' docker-compose.yml; then
  echo "default Compose must not run privileged, use host networking, or mount Docker socket" >&2
  exit 1
fi
