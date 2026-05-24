# Dependency Graph and Impact Propagation

Tallow models dependency inventory as a graph rather than a flat package list.

## Confidence order

1. Lockfile or resolved dependency graph.
2. Package manager native graph command in controlled mode.
3. Registry metadata dependency declarations.
4. Manifest constraints only.

Each edge should carry a confidence value such as `resolved-lockfile`, `declared-metadata`, or `inferred`.

## Status language

- `clean`: no known relevant finding.
- `suspicious`: deterministic evidence exists but compromise is not confirmed.
- `compromised_intrinsic`: the package artifact itself contains high-confidence malicious or dangerous evidence.
- `affected_by_transitive`: a resolved dependency path includes a suspicious/compromised package.
- `unknown`: insufficient evidence.
- `suppressed`: operator-reviewed suppression.

Direct dependencies that resolve to compromised transitives are marked **affected by transitive compromise**, not intrinsically malicious unless their own artifact has evidence.

## Impact paths

Impact records must preserve paths:

```text
repo -> manifest -> direct-package@version -> ... -> compromised-package@version
```

This lets operators see exactly why a repo or package version is affected.
